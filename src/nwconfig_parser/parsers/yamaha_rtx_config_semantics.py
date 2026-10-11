"""Semantic interpretation of vendor configuration into common models.

Only statements whose syntax is documented in the Yamaha RT command reference
are interpreted. ``pp select``/``tunnel select`` set a statement-order context
(never inferred from indentation) used by ``description pp|tunnel`` and
``ip pp address``; other lines in those sections are reported as unsupported.
"""

from __future__ import annotations

import re
from ipaddress import IPv4Address, IPv4Network
from typing import Any

from nwconfig_parser.models import (
    ACL,
    ACLAddressCondition,
    ACLBinding,
    ACLPortCondition,
    ACLRule,
    ConfigDocument,
    ConfigNode,
    ConfigReference,
    IssueSeverity,
    ParseIssue,
    Route,
)
from nwconfig_parser.parsers.vendor_config_base import (
    ConfigInterpreter,
    Reject,
    make_interface,
    make_network,
    mask_to_prefix,
    parse_ipv4,
)

_INTERFACE = re.compile(r"^(?:lan|wan|bridge|loopback)\d+$", re.IGNORECASE)
_DESCRIPTION = re.compile(r"^description\s+(?P<target>\S+)\s+(?P<text>\S.*)$")
_CONTEXT_TARGETS = {"pp", "tunnel"}
_NUMBER = re.compile(r"^\d+$")


class YamahaRtxConfigInterpreter(ConfigInterpreter):
    # (kind, number) chosen by the latest `pp select` / `tunnel select`.
    _context: tuple[str, str] | None = None

    def __init__(
        self, document: ConfigDocument, filename: str | None, command: str
    ) -> None:
        super().__init__(document, filename, command)
        self._acls: dict[str, ACL] = {}
        self._bindings: list[ACLBinding] = []

    def handle_root(self, node: ConfigNode) -> None:
        tokens = node.command.split()
        negated = node.negated
        if negated:
            tokens = tokens[1:]
        keyword = tokens[0].casefold() if tokens else ""
        if keyword in _CONTEXT_TARGETS and len(tokens) >= 2 and tokens[1] == "select":
            self._select(node, keyword, tokens[2:], negated)
        elif keyword == "description" and not negated:
            self._description(node)
        elif keyword == "ip" and len(tokens) >= 2 and tokens[1].casefold() == "route":
            self._route(node, tokens[2:], negated)
        elif keyword == "ip" and len(tokens) >= 2 and tokens[1].casefold() == "filter":
            self._ip_filter(node, tokens[2:], negated)
        elif (
            keyword == "ip"
            and len(tokens) >= 4
            and tokens[2].casefold() == "secure"
            and tokens[3].casefold() == "filter"
        ):
            self._secure_filter(node, tokens[1], tokens[4:], negated)
        elif keyword == "ip" and len(tokens) >= 3 and tokens[2].casefold() == "address":
            self._address(node, tokens[1], tokens[3:], negated)
        elif keyword == "lan" and len(tokens) >= 3 and tokens[1] == "shutdown":
            self._shutdown(node, tokens[2:], negated)
        elif keyword == "snmp" and len(tokens) >= 2 and tokens[1] == "sysname":
            raise Reject("snmp sysname is not a hostname command; not mapped.")
        else:
            raise Reject("Statement is not supported by this parser.")

    def finalize(self) -> None:
        super().finalize()
        self.document.acls = list(self._acls.values())
        self.document.acl_bindings = self._bindings
        defined = {name.casefold() for name in self._acls}
        references: list[ConfigReference] = []
        for binding in self._bindings:
            source = binding.source_reference
            resolved = binding.acl_name.casefold() in defined
            references.append(
                ConfigReference(
                    source_type=binding.target_type,
                    source_name=binding.target_name,
                    relation=f"secure-filter-{binding.direction}",
                    target_type="acl",
                    target_name=binding.acl_name,
                    line_number=source.start_line if source else None,
                    resolved=resolved,
                )
            )
            if not resolved:
                self.issues.append(
                    ParseIssue(
                        severity=IssueSeverity.INFO,
                        code="DANGLING_REFERENCE",
                        message="Filter reference is not defined in the parsed input.",
                        line_number=source.start_line if source else None,
                        source_reference=source,
                    )
                )
        self.document.references = references

    def _ip_filter(
        self, node: ConfigNode, tokens: list[str], negated: bool
    ) -> None:
        if not tokens or not tokens[0].isdigit():
            raise Reject("Static filter number is missing or invalid.", invalid=True)
        filter_id = int(tokens[0])
        if not 1 <= filter_id <= 21474836:
            raise Reject(
                "Static filter number is outside the documented range.", invalid=True
            )
        name = str(filter_id)
        if negated:
            if len(tokens) > 2 or (
                len(tokens) == 2 and tokens[1].casefold() not in {"pass", "reject"}
            ):
                acl = self._acls.get(name)
                if acl is not None:
                    self._taint_acl(acl, node, "unsupported removal form")
                raise Reject("Static-filter removal form is not supported.")
            acl = self._acls.get(name)
            action_matches = (
                len(tokens) == 1
                or (
                    acl is not None
                    and str(acl.rules[0].attributes.get("vendor_action", "")).startswith(
                        tokens[1].casefold()
                    )
                )
            )
            if acl is not None and action_matches:
                self._acls.pop(name)
            elif acl is not None:
                self.info(
                    node,
                    "FILTER_ACTION_MISMATCH",
                    "The filter action does not match the parsed definition.",
                )
            else:
                self._missing(node)
            self.parsed(node)
            return
        if len(tokens) < 3:
            acl = self._acls.get(name)
            if acl is not None:
                self._taint_acl(acl, node, "invalid redefinition")
            raise Reject("Static filter requires an action and source.", invalid=True)
        if name in self._acls:
            self._taint_acl(self._acls[name], node, "duplicate filter identifier")
            raise Reject("Duplicate static-filter identifier; no overwrite is assumed.")
        action_token = tokens[1].casefold()
        actions = {
            "pass": ("permit", None),
            "pass-log": ("permit", True),
            "pass-nolog": ("permit", False),
            "reject": ("deny", None),
            "reject-log": ("deny", True),
            "reject-nolog": ("deny", False),
        }
        action = actions.get(action_token)
        if action is None:
            raise Reject("Conditional or unsupported filter action.")

        values = tokens[2:]
        source, index = self._filter_address(values, 0)
        destination = ACLAddressCondition(kind="any")
        if index < len(values):
            destination, index = self._filter_address(values, index)
        protocol = "ip"
        if index < len(values):
            protocol = values[index].casefold()
            index += 1
            if protocol == "*":
                protocol = "ip"
            elif protocol not in {"tcp", "udp", "icmp", "gre", "esp", "ah"}:
                raise Reject("Filter protocol is not supported by this IPv4 parser.")
        source_port: ACLPortCondition | None = None
        destination_port: ACLPortCondition | None = None
        if index < len(values):
            if protocol not in {"tcp", "udp"}:
                raise Reject("Only TCP/UDP numeric ports are modelled.")
            source_port, index = self._filter_port(values, index)
        if index < len(values):
            if protocol not in {"tcp", "udp"}:
                raise Reject("Only TCP/UDP numeric ports are modelled.")
            destination_port, index = self._filter_port(values, index)
        if index != len(values):
            raise Reject("Filter options are not supported.")

        reference = self.reference(node.line_number)
        rule = ACLRule(
            input_order=0,
            sequence=filter_id,
            action=action[0],
            protocol=protocol,
            source=source,
            destination=destination,
            source_port=source_port,
            destination_port=destination_port,
            log=action[1],
            source_reference=reference,
            attributes={"vendor_action": action_token},
        )
        self._acls[name] = ACL(
            name=name,
            type="ip-filter",
            entries=[node.command],
            attributes={
                "vendor": "Yamaha",
                "os_family": "RTX",
                "acl_scope": "global",
            },
            rules=[rule],
            source_reference=reference,
        )
        self.parsed(node)

    @staticmethod
    def _filter_address(
        tokens: list[str], index: int
    ) -> tuple[ACLAddressCondition, int]:
        if index >= len(tokens):
            raise Reject("Filter address condition is missing.", invalid=True)
        value = tokens[index]
        if value == "*":
            return ACLAddressCondition(kind="any"), index + 1
        if "," in value or "*" in value or "-" in value or "@" in value:
            raise Reject("Address lists and non-literal addresses are not modelled.")
        address_text, separator, mask_text = value.partition("/")
        try:
            address = IPv4Address(address_text)
        except ValueError as exc:
            raise Reject("Filter IPv4 address is invalid.", invalid=True) from exc
        if not separator:
            return ACLAddressCondition(kind="host", address=address), index + 1
        prefix = mask_to_prefix(mask_text, allow_hex=True)
        network = make_network(str(address), prefix)
        return ACLAddressCondition(kind="prefix", address=network), index + 1

    @staticmethod
    def _filter_port(
        tokens: list[str], index: int
    ) -> tuple[ACLPortCondition | None, int]:
        value = tokens[index]
        if value == "*":
            return None, index + 1
        if not value.isdigit():
            raise Reject("Only a single numeric port is supported.")
        port = int(value)
        if not 0 <= port <= 65535:
            raise Reject("Filter port is outside the numeric range.", invalid=True)
        return ACLPortCondition(operator="eq", first_port=port), index + 1

    def _secure_filter(
        self,
        node: ConfigNode,
        target_token: str,
        tokens: list[str],
        negated: bool,
    ) -> None:
        if not tokens or tokens[0].casefold() not in {"in", "out"}:
            raise Reject("Secure-filter direction must be in or out.", invalid=True)
        direction = tokens[0].casefold()
        if target_token.casefold() == "null":
            if direction == "in":
                raise Reject("The documented NULL interface has no inbound filter.")
            name = "null"
            target_type = "interface"
        else:
            name = self._name(target_token)
            target_type = (
                "interface"
                if _INTERFACE.fullmatch(target_token) is not None
                else target_token.casefold()
            )
        if target_type == "interface":
            self.interface(name)
        filter_ids = tokens[1:]
        if any(not token.isdigit() for token in filter_ids):
            raise Reject("Only ordered static filter numbers are supported.")
        if not filter_ids and not negated:
            raise Reject(
                "Secure filter requires at least one filter number.", invalid=True
            )
        if any(not 1 <= int(value) <= 21474836 for value in filter_ids):
            raise Reject(
                "Static filter number is outside the documented range.", invalid=True
            )
        selected = {str(int(value)) for value in filter_ids}
        matches = [
            binding
            for binding in self._bindings
            if binding.target_name.casefold() == name.casefold()
            and binding.direction == direction
            and (not selected or binding.acl_name in selected)
        ]
        if negated:
            if matches:
                for binding in matches:
                    self._bindings.remove(binding)
            else:
                self._missing(node)
            self.parsed(node)
            return
        for position, filter_id in enumerate(filter_ids):
            self._bindings.append(
                ACLBinding(
                    acl_name=str(int(filter_id)),
                    target_type=target_type,
                    target_name=name,
                    direction=direction,
                    source_reference=self.reference(node.line_number),
                    attributes={
                        "vendor": "Yamaha",
                        "os_family": "RTX",
                        "filter_order": position,
                    },
                )
            )
        self.parsed(node)

    def _taint_acl(self, acl: ACL, node: ConfigNode, reason: str) -> None:
        acl.complete = False
        acl.incomplete_reasons.append(f"line {node.line_number}: {reason}")
        acl.incomplete_source_references.append(self.reference(node.line_number))

    def _select(
        self, node: ConfigNode, kind: str, rest: list[str], negated: bool
    ) -> None:
        if negated:
            if rest:
                raise Reject("Statement is not supported by this parser.")
            self._context = None
        elif len(rest) != 1:
            raise Reject("Statement is not supported by this parser.", invalid=True)
        elif rest[0] == "none":
            self._context = None
        elif _NUMBER.fullmatch(rest[0]) is not None:
            self._context = (kind, rest[0])
        elif kind == "pp" and rest[0] == "anonymous":
            self._context = (kind, rest[0])
        else:
            raise Reject("Select value is not valid.", invalid=True)
        self.parsed(node, count=False)

    def _name(self, token: str) -> str:
        kind = token.casefold()
        if kind in _CONTEXT_TARGETS:
            if self._context is None or self._context[0] != kind:
                raise Reject("No matching pp/tunnel select context is active.")
            if self._context[1] == "anonymous":
                raise Reject("The anonymous pp context is not modelled.")
            return f"{kind} {self._context[1]}"
        if _INTERFACE.fullmatch(token) is None:
            raise Reject("Interface name form is not supported.")
        return token.casefold()

    def _description(self, node: ConfigNode) -> None:
        match = _DESCRIPTION.match(node.command)
        if match is None:
            raise Reject("Statement is not supported by this parser.")
        name = self._name(match.group("target"))
        self.interface(name).description = match.group("text")
        self.parsed(node)

    def _address(
        self, node: ConfigNode, target: str, rest: list[str], negated: bool
    ) -> None:
        name = self._name(target)
        if target.casefold() == "tunnel":
            raise Reject("ip tunnel address is not documented; not supported.")
        if negated:
            if len(rest) > 1:
                raise Reject("Statement is not supported by this parser.")
            if not rest:
                if name in self.interfaces:
                    self.interfaces[name].ipv4_addresses.clear()
                else:
                    self._missing(node)
            else:
                self._remove_address(node, name, rest[0])
            self.parsed(node)
            return
        if len(rest) != 1:
            raise Reject("Address options are not supported.")
        if rest[0].casefold() == "dhcp":
            raise Reject("DHCP address assignment is not modelled.")
        address, _, mask = rest[0].partition("/")
        if not mask:
            if target.casefold() == "pp":
                raise Reject("pp address without a mask is not supported.")
            raise Reject("Address without mask is not supported.", invalid=True)
        interface = make_interface(address, mask_to_prefix(mask, allow_hex=True))
        entry = self.interface(name)
        entry.ipv4_addresses = [interface]
        self.parsed(node)

    def _remove_address(self, node: ConfigNode, name: str, value: str) -> None:
        address, _, mask = value.partition("/")
        wanted = make_interface(address, mask_to_prefix(mask, allow_hex=True))
        entry = self.interfaces.get(name)
        if entry is None or wanted not in entry.ipv4_addresses:
            self._missing(node)
        else:
            entry.ipv4_addresses.remove(wanted)

    def _missing(self, node: ConfigNode) -> None:
        self.info(
            node,
            "NEGATION_TARGET_NOT_IN_INPUT",
            "The configuration removed by this statement is not in the input.",
        )

    def _shutdown(self, node: ConfigNode, rest: list[str], negated: bool) -> None:
        if len(rest) != 1:
            raise Reject("Port-level shutdown is not an interface state.")
        name = self._name(rest[0])
        self.interface(name).admin_status = "up" if negated else "down"
        self.parsed(node)

    def _route(self, node: ConfigNode, tokens: list[str], negated: bool) -> None:
        if not tokens:
            raise Reject("Statement is not supported by this parser.")
        network = self._network(tokens[0])
        gateways = self._gateways(tokens[1:], allow_empty=negated)
        targets = [item["target"] for item in gateways]
        if negated:
            before = len(self.document.static_routes)
            self.document.static_routes = [
                route
                for route in self.document.static_routes
                if not (
                    route.network == network
                    and (
                        not targets
                        or targets == route.attributes.get("gateway_targets")
                    )
                )
            ]
            if len(self.document.static_routes) == before:
                self._missing(node)
            self.parsed(node)
            return
        next_hops = [
            parse_ipv4(item["target"]) for item in gateways if "." in item["target"]
        ]
        interfaces = [item["target"] for item in gateways if "." not in item["target"]]
        metric = gateways[0].get("metric") if len(gateways) == 1 else None
        route = Route(
            network=network,
            protocol="static",
            next_hops=next_hops,
            outgoing_interfaces=interfaces,
            metric=metric,
            attributes={
                "line_number": node.line_number,
                "gateways": gateways,
                "gateway_targets": targets,
            },
        )
        self.document.static_routes = [
            existing
            for existing in self.document.static_routes
            if not (
                existing.network == network
                and existing.attributes.get("gateway_targets") == targets
            )
        ]
        self.document.static_routes.append(route)
        self.parsed(node)

    @staticmethod
    def _network(token: str) -> IPv4Network:
        if token.casefold() == "default":
            return make_network("0.0.0.0", 0)
        address, _, mask = token.partition("/")
        prefix = mask_to_prefix(mask, allow_hex=True) if mask else 32
        return make_network(address, prefix)

    @staticmethod
    def _gateways(tokens: list[str], *, allow_empty: bool) -> list[dict[str, Any]]:
        if not tokens:
            if allow_empty:
                return []
            raise Reject("Route without a gateway is not supported.")
        gateways: list[dict[str, Any]] = []
        index = 0
        while index < len(tokens):
            if tokens[index].casefold() != "gateway" or index + 1 >= len(tokens):
                raise Reject("Route option is not supported.")
            index += 1
            first = tokens[index]
            if "." in first:
                parse_ipv4(first)
                gateway: dict[str, Any] = {"target": first}
                index += 1
            elif (
                first.casefold() in _CONTEXT_TARGETS
                and index + 1 < len(tokens)
                and tokens[index + 1].isdigit()
            ):
                gateway = {"target": f"{first.casefold()} {tokens[index + 1]}"}
                index += 2
            else:
                raise Reject("Gateway form is not supported.")
            while index < len(tokens) and tokens[index].casefold() != "gateway":
                index = _gateway_parameter(gateway, tokens, index)
            gateways.append(gateway)
        return gateways


def _gateway_parameter(gateway: dict[str, Any], tokens: list[str], index: int) -> int:
    key = tokens[index].casefold()
    if key == "hide":
        gateway["hide"] = True
        return index + 1
    if key in {"metric", "weight", "keepalive"} and index + 1 < len(tokens):
        value = tokens[index + 1]
        if not value.isdigit():
            raise Reject("Invalid route parameter value.", invalid=True)
        gateway[key] = int(value)
        return index + 2
    if key == "filter":
        numbers: list[int] = []
        index += 1
        while index < len(tokens) and tokens[index].isdigit():
            numbers.append(int(tokens[index]))
            index += 1
        if not numbers:
            raise Reject("Invalid route parameter value.", invalid=True)
        gateway["filter"] = numbers
        return index
    raise Reject("Route option is not supported.")
