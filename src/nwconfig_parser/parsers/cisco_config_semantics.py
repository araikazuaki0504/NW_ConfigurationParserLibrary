"""Semantic interpretation of a Cisco IOS-family configuration hierarchy.

The hierarchy builder in ``cisco_config`` only stores structure.  This module
converts recognised statements into vendor-neutral models and marks every node
as PARSED, UNSUPPORTED or INVALID so that "stored" never means "understood".
Nothing is guessed: unknown statements are preserved with their line numbers.
"""

from __future__ import annotations

import re
from collections import OrderedDict
from dataclasses import dataclass, field
from ipaddress import AddressValueError, IPv4Address, IPv4Interface, IPv4Network

from nwconfig_parser.models import (
    ACL,
    VLAN,
    VRF,
    ACLAddressCondition,
    ACLBinding,
    ACLPortCondition,
    ACLRule,
    Banner,
    BGPNetwork,
    BGPPeer,
    BGPProcess,
    BGPVrfAddressFamily,
    ConfigDocument,
    ConfigNode,
    ConfigReference,
    Interface,
    IssueSeverity,
    OSPFProcess,
    ParseIssue,
    PrefixList,
    PrefixListEntry,
    Route,
    RouteMap,
    RouteMapEntry,
    SemanticStatus,
    SourceReference,
    UnsupportedConfigLine,
)

_PREFIX_LINE = re.compile(
    r"^ip\s+prefix-list\s+(?P<name>\S+)"
    r"(?:\s+seq\s+(?P<sequence>\d+))?\s+"
    r"(?P<action>permit|deny)\s+(?P<prefix>\S+)"
    r"(?:\s+ge\s+(?P<ge>\d+))?"
    r"(?:\s+le\s+(?P<le>\d+))?$",
    re.IGNORECASE,
)
_PREFIX_NAME = re.compile(r"^ip\s+prefix-list\s+(?P<name>\S+)", re.IGNORECASE)
_NO_PREFIX_ENTRY = re.compile(
    r"^(?:seq\s+(?P<sequence>\d+))?\s*"
    r"(?:(?P<action>permit|deny)\s+(?P<prefix>\S+)"
    r"(?:\s+ge\s+(?P<ge>\d+))?(?:\s+le\s+(?P<le>\d+))?)?$",
    re.IGNORECASE,
)
_PREFIX_DESCRIPTION = re.compile(
    r"^ip\s+prefix-list\s+(?P<name>\S+)\s+description\s+(?P<text>.+)$", re.IGNORECASE
)
_HOSTNAME_LINE = re.compile(r"^hostname\s+(?P<hostname>\S+)\s*$", re.IGNORECASE)
_ROUTE_MAP_HEADER = re.compile(
    r"^route-map\s+(?P<name>\S+)\s+(?P<action>permit|deny)\s+(?P<sequence>\d+)$",
    re.IGNORECASE,
)
_INTERFACE_NAME = re.compile(r"^[A-Za-z][A-Za-z-]*\d[\w/.:-]*$")
_ROUTE_DISTINGUISHER = re.compile(
    r"^(?:\d+|\d+\.\d+|(?:\d{1,3}\.){3}\d{1,3}):\d+$",
)
_VLAN_LIST = re.compile(r"^\d+(-\d+)?(,\d+(-\d+)?)*$")


class _Reject(Exception):
    """A statement is recognised but cannot be represented safely."""

    def __init__(self, reason: str, *, invalid: bool = False) -> None:
        super().__init__(reason)
        self.reason = reason
        self.invalid = invalid


def mask_to_prefix(mask: str, *, wildcard: bool = False) -> int:
    """Convert a contiguous netmask or wildcard to a prefix length."""
    try:
        value = int(IPv4Address(mask))
    except AddressValueError as exc:
        raise _Reject(f"Invalid mask {mask!r}", invalid=True) from exc
    if wildcard:
        value ^= 0xFFFFFFFF
    prefix = bin(value).count("1")
    if value != (((1 << prefix) - 1) << (32 - prefix)) & 0xFFFFFFFF:
        raise _Reject(f"Non-contiguous mask {mask!r}", invalid=True)
    return prefix


def _address(value: str) -> IPv4Address:
    try:
        return IPv4Address(value)
    except AddressValueError as exc:
        raise _Reject(f"Invalid IPv4 address {value!r}", invalid=True) from exc


def _integer(value: str, low: int, high: int, what: str) -> int:
    if not value.isdigit() or not low <= int(value) <= high:
        raise _Reject(f"Invalid {what} {value!r}", invalid=True)
    return int(value)


def _vlan_list(value: str) -> set[int]:
    if _VLAN_LIST.fullmatch(value) is None:
        raise _Reject(f"Unsupported VLAN list {value!r}")
    vlans: set[int] = set()
    for part in value.split(","):
        low_text, _, high_text = part.partition("-")
        low = _integer(low_text, 1, 4094, "VLAN ID")
        high = _integer(high_text, 1, 4094, "VLAN ID") if high_text else low
        if low > high:
            raise _Reject(f"Descending VLAN range {part!r}", invalid=True)
        vlans.update(range(low, high + 1))
    return vlans


def _split(node: ConfigNode) -> tuple[bool, list[str]]:
    tokens = node.command.split()
    if tokens and tokens[0].casefold() == "no":
        return True, tokens[1:]
    return False, tokens


@dataclass(slots=True)
class _TrunkState:
    kind: str = "unspecified"  # unspecified | all | list | all_except
    vlans: set[int] = field(default_factory=set)


@dataclass(slots=True)
class _BgpScope:
    family: str
    vrf: str | None
    target: BGPProcess | BGPVrfAddressFamily


@dataclass(slots=True)
class _EntryBuilder:
    action: str
    reference: SourceReference
    matches: list[str] = field(default_factory=list)
    sets: list[str] = field(default_factory=list)
    prefix_lists: list[str] = field(default_factory=list)
    acls: list[str] = field(default_factory=list)
    acl_reference_sources: list[SourceReference] = field(default_factory=list)


class CiscoConfigInterpreter:
    def __init__(self, document: ConfigDocument, filename: str | None, command: str):
        self.document = document
        self.filename = filename
        self.command = command
        self.issues: list[ParseIssue] = []
        self.unparsed: list[SourceReference] = []
        self._prefix_lists: OrderedDict[str, PrefixList] = OrderedDict()
        self._interfaces: OrderedDict[str, Interface] = OrderedDict()
        self._interface_trunks: dict[str, _TrunkState] = {}
        self._vlans: OrderedDict[int, VLAN] = OrderedDict()
        self._ospf: OrderedDict[tuple[str, str | None], OSPFProcess] = OrderedDict()
        self._bgp: BGPProcess | None = None
        self._banners: list[Banner] = []
        self._vrfs: OrderedDict[str, VRF] = OrderedDict()
        self._route_maps: OrderedDict[str, dict[int, _EntryBuilder]] = OrderedDict()
        self._route_map_state: dict[str, RouteMap] = {}
        self._acls: OrderedDict[tuple[str, str], ACL] = OrderedDict()
        self._acl_order: dict[tuple[str, str], int] = {}
        self._acl_bindings: list[ACLBinding] = []
        self.parsed_count = 0

    # ------------------------------------------------------------------ utils
    def _reference(self, start: int, end: int | None = None) -> SourceReference:
        return SourceReference(
            filename=self.filename,
            command=self.command,
            start_line=start,
            end_line=end if end is not None else start,
        )

    @staticmethod
    def _last_line(node: ConfigNode) -> int:
        return max(
            [node.line_number, node.end_line or 0]
            + [max(c.line_number, c.end_line or 0) for c in _walk(node)]
        )

    def _parsed(self, node: ConfigNode) -> None:
        node.semantic_status = SemanticStatus.PARSED
        self.parsed_count += 1

    def _reject(
        self,
        node: ConfigNode,
        reason: str,
        *,
        invalid: bool = False,
        parent: ConfigNode | None = None,
        code: str | None = None,
        severity: IssueSeverity | None = None,
        record_issue: bool = True,
    ) -> None:
        status = SemanticStatus.INVALID if invalid else SemanticStatus.UNSUPPORTED
        node.semantic_status = status
        parent_text = parent.command if parent is not None else None
        self.document.unsupported_lines.append(
            UnsupportedConfigLine(
                line_number=node.line_number,
                raw_text=node.raw_text,
                reason=reason,
                parent=parent_text,
            )
        )
        for child in node.children:
            self._reject(
                child,
                f"Inside unsupported block: {reason}",
                invalid=invalid,
                parent=node,
                record_issue=False,
            )
        if not record_issue:
            return
        end = self._last_line(node)
        reference = self._reference(node.line_number, end)
        self.unparsed.append(reference)
        self.issues.append(
            ParseIssue(
                severity=severity
                or (IssueSeverity.ERROR if invalid else IssueSeverity.WARNING),
                code=code
                or ("INVALID_CONFIG_STATEMENT" if invalid else "UNSUPPORTED_CONFIG"),
                message=reason,
                line_number=node.line_number,
                source_reference=reference,
            )
        )

    def _info(self, node: ConfigNode, code: str, message: str) -> None:
        self.issues.append(
            ParseIssue(
                severity=IssueSeverity.INFO,
                code=code,
                message=message,
                line_number=node.line_number,
                source_reference=self._reference(node.line_number),
            )
        )

    def _run_child(
        self,
        parent: ConfigNode,
        child: ConfigNode,
        handler: object,
    ) -> None:
        """Run a child handler, converting rejections into preserved lines."""
        assert callable(handler)
        try:
            handler(child)
        except _Reject as rejection:
            self._reject(child, rejection.reason, invalid=rejection.invalid)

    # ------------------------------------------------------------------- main
    def run(self) -> None:
        for node in self.document.roots:
            try:
                self._top_level(node)
            except _Reject as rejection:
                self._reject(node, rejection.reason, invalid=rejection.invalid)
        self.document.prefix_lists = list(self._prefix_lists.values())
        self.document.banners = list(self._banners)
        self.document.vrfs = list(self._vrfs.values())
        self.document.interfaces = list(self._interfaces.values())
        for interface in self.document.interfaces:
            definition = self._vrfs.get(interface.vrf or "")
            if definition is not None:
                definition.interfaces.append(interface.name)
        for name, trunk in self._interface_trunks.items():
            self._finish_trunk(self._interfaces[name], trunk)
        self.document.vlans = sorted(self._vlans.values(), key=lambda v: v.vlan_id)
        self.document.ospf_processes = list(self._ospf.values())
        if self._bgp is not None:
            self.document.bgp_processes = [self._bgp]
        self.document.acls = list(self._acls.values())
        self.document.acl_bindings = self._acl_bindings
        self._finish_acls()
        self._finish_route_maps()
        self._build_references()

    def _top_level(self, node: ConfigNode) -> None:
        negated, tokens = _split(node)
        words = [token.casefold() for token in tokens]
        if not tokens:
            raise _Reject("Empty statement")
        if not negated and words[0] == "hostname":
            self._hostname(node)
        elif not negated and words[0] == "end" and len(words) == 1:
            self._parsed(node)
        elif not negated and words[0] == "interface":
            self._interface(node, tokens)
        elif not negated and words[0] == "vlan":
            self._vlan(node, tokens)
        elif not negated and words[:2] == ["vrf", "definition"]:
            self._vrf_definition(node, tokens, legacy=False)
        elif not negated and words[:2] == ["ip", "vrf"]:
            self._vrf_definition(node, tokens, legacy=True)
        elif negated and words[:2] in (["vrf", "definition"], ["ip", "vrf"]):
            self._no_vrf_definition(node, tokens)
        elif words[:2] == ["ip", "routing"] and len(words) == 2:
            self.document.ip_routing = not negated
            self._parsed(node)
        elif words[:2] == ["ip", "route"]:
            self._static_route(node, negated, tokens[2:])
        elif words[:2] == ["ip", "access-list"]:
            self._access_list(node, negated, tokens)
        elif words[0] == "access-list":
            self._numbered_access_list(node, negated, tokens)
        elif not negated and words[:2] == ["router", "ospf"]:
            self._ospf_block(node, tokens)
        elif not negated and words[:2] == ["router", "bgp"]:
            self._bgp_block(node, tokens)
        elif words[0] == "banner":
            self._banner(node, negated, tokens)
        elif not negated and words[:3] == ["macro", "name"] and node.body_lines:
            self._macro(node)
        elif words[:2] == ["ip", "prefix-list"]:
            if negated:
                self._no_prefix_list(node)
            else:
                self._prefix_list(node)
        elif not negated and words[0] == "route-map":
            self._route_map(node)
        else:
            raise _Reject("No semantic handler for this statement")

    # --------------------------------------------------------------- hostname
    def _hostname(self, node: ConfigNode) -> None:
        match = _HOSTNAME_LINE.fullmatch(node.command)
        if match is None:
            raise _Reject("hostname requires exactly one name", invalid=True)
        self.document.hostname = match.group("hostname")
        self._parsed(node)

    # -------------------------------------------------------------- interface
    def _interface(self, node: ConfigNode, tokens: list[str]) -> None:
        if len(tokens) != 2 or _INTERFACE_NAME.fullmatch(tokens[1]) is None:
            raise _Reject("Unsupported interface designation (range or spaced name)")
        name = tokens[1]
        key = name.casefold()
        interface = self._interfaces.setdefault(key, Interface(name=name))
        trunk = self._interface_trunks.setdefault(key, _TrunkState())
        interface.attributes.setdefault("source_lines", []).append(node.line_number)
        self._parsed(node)
        for child in node.children:
            try:
                self._interface_child(interface, trunk, child)
            except _Reject as rejection:
                self._reject(
                    child, rejection.reason, invalid=rejection.invalid, parent=node
                )

    def _interface_child(
        self, interface: Interface, trunk: _TrunkState, node: ConfigNode
    ) -> None:
        if node.children:
            raise _Reject("Nested block inside interface is not supported")
        negated, tokens = _split(node)
        words = [token.casefold() for token in tokens]
        if not tokens:
            raise _Reject("Empty statement")
        if words[0] == "description":
            if negated:
                interface.description = None
            else:
                text = node.command.split(None, 1)[1] if len(tokens) > 1 else ""
                if not text:
                    raise _Reject("description requires text", invalid=True)
                interface.description = text
        elif words == ["shutdown"]:
            interface.admin_status = "down" if not negated else "up"
            history = interface.attributes.setdefault("admin_status_history", [])
            history.append(
                {
                    "line": node.line_number,
                    "statement": "no shutdown" if negated else "shutdown",
                }
            )
        elif words[:2] == ["vrf", "forwarding"] or words[:3] == [
            "ip",
            "vrf",
            "forwarding",
        ]:
            self._interface_vrf(interface, node, negated, tokens)
        elif words[:2] == ["ip", "address"]:
            self._interface_ip(interface, negated, tokens[2:])
        elif words[:2] == ["ip", "access-group"]:
            self._interface_access_group(interface, node, negated, tokens)
        elif words == ["switchport"]:
            if negated:
                interface.mode = "routed"
            elif interface.mode == "routed":
                interface.mode = None
        elif words[:2] == ["switchport", "mode"]:
            if negated and len(words) == 2:
                interface.mode = None
            elif not negated and len(words) == 3 and words[2] in {"access", "trunk"}:
                interface.mode = words[2]
            else:
                raise _Reject("Unsupported switchport mode")
        elif words[:3] == ["switchport", "access", "vlan"]:
            if negated and len(words) == 3:
                interface.access_vlan = None
            elif not negated and len(words) == 4:
                interface.access_vlan = _integer(tokens[3], 1, 4094, "VLAN ID")
            else:
                raise _Reject("Unsupported switchport access vlan syntax")
        elif words[:3] == ["switchport", "trunk", "native"] and words[3:4] == ["vlan"]:
            if negated and len(words) == 4:
                interface.attributes.pop("native_vlan", None)
            elif not negated and len(words) == 5:
                interface.attributes["native_vlan"] = _integer(
                    tokens[4], 1, 4094, "VLAN ID"
                )
            else:
                raise _Reject("Unsupported switchport trunk native vlan syntax")
        elif words[:4] == ["switchport", "trunk", "allowed", "vlan"]:
            self._trunk_allowed(trunk, negated, tokens[4:])
        else:
            raise _Reject("No semantic handler for this interface statement")
        self._parsed(node)

    @staticmethod
    def _interface_ip(interface: Interface, negated: bool, args: list[str]) -> None:
        secondaries: list[IPv4Interface] = interface.attributes.setdefault(
            "secondary_addresses", []
        )
        if negated and not args:
            interface.ipv4_addresses.clear()
            secondaries.clear()
        else:
            is_secondary = len(args) == 3 and args[2].casefold() == "secondary"
            if len(args) not in {2, 3} or (len(args) == 3 and not is_secondary):
                raise _Reject("Unsupported ip address syntax (e.g. dhcp, negotiated)")
            try:
                prefix = mask_to_prefix(args[1])
                address = IPv4Interface(f"{_address(args[0])}/{prefix}")
            except ValueError as exc:
                raise _Reject(f"Invalid ip address: {exc}", invalid=True) from exc
            if negated:
                if address in interface.ipv4_addresses:
                    interface.ipv4_addresses.remove(address)
                if address in secondaries:
                    secondaries.remove(address)
            elif is_secondary:
                if address not in interface.ipv4_addresses:
                    interface.ipv4_addresses.append(address)
                    secondaries.append(address)
            else:
                # A new primary address replaces the previous primary one.
                interface.ipv4_addresses = [
                    a for a in interface.ipv4_addresses if a in secondaries
                ]
                interface.ipv4_addresses.insert(0, address)
        primaries = [a for a in interface.ipv4_addresses if a not in secondaries]
        interface.ipv4_address = primaries[0].ip if primaries else None

    # --------------------------------------------------------------- IPv4 ACL
    @staticmethod
    def _numbered_acl_type(number: int) -> str | None:
        if 1 <= number <= 99 or 1300 <= number <= 1999:
            return "standard"
        if 100 <= number <= 199 or 2000 <= number <= 2699:
            return "extended"
        return None

    def _get_acl(self, name: str, acl_type: str) -> ACL:
        key = (acl_type.casefold(), name.casefold())
        acl = self._acls.get(key)
        if acl is None:
            acl = ACL(
                name=name,
                type=acl_type,
                attributes={"vendor": "Cisco", "acl_scope": "global"},
            )
            self._acls[key] = acl
            self._acl_order[key] = 0
        return acl

    def _access_list(
        self, node: ConfigNode, negated: bool, tokens: list[str]
    ) -> None:
        if len(tokens) != 4 or tokens[2].casefold() not in {"standard", "extended"}:
            raise _Reject("Unsupported ip access-list form.")
        acl_type = tokens[2].casefold()
        name = tokens[3]
        key = (acl_type, name.casefold())
        if negated:
            if node.children:
                raise _Reject("Negated ACL definition cannot contain entries.")
            if self._acls.pop(key, None) is None:
                self._info(
                    node,
                    "ACL_NOT_IN_PARSED_STATE",
                    "ACL removal target is not present in the parsed input.",
                )
            self._acl_order.pop(key, None)
            self._parsed(node)
            return
        acl = self._get_acl(name, acl_type)
        if acl.source_reference is None:
            acl.source_reference = self._reference(node.line_number)
        self._parsed(node)
        for child in node.children:
            acl.entries.append(child.command)
            try:
                self._parse_acl_rule(acl, child)
            except _Reject as rejection:
                self._taint_acl(acl, child.line_number, "unparsed ACL entry")
                self._reject(
                    child,
                    rejection.reason,
                    invalid=rejection.invalid,
                    parent=node,
                )

    def _numbered_access_list(
        self, node: ConfigNode, negated: bool, tokens: list[str]
    ) -> None:
        if len(tokens) < 2 or not tokens[1].isdigit():
            raise _Reject("ACL number is missing or invalid.", invalid=True)
        number = int(tokens[1])
        acl_type = self._numbered_acl_type(number)
        if acl_type is None:
            raise _Reject("ACL number is outside the supported IPv4 ranges.")
        name = str(number)
        key = (acl_type, name)
        if negated:
            if len(tokens) != 2 or node.children:
                acl = self._acls.get(key)
                if acl is not None:
                    self._taint_acl(acl, node.line_number, "unsupported ACL removal form")
                raise _Reject("Only whole numbered ACL removal is supported.")
            if self._acls.pop(key, None) is None:
                self._info(
                    node,
                    "ACL_NOT_IN_PARSED_STATE",
                    "ACL removal target is not present in the parsed input.",
                )
            self._acl_order.pop(key, None)
            self._parsed(node)
            return
        acl = self._get_acl(name, acl_type)
        if acl.source_reference is None:
            acl.source_reference = self._reference(node.line_number)
        acl.entries.append(node.command)
        try:
            self._parse_acl_rule(acl, node, tokens=tokens[2:])
        except _Reject as rejection:
            self._taint_acl(acl, node.line_number, "unparsed ACL entry")
            self._reject(node, rejection.reason, invalid=rejection.invalid)

    def _parse_acl_rule(
        self,
        acl: ACL,
        node: ConfigNode,
        *,
        tokens: list[str] | None = None,
    ) -> None:
        parts = node.command.split() if tokens is None else list(tokens)
        if node.children or not parts:
            raise _Reject("ACL entry is empty or nested.", invalid=True)
        sequence: int | None = None
        if parts[0].isdigit():
            sequence = int(parts.pop(0))
            if sequence < 1:
                raise _Reject("ACL sequence must be positive.", invalid=True)
        if not parts:
            raise _Reject("ACL action is missing.", invalid=True)

        order_key = (acl.type or "", acl.name.casefold())
        input_order = self._acl_order[order_key]
        self._acl_order[order_key] += 1
        action = parts.pop(0).casefold()
        reference = self._reference(node.line_number)
        if action == "remark":
            if not parts:
                raise _Reject("ACL remark text is missing.", invalid=True)
            rule = ACLRule(
                input_order=input_order,
                sequence=sequence,
                remark=" ".join(parts),
                source_reference=reference,
            )
        elif action in {"permit", "deny"}:
            rule = self._parse_acl_match(
                parts,
                acl.type or "",
                action,
                input_order,
                sequence,
                reference,
            )
        else:
            raise _Reject("ACL action is not supported.")
        if sequence is not None and any(
            existing.sequence == sequence for existing in acl.rules
        ):
            acl.complete = False
            reason = f"duplicate explicit sequence at line {node.line_number}"
            acl.incomplete_reasons.append(reason)
            rule.complete = False
            rule.incomplete_reasons.append(reason)
            acl.rules.append(rule)
            self._parsed(node)
            self._reject(
                node,
                "Duplicate ACL sequence; evaluation order is ambiguous.",
                code="DUPLICATE_ACL_SEQUENCE",
            )
            return
        acl.rules.append(rule)
        self._parsed(node)

    def _parse_acl_match(
        self,
        parts: list[str],
        acl_type: str,
        action: str,
        input_order: int,
        sequence: int | None,
        reference: SourceReference,
    ) -> ACLRule:
        if acl_type == "standard":
            source, index = self._acl_address(parts, 0)
            log: bool | None = None
            if index < len(parts) and parts[index].casefold() == "log":
                log = True
                index += 1
            if index != len(parts):
                raise _Reject("Standard ACL options are not supported.")
            return ACLRule(
                input_order=input_order,
                sequence=sequence,
                action=action,
                source=source,
                log=log,
                source_reference=reference,
            )

        if acl_type != "extended" or not parts:
            raise _Reject("ACL type or protocol is not supported.")
        protocol = parts[0].casefold()
        if protocol not in {"ip", "tcp", "udp", "icmp"}:
            raise _Reject("ACL protocol is not supported.")
        source, index = self._acl_address(parts, 1)
        source_port: ACLPortCondition | None = None
        port_operators = {"eq", "neq", "lt", "gt", "range"}
        if (
            protocol in {"tcp", "udp"}
            and index < len(parts)
            and parts[index].casefold() in port_operators
        ):
            source_port, index = self._acl_port(parts, index)
        destination, index = self._acl_address(parts, index)
        destination_port: ACLPortCondition | None = None
        if (
            protocol in {"tcp", "udp"}
            and index < len(parts)
            and parts[index].casefold() in port_operators
        ):
            destination_port, index = self._acl_port(parts, index)
        log = None
        if index < len(parts) and parts[index].casefold() == "log":
            log = True
            index += 1
        if index != len(parts):
            raise _Reject("Extended ACL option is not supported.")
        return ACLRule(
            input_order=input_order,
            sequence=sequence,
            action=action,
            protocol=protocol,
            source=source,
            destination=destination,
            source_port=source_port,
            destination_port=destination_port,
            log=log,
            source_reference=reference,
        )

    @staticmethod
    def _acl_address(
        parts: list[str], index: int
    ) -> tuple[ACLAddressCondition, int]:
        if index >= len(parts):
            raise _Reject("ACL address condition is missing.", invalid=True)
        token = parts[index].casefold()
        if token == "any":
            return ACLAddressCondition(kind="any"), index + 1
        if token == "host":
            if index + 1 >= len(parts):
                raise _Reject("ACL host address is missing.", invalid=True)
            try:
                address = IPv4Address(parts[index + 1])
            except AddressValueError as exc:
                raise _Reject("ACL host address is invalid.", invalid=True) from exc
            return ACLAddressCondition(kind="host", address=address), index + 2
        try:
            address = IPv4Address(parts[index])
        except AddressValueError as exc:
            if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", parts[index]):
                raise _Reject("ACL IPv4 address is invalid.", invalid=True) from exc
            raise _Reject("ACL address form is not supported.") from exc
        if index + 1 < len(parts):
            try:
                wildcard = IPv4Address(parts[index + 1])
            except AddressValueError:
                wildcard = None
            if wildcard is not None:
                return (
                    ACLAddressCondition(
                        kind="wildcard", address=address, wildcard_mask=wildcard
                    ),
                    index + 2,
                )
        return ACLAddressCondition(kind="host", address=address), index + 1

    @staticmethod
    def _acl_port(
        parts: list[str], index: int
    ) -> tuple[ACLPortCondition, int]:
        if index >= len(parts):
            raise _Reject("ACL port operator is missing.", invalid=True)
        operator = parts[index].casefold()
        if operator not in {"eq", "neq", "lt", "gt", "range"}:
            raise _Reject("ACL port operator is not supported.")
        required = 2 if operator == "range" else 1
        if len(parts) < index + required + 1:
            raise _Reject("ACL port value is missing.", invalid=True)
        values = parts[index + 1 : index + required + 1]
        if any(not value.isdigit() for value in values):
            raise _Reject("Named ACL ports are not supported.")
        numbers = [int(value) for value in values]
        if any(value > 65535 for value in numbers):
            raise _Reject("ACL port is outside the numeric range.", invalid=True)
        if required == 2 and numbers[0] > numbers[1]:
            raise _Reject("ACL port range is descending.", invalid=True)
        return (
            ACLPortCondition(
                operator=operator,
                first_port=numbers[0],
                last_port=numbers[1] if required == 2 else None,
            ),
            index + required + 1,
        )

    def _taint_acl(self, acl: ACL, line: int, reason: str) -> None:
        acl.complete = False
        acl.incomplete_reasons.append(f"line {line}: {reason}")
        acl.incomplete_source_references.append(self._reference(line))

    def _finish_acls(self) -> None:
        same_name: dict[str, list[ACL]] = {}
        for acl in self.document.acls:
            same_name.setdefault(acl.name.casefold(), []).append(acl)
        for candidates in same_name.values():
            if len(candidates) > 1:
                for acl in candidates:
                    acl.complete = False
                    acl.incomplete_reasons.append(
                        "the same ACL identifier exists in multiple ACL types"
                    )
        for acl in self.document.acls:
            if not acl.rules:
                continue
            explicit = [rule.sequence is not None for rule in acl.rules]
            sequences = [rule.sequence for rule in acl.rules]
            if all(explicit) and len(set(sequences)) == len(sequences):
                acl.rules.sort(key=lambda rule: rule.sequence or 0)
            elif any(explicit) and not all(explicit):
                acl.complete = False
                acl.incomplete_reasons.append(
                    "mixed explicit and implicit sequence; declaration order retained"
                )

    def _interface_access_group(
        self,
        interface: Interface,
        node: ConfigNode,
        negated: bool,
        tokens: list[str],
    ) -> None:
        if len(tokens) != 4 or tokens[3].casefold() not in {"in", "out"}:
            raise _Reject("Only IPv4 interface access-group in/out is supported.")
        name, direction = tokens[2], tokens[3].casefold()
        existing = [
            binding
            for binding in self._acl_bindings
            if binding.target_type == "interface"
            and binding.target_name.casefold() == interface.name.casefold()
            and binding.acl_name.casefold() == name.casefold()
            and binding.direction == direction
        ]
        if negated:
            if existing:
                self._acl_bindings.remove(existing[-1])
            else:
                self._info(
                    node,
                    "ACL_BINDING_NOT_IN_PARSED_STATE",
                    "ACL binding removal target is not present in parsed input.",
                )
        else:
            if any(
                binding.target_type == "interface"
                and binding.target_name.casefold() == interface.name.casefold()
                and binding.direction == direction
                for binding in self._acl_bindings
            ):
                raise _Reject(
                    "Multiple ACL bindings for one interface direction are ambiguous."
                )
            self._acl_bindings.append(
                ACLBinding(
                    acl_name=name,
                    target_type="interface",
                    target_name=interface.name,
                    direction=direction,
                    source_reference=self._reference(node.line_number),
                    attributes={"vendor": "Cisco", "acl_scope": "global"},
                )
            )
        self._parsed(node)

    @staticmethod
    def _trunk_allowed(trunk: _TrunkState, negated: bool, args: list[str]) -> None:
        if negated:
            if args:
                raise _Reject("Unsupported 'no switchport trunk allowed vlan' syntax")
            trunk.kind, trunk.vlans = "unspecified", set()
            return
        words = [arg.casefold() for arg in args]
        if words == ["all"]:
            trunk.kind, trunk.vlans = "all", set()
        elif words == ["none"]:
            trunk.kind, trunk.vlans = "list", set()
        elif len(args) == 1:
            trunk.kind, trunk.vlans = "list", _vlan_list(args[0])
        elif len(args) == 2 and words[0] in {"add", "remove", "except"}:
            vlans = _vlan_list(args[1])
            if words[0] == "except":
                trunk.kind, trunk.vlans = "all_except", vlans
            elif words[0] == "add":
                if trunk.kind == "list":
                    trunk.vlans |= vlans
                elif trunk.kind == "all_except":
                    trunk.vlans -= vlans
                else:
                    trunk.kind, trunk.vlans = "all", set()
            elif trunk.kind == "list":
                trunk.vlans -= vlans
            elif trunk.kind == "all_except":
                trunk.vlans |= vlans
            else:
                trunk.kind, trunk.vlans = "all_except", vlans
        else:
            raise _Reject("Unsupported switchport trunk allowed vlan syntax")

    @staticmethod
    def _finish_trunk(interface: Interface, trunk: _TrunkState) -> None:
        if trunk.kind == "unspecified":
            return
        interface.attributes["trunk_allowed_state"] = trunk.kind
        if trunk.kind == "list":
            interface.trunk_vlans = sorted(trunk.vlans)
        elif trunk.kind == "all_except":
            interface.attributes["trunk_excluded_vlans"] = sorted(trunk.vlans)

    # ------------------------------------------------------------------- vlan
    def _vlan(self, node: ConfigNode, tokens: list[str]) -> None:
        if len(tokens) != 2 or not tokens[1].isdigit():
            raise _Reject("Unsupported vlan statement (list, range or name)")
        vlan_id = _integer(tokens[1], 1, 4094, "VLAN ID")
        vlan = self._vlans.setdefault(vlan_id, VLAN(vlan_id=vlan_id))
        self._parsed(node)
        for child in node.children:
            try:
                negated, parts = _split(child)
                if child.children:
                    raise _Reject("Nested block inside vlan is not supported")
                if parts and parts[0].casefold() == "name" and not negated:
                    if len(parts) < 2:
                        raise _Reject("vlan name requires a value", invalid=True)
                    vlan.name = child.command.split(None, 1)[1]
                    self._parsed(child)
                else:
                    raise _Reject("No semantic handler for this vlan statement")
            except _Reject as rejection:
                self._reject(
                    child, rejection.reason, invalid=rejection.invalid, parent=node
                )

    # ----------------------------------------------------------- static route
    def _static_route(self, node: ConfigNode, negated: bool, args: list[str]) -> None:
        if node.children:
            raise _Reject("Nested block inside ip route is not supported")
        vrf: str | None = None
        if args[:1] and args[0].casefold() == "vrf":
            if len(args) < 2:
                raise _Reject("ip route vrf requires a name", invalid=True)
            vrf, args = args[1], args[2:]
        if len(args) < 2:
            raise _Reject("ip route requires prefix and mask", invalid=True)
        try:
            network = IPv4Network(
                f"{_address(args[0])}/{mask_to_prefix(args[1])}", strict=True
            )
        except ValueError as exc:
            raise _Reject(f"Invalid ip route prefix: {exc}", invalid=True) from exc
        rest = args[2:]
        next_hops: list[IPv4Address] = []
        interfaces: list[str] = []
        if rest and _INTERFACE_NAME.fullmatch(rest[0]) and not _is_ipv4(rest[0]):
            interfaces.append(rest.pop(0))
        if rest and _is_ipv4(rest[0]):
            next_hops.append(IPv4Address(rest.pop(0)))
        distance: int | None = None
        attributes: dict[str, object] = {}
        if rest and rest[0].isdigit():
            distance = _integer(rest.pop(0), 1, 255, "administrative distance")
        while rest:
            option = rest.pop(0).casefold()
            if option == "permanent":
                attributes["permanent"] = True
            elif option in {"tag", "name"} and rest:
                value = rest.pop(0)
                attributes[option] = (
                    _integer(value, 1, 4294967295, "tag") if option == "tag" else value
                )
            else:
                raise _Reject(f"Unsupported ip route option {option!r}")
        if not negated and not next_hops and not interfaces:
            raise _Reject("ip route requires a next hop or interface")
        routes = self.document.static_routes
        if negated:
            kept = [
                r
                for r in routes
                if not (
                    r.network == network
                    and r.vrf == vrf
                    and (
                        (not next_hops and not interfaces)
                        or (
                            r.next_hops == next_hops
                            and r.outgoing_interfaces == interfaces
                        )
                    )
                )
            ]
            if len(kept) == len(routes):
                self._info(node, "NO_MATCHING_ROUTE", "No earlier ip route matched.")
            self.document.static_routes = kept
        else:
            attributes["line_number"] = node.line_number
            attributes["source_reference"] = self._reference(node.line_number)
            duplicate = any(
                r.network == network
                and r.vrf == vrf
                and r.next_hops == next_hops
                and r.outgoing_interfaces == interfaces
                for r in routes
            )
            if not duplicate:
                routes.append(
                    Route(
                        network=network,
                        protocol="static",
                        next_hops=next_hops,
                        outgoing_interfaces=interfaces,
                        administrative_distance=distance,
                        vrf=vrf,
                        attributes=attributes,
                    )
                )
        self._parsed(node)

    # -------------------------------------------------------------------- vrf
    def _warn(self, node: ConfigNode, code: str, message: str) -> None:
        self.issues.append(
            ParseIssue(
                severity=IssueSeverity.WARNING,
                code=code,
                message=message,
                line_number=node.line_number,
                source_reference=self._reference(node.line_number),
            )
        )

    def _interface_vrf(
        self,
        interface: Interface,
        node: ConfigNode,
        negated: bool,
        tokens: list[str],
    ) -> None:
        args = tokens[2:] if tokens[0].casefold() == "vrf" else tokens[3:]
        if len(args) > 1 or (not negated and len(args) != 1):
            raise _Reject("vrf forwarding requires exactly one VRF name", invalid=True)
        if negated:
            if args and interface.vrf != args[0]:
                self._info(node, "NO_MATCHING_VRF", "Interface was not in that VRF.")
                return
            interface.vrf = None
            interface.vrf_source_reference = None
            return
        if interface.ipv4_addresses and interface.vrf != args[0]:
            # A device removes IPv4 addresses when the VRF changes; replaying
            # change commands is not implemented, so flag the uncertainty.
            interface.attributes["address_validity_uncertain"] = True
            self._warn(
                node,
                "VRF_ASSIGNMENT_AFTER_IP_ADDRESS",
                "vrf forwarding follows ip address; a device would remove the "
                "address. Address validity is uncertain (change-command replay "
                "is not implemented).",
            )
        interface.vrf = args[0]
        interface.vrf_source_reference = self._reference(node.line_number)

    def _no_vrf_definition(self, node: ConfigNode, tokens: list[str]) -> None:
        if len(tokens) != 3:
            raise _Reject("VRF definition requires exactly one name", invalid=True)
        if self._vrfs.pop(tokens[2], None) is None:
            self._info(node, "NO_MATCHING_VRF", "No earlier VRF definition.")
        self._parsed(node)

    def _vrf_definition(
        self, node: ConfigNode, tokens: list[str], *, legacy: bool
    ) -> None:
        if len(tokens) != 3:
            raise _Reject("VRF definition requires exactly one name", invalid=True)
        name = tokens[2]
        vrf = self._vrfs.setdefault(
            name, VRF(name=name, source_reference=self._reference(node.line_number))
        )
        styles = vrf.attributes.setdefault("definition_styles", [])
        style = "ip vrf" if legacy else "vrf definition"
        if style not in styles:
            styles.append(style)
        self._parsed(node)
        self._vrf_children(vrf, node)

    def _vrf_children(self, vrf: VRF, parent: ConfigNode) -> None:
        for child in parent.children:
            try:
                self._vrf_child(vrf, child)
            except _Reject as rejection:
                self._reject(
                    child, rejection.reason, invalid=rejection.invalid, parent=parent
                )

    def _vrf_child(self, vrf: VRF, node: ConfigNode) -> None:
        negated, tokens = _split(node)
        words = [token.casefold() for token in tokens]
        if not tokens:
            raise _Reject("Empty statement")
        if words[0] == "address-family":
            if negated or words[1:] not in (["ipv4"], ["ipv4", "unicast"]):
                raise _Reject("Only VRF address-family ipv4 is supported")
            self._parsed(node)
            self._vrf_children(vrf, node)
            return
        if node.children:
            raise _Reject("Nested block inside VRF statement is not supported")
        if words[0] == "description":
            text = node.command.split(None, 2 if negated else 1)[-1]
            if negated:
                vrf.description = None
            elif len(tokens) < 2:
                raise _Reject("description requires text", invalid=True)
            else:
                vrf.description = text
        elif words[0] == "rd":
            if negated:
                vrf.route_distinguisher = None
            elif len(tokens) == 2 and _ROUTE_DISTINGUISHER.fullmatch(tokens[1]):
                vrf.route_distinguisher = tokens[1]
            else:
                raise _Reject("Invalid route distinguisher", invalid=True)
        elif words[0] == "route-target":
            self._route_target(vrf, node, negated, tokens)
        elif words == ["exit-address-family"] and not negated:
            pass
        else:
            raise _Reject("No semantic handler for this VRF statement")
        self._parsed(node)

    @staticmethod
    def _route_target(
        vrf: VRF, node: ConfigNode, negated: bool, tokens: list[str]
    ) -> None:
        args = tokens[1:]
        if len(args) == 1:
            args = ["both", *args]
        if (
            len(args) != 2
            or args[0].casefold() not in {"import", "export", "both"}
            or _ROUTE_DISTINGUISHER.fullmatch(args[1]) is None
        ):
            raise _Reject("Invalid route-target statement", invalid=True)
        entries: list[dict[str, object]] = vrf.attributes.setdefault(
            "route_targets", []
        )
        direction, value = args[0].casefold(), args[1]
        entries[:] = [
            e for e in entries if (e["direction"], e["value"]) != (direction, value)
        ]
        if not negated:
            entries.append(
                {"direction": direction, "value": value, "line": node.line_number}
            )

    # ------------------------------------------------------------------- ospf
    def _ospf_block(self, node: ConfigNode, tokens: list[str]) -> None:
        vrf: str | None = None
        if len(tokens) == 5 and tokens[3].casefold() == "vrf":
            vrf = tokens[4]
        elif len(tokens) != 3:
            raise _Reject("Unsupported router ospf syntax")
        process_id = str(_integer(tokens[2], 1, 65535, "OSPF process ID"))
        process = self._ospf.setdefault(
            (process_id, vrf), OSPFProcess(process_id=process_id)
        )
        process.attributes.setdefault("vrf", vrf)
        process.vrf = vrf
        statements = process.attributes.setdefault("network_statements", [])
        passive = process.attributes.setdefault("passive_interfaces", [])
        active = process.attributes.setdefault("non_passive_interfaces", [])
        process.attributes.setdefault("passive_interface_default", False)
        self._parsed(node)
        for child in node.children:
            try:
                self._ospf_child(process, statements, passive, active, child)
            except _Reject as rejection:
                self._reject(
                    child, rejection.reason, invalid=rejection.invalid, parent=node
                )

    def _ospf_child(
        self,
        process: OSPFProcess,
        statements: list[dict[str, object]],
        passive: list[str],
        active: list[str],
        node: ConfigNode,
    ) -> None:
        if node.children:
            raise _Reject("Nested block inside router ospf is not supported")
        negated, tokens = _split(node)
        words = [token.casefold() for token in tokens]
        if words[:1] == ["router-id"] and not negated and len(tokens) == 2:
            process.router_id = _address(tokens[1])
        elif words[:1] == ["network"] and len(tokens) == 5 and words[3] == "area":
            prefix = mask_to_prefix(tokens[2], wildcard=True)
            network = IPv4Network(f"{_address(tokens[1])}/{prefix}", strict=False)
            area = tokens[4]
            if not (area.isdigit() or _is_ipv4(area)):
                raise _Reject(f"Invalid OSPF area {area!r}", invalid=True)
            statement = {
                "network": str(network),
                "wildcard": tokens[2],
                "area": area,
                "line": node.line_number,
            }
            if negated:
                before = len(statements)
                statements[:] = [
                    s
                    for s in statements
                    if (s["network"], s["area"]) != (statement["network"], area)
                ]
                if len(statements) == before:
                    self._info(node, "NO_MATCHING_NETWORK", "No earlier network.")
            elif not any(
                (s["network"], s["area"]) == (statement["network"], area)
                for s in statements
            ):
                statements.append(statement)
            process.networks = [str(s["network"]) for s in statements]
            process.areas = list(dict.fromkeys(str(s["area"]) for s in statements))
        elif words[:1] == ["passive-interface"] and len(tokens) == 2:
            target = tokens[1]
            if words[1] == "default":
                process.attributes["passive_interface_default"] = not negated
                passive.clear()
                active.clear()
            elif _INTERFACE_NAME.fullmatch(target) is None:
                raise _Reject("Unsupported passive-interface target")
            elif negated:
                _discard(passive, target)
                if target not in active:
                    active.append(target)
            else:
                _discard(active, target)
                if target not in passive:
                    passive.append(target)
        else:
            raise _Reject("No semantic handler for this router ospf statement")
        self._parsed(node)

    # -------------------------------------------------------------------- bgp
    def _bgp_block(self, node: ConfigNode, tokens: list[str]) -> None:
        if len(tokens) != 3 or not tokens[2].isdigit():
            raise _Reject("Unsupported router bgp AS number format (e.g. asdot)")
        asn = _integer(tokens[2], 1, 4294967295, "AS number")
        if self._bgp is not None and self._bgp.asn != asn:
            raise _Reject(
                f"Second BGP process AS {asn} conflicts with AS {self._bgp.asn}",
                invalid=True,
            )
        bgp = self._bgp or BGPProcess(asn=asn)
        self._bgp = bgp
        self._parsed(node)
        for child in node.children:
            self._bgp_child(bgp, node, child, scope=None)

    def _bgp_child(
        self,
        bgp: BGPProcess,
        parent: ConfigNode,
        node: ConfigNode,
        scope: _BgpScope | None,
    ) -> None:
        try:
            self._bgp_statement(bgp, node, scope)
        except _Reject as rejection:
            self._reject(
                node, rejection.reason, invalid=rejection.invalid, parent=parent
            )

    def _bgp_statement(
        self, bgp: BGPProcess, node: ConfigNode, scope: _BgpScope | None
    ) -> None:
        negated, tokens = _split(node)
        words = [token.casefold() for token in tokens]
        if not tokens:
            raise _Reject("Empty statement")
        if words == ["exit-address-family"] and not negated:
            self._parsed(node)
            return
        if words[0] == "address-family" and not negated:
            if scope is not None:
                raise _Reject("Nested address-family is not supported")
            spec = words[1:]
            if spec[:2] == ["ipv4", "unicast"]:
                spec = ["ipv4", *spec[2:]]
            new_scope: _BgpScope
            if spec == ["ipv4"]:
                if "ipv4" not in bgp.address_families:
                    bgp.address_families.append("ipv4")
                new_scope = _BgpScope("ipv4", None, bgp)
            elif len(spec) == 3 and spec[:2] == ["ipv4", "vrf"]:
                vrf_name = tokens[-1]
                vrf_family = next(
                    (a for a in bgp.vrf_address_families if a.vrf == vrf_name), None
                )
                if vrf_family is None:
                    vrf_family = BGPVrfAddressFamily(
                        vrf=vrf_name,
                        source_reference=self._reference(node.line_number),
                    )
                    bgp.vrf_address_families.append(vrf_family)
                new_scope = _BgpScope(f"ipv4 vrf {vrf_name}", vrf_name, vrf_family)
            else:
                raise _Reject(
                    "Only 'address-family ipv4 [unicast] [vrf NAME]' is supported"
                )
            self._parsed(node)
            for child in node.children:
                self._bgp_child(bgp, node, child, scope=new_scope)
            return
        if node.children:
            raise _Reject("Nested block inside router bgp is not supported")
        family = scope.family if scope else "global"
        target = scope.target if scope else bgp
        if words[:2] == ["bgp", "router-id"] and not negated and len(tokens) == 3:
            if scope is not None and scope.vrf is not None:
                raise _Reject("bgp router-id inside a VRF address-family")
            bgp.router_id = _address(tokens[2])
        elif words[0] == "network":
            self._bgp_network(target, node, negated, tokens, family)
        elif words[0] == "neighbor" and len(tokens) >= 3:
            self._bgp_neighbor(bgp, target, node, negated, tokens, family)
        else:
            raise _Reject("No semantic handler for this router bgp statement")
        self._parsed(node)

    def _bgp_network(
        self,
        bgp: BGPProcess | BGPVrfAddressFamily,
        node: ConfigNode,
        negated: bool,
        tokens: list[str],
        family: str,
    ) -> None:
        if len(tokens) < 4 or tokens[2].casefold() != "mask":
            raise _Reject("network without explicit mask is not guessed")
        try:
            network = IPv4Network(
                f"{_address(tokens[1])}/{mask_to_prefix(tokens[3])}", strict=True
            )
        except ValueError as exc:
            raise _Reject(f"Invalid network: {exc}", invalid=True) from exc
        route_map: str | None = None
        extra = tokens[4:]
        if extra:
            if len(extra) == 2 and extra[0].casefold() == "route-map":
                route_map = extra[1]
            else:
                raise _Reject("Unsupported network options")
        address_family = "ipv4"
        if negated:
            before = len(bgp.networks)
            bgp.networks = [
                n
                for n in bgp.networks
                if not (n.network == network and n.address_family == address_family)
            ]
            if len(bgp.networks) == before:
                self._info(node, "NO_MATCHING_NETWORK", "No earlier network matched.")
        else:
            bgp.networks = [
                n
                for n in bgp.networks
                if not (n.network == network and n.address_family == address_family)
            ]
            bgp.networks.append(
                BGPNetwork(
                    network=network,
                    address_family=address_family,
                    route_map=route_map,
                    line_number=node.line_number,
                )
            )
        if family == "global" and isinstance(bgp, BGPProcess):
            bgp.attributes.setdefault("global_network_lines", []).append(
                node.line_number
            )

    def _bgp_neighbor(
        self,
        bgp: BGPProcess,
        target: BGPProcess | BGPVrfAddressFamily,
        node: ConfigNode,
        negated: bool,
        tokens: list[str],
        family: str,
    ) -> None:
        if not _is_ipv4(tokens[1]):
            raise _Reject("Only IPv4 neighbor addresses are supported (no peer-groups)")
        address = IPv4Address(tokens[1])
        peer = next((p for p in target.peers if p.neighbor_address == address), None)
        if peer is None:
            peer = BGPPeer(neighbor_address=address, local_as=bgp.asn)
            target.peers.append(peer)
        option = tokens[2].casefold()
        args = tokens[3:]
        if option == "remote-as" and not negated and len(args) == 1:
            peer.remote_as = _integer(args[0], 1, 4294967295, "AS number")
        elif option == "description" and not negated and args:
            peer.description = node.command.split(None, 3)[3]
        elif option == "shutdown" and not args:
            peer.attributes.setdefault("shutdown_history", []).append(
                {
                    "line": node.line_number,
                    "statement": "no shutdown" if negated else "shutdown",
                }
            )
            peer.attributes["shutdown"] = not negated
        elif option == "activate" and not args:
            active = peer.attributes.setdefault("activated_address_families", [])
            af_name = family if family != "global" else "ipv4"
            if negated:
                _discard(active, af_name)
            elif af_name not in active:
                active.append(af_name)
        elif option in {"route-map", "prefix-list"} and len(args) == 2:
            direction = args[1].casefold()
            if direction not in {"in", "out"}:
                raise _Reject(f"Invalid direction {args[1]!r}", invalid=True)
            attribute = f"{option.replace('-', '_')}_{direction}"
            current = getattr(peer, attribute)
            if negated:
                if current == args[0]:
                    setattr(peer, attribute, None)
                else:
                    self._info(node, "NO_MATCHING_POLICY", "No matching binding.")
            else:
                setattr(peer, attribute, args[0])
            bindings = peer.attributes.setdefault("policy_bindings", [])
            bindings[:] = [
                b
                for b in bindings
                if (b["type"], b["direction"]) != (option, direction)
            ]
            if not negated:
                bindings.append(
                    {
                        "type": option,
                        "direction": direction,
                        "name": args[0],
                        "address_family": family,
                        "line": node.line_number,
                    }
                )
        else:
            raise _Reject("No semantic handler for this neighbor statement")

    # ------------------------------------------------------ banner and macro
    def _banner(self, node: ConfigNode, negated: bool, tokens: list[str]) -> None:
        if negated:
            if len(tokens) != 2:
                raise _Reject("Unsupported 'no banner' form")
            kind = tokens[1].casefold()
            self._banners = [b for b in self._banners if b.kind.casefold() != kind]
            self._parsed(node)
            return
        if node.end_line is None:
            raise _Reject("banner without a delimiter and text", invalid=True)
        if not node.terminated:
            raise _Reject(
                "Banner is missing its closing delimiter; the remaining lines "
                "were consumed as banner text.",
                invalid=True,
            )
        kind = tokens[1]
        self._banners = [
            b for b in self._banners if b.kind.casefold() != kind.casefold()
        ]
        self._banners.append(
            Banner(
                kind=kind,
                text="\n".join(node.body_lines),
                source_reference=self._reference(node.line_number, node.end_line),
            )
        )
        self._parsed(node)

    def _macro(self, node: ConfigNode) -> None:
        if not node.terminated:
            raise _Reject("Macro is missing its closing '@' line.", invalid=True)
        raise _Reject("Macro bodies are preserved but not interpreted")

    # ------------------------------------------------------------ prefix-list
    @staticmethod
    def _prefix_fields(
        prefix_text: str, ge_text: str | None, le_text: str | None
    ) -> tuple[IPv4Network, int | None, int | None]:
        prefix = IPv4Network(prefix_text, strict=True)
        ge = int(ge_text) if ge_text else None
        le = int(le_text) if le_text else None
        if ge is not None and not prefix.prefixlen <= ge <= 32:
            raise ValueError("ge must be between the prefix length and 32")
        if le is not None and not prefix.prefixlen <= le <= 32:
            raise ValueError("le must be between the prefix length and 32")
        if ge is not None and le is not None and ge > le:
            raise ValueError("ge cannot be greater than le")
        return prefix, ge, le

    def _no_prefix_list(self, node: ConfigNode) -> None:
        """Apply 'no ip prefix-list ...' in file order against parsed state.

        Removal is applied only when the target is found in the state built so
        far. A missing or ambiguous target is never assumed away: the list is
        marked incomplete and the line is reported.
        """
        body = node.command.split(None, 1)[1]
        name_match = _PREFIX_NAME.match(body)
        if name_match is None:
            raise _Reject("Unsupported 'no ip prefix-list' form")
        name = name_match.group("name")
        if name.casefold() == "sequence-number":
            raise _Reject("'ip prefix-list sequence-number' is not interpreted")
        rest = body[name_match.end() :].strip()
        words = rest.split()
        if not rest:
            if self._prefix_lists.pop(name, None) is None:
                self._info(
                    node,
                    "PREFIX_LIST_NOT_IN_PARSED_STATE",
                    f"Prefix-list {name} was not defined earlier in this input.",
                )
            self._parsed(node)
            return
        if words[0].casefold() == "description":
            plist = self._prefix_lists.get(name)
            if plist is not None:
                plist.description = None
            self._parsed(node)
            return
        match = _NO_PREFIX_ENTRY.fullmatch(rest)
        if match is None or (not match.group("sequence") and not match.group("action")):
            self._taint_prefix_list(name_match, node.line_number, "unsupported removal")
            self._reject(
                node,
                "'no ip prefix-list' form is not supported.",
                code="UNSUPPORTED_PREFIX_LIST_SYNTAX",
                severity=IssueSeverity.ERROR,
            )
            return
        wanted: tuple[IPv4Network, int | None, int | None] | None = None
        if match.group("action"):
            try:
                wanted = self._prefix_fields(
                    match.group("prefix"), match.group("ge"), match.group("le")
                )
            except ValueError as exc:
                self._taint_prefix_list(name_match, node.line_number, str(exc))
                self._reject(
                    node,
                    f"Invalid prefix-list removal: {exc}",
                    invalid=True,
                    code="INVALID_PREFIX_LIST_ENTRY",
                )
                return
        plist = self._prefix_lists.get(name)
        candidates = [
            entry
            for entry in (plist.entries if plist else [])
            if self._removal_matches(entry, match, wanted)
        ]
        if plist is None or len(candidates) != 1:
            why = (
                "target entry not found in parsed state"
                if not candidates
                else "removal matches several entries"
            )
            self._taint_prefix_list(name_match, node.line_number, why)
            self._reject(
                node,
                f"Prefix-list removal not applied: {why}.",
                code="PREFIX_LIST_REMOVAL_UNRESOLVED",
            )
            return
        plist.entries.remove(candidates[0])
        self._parsed(node)

    @staticmethod
    def _removal_matches(
        entry: PrefixListEntry,
        match: re.Match[str],
        wanted: tuple[IPv4Network, int | None, int | None] | None,
    ) -> bool:
        if match.group("sequence"):
            if entry.sequence != int(match.group("sequence")):
                return False
        if wanted is not None:
            prefix, ge, le = wanted
            return (
                entry.action == match.group("action").lower()
                and entry.prefix == prefix
                and entry.ge == ge
                and entry.le == le
            )
        return True

    def _prefix_list(self, node: ConfigNode) -> None:
        command = node.command
        description = _PREFIX_DESCRIPTION.fullmatch(command)
        name_match = _PREFIX_NAME.match(command)
        if description is not None:
            plist = self._prefix_lists.setdefault(
                description.group("name"), PrefixList(name=description.group("name"))
            )
            plist.description = description.group("text").strip()
            self._parsed(node)
            return
        match = _PREFIX_LINE.fullmatch(command)
        if match is None:
            self._taint_prefix_list(name_match, node.line_number, "unsupported syntax")
            self._reject(
                node,
                "Prefix-list line does not match the supported Cisco syntax.",
                code="UNSUPPORTED_PREFIX_LIST_SYNTAX",
                severity=IssueSeverity.ERROR,
            )
            return
        try:
            prefix, ge, le = self._prefix_fields(
                match.group("prefix"), match.group("ge"), match.group("le")
            )
        except ValueError as exc:
            self._taint_prefix_list(name_match, node.line_number, str(exc))
            self._reject(
                node,
                f"Invalid prefix-list entry: {exc}",
                invalid=True,
                code="INVALID_PREFIX_LIST_ENTRY",
            )
            return
        name = match.group("name")
        plist = self._prefix_lists.setdefault(name, PrefixList(name=name))
        sequence = int(match.group("sequence")) if match.group("sequence") else None
        if sequence is not None and any(e.sequence == sequence for e in plist.entries):
            plist.complete = False
            plist.incomplete_reasons.append(
                f"duplicate sequence {sequence} at line {node.line_number}"
            )
            self._reject(
                node,
                f"Duplicate prefix-list sequence {sequence}; device behaviour "
                "is not assumed.",
                invalid=True,
                code="DUPLICATE_PREFIX_LIST_SEQUENCE",
            )
            return
        plist.entries.append(
            PrefixListEntry(
                sequence=sequence,
                action=match.group("action").lower(),
                prefix=prefix,
                ge=ge,
                le=le,
                source_reference=self._reference(node.line_number),
            )
        )
        self._parsed(node)

    def _taint_prefix_list(
        self, match: re.Match[str] | None, line: int, why: str
    ) -> None:
        if match is None:
            return
        name = match.group("name")
        plist = self._prefix_lists.setdefault(name, PrefixList(name=name))
        plist.complete = False
        plist.incomplete_reasons.append(f"line {line}: {why}")

    # -------------------------------------------------------------- route-map
    def _route_map(self, node: ConfigNode) -> None:
        tokens = node.command.split()
        name = tokens[1] if len(tokens) > 1 else None
        match = _ROUTE_MAP_HEADER.fullmatch(node.command)
        if match is None:
            if name is not None:
                self._taint_route_map(name, node.line_number, "unsupported header")
            raise _Reject(
                "route-map requires explicit name, permit|deny and sequence "
                "(defaults are not assumed)"
            )
        name = match.group("name")
        action = match.group("action").lower()
        sequence = int(match.group("sequence"))
        entries = self._route_maps.setdefault(name, {})
        builder = entries.get(sequence)
        if builder is not None and builder.action != action:
            self._taint_route_map(name, node.line_number, "conflicting action")
            raise _Reject(
                f"route-map {name} sequence {sequence} redefined with a different "
                "action",
                invalid=True,
            )
        if builder is None:
            builder = _EntryBuilder(action, self._reference(node.line_number))
            entries[sequence] = builder
        self._parsed(node)
        for child in node.children:
            try:
                self._route_map_child(builder, child)
            except _Reject as rejection:
                self._taint_route_map(
                    name, child.line_number, f"unparsed line: {rejection.reason}"
                )
                self._reject(
                    child, rejection.reason, invalid=rejection.invalid, parent=node
                )

    def _route_map_child(self, builder: _EntryBuilder, node: ConfigNode) -> None:
        if node.children:
            raise _Reject("Nested block inside route-map is not supported")
        negated, tokens = _split(node)
        words = [token.casefold() for token in tokens]
        if negated:
            raise _Reject("Negated route-map statements are not supported")
        if words[:1] == ["description"]:
            pass
        elif words[:3] == ["match", "ip", "address"] and len(tokens) >= 4:
            if words[3] == "prefix-list":
                if len(tokens) < 5:
                    raise _Reject("Missing prefix-list name", invalid=True)
                builder.prefix_lists.extend(tokens[4:])
            else:
                builder.acls.extend(tokens[3:])
                builder.acl_reference_sources.extend(
                    self._reference(node.line_number) for _ in tokens[3:]
                )
            builder.matches.append(node.command)
        elif words[:2] == ["set", "local-preference"] and len(tokens) == 3:
            _integer(tokens[2], 0, 4294967295, "local-preference")
            builder.sets.append(node.command)
        elif words[:2] == ["set", "metric"] and len(tokens) == 3:
            _integer(tokens[2], 0, 4294967295, "metric")
            builder.sets.append(node.command)
        elif words[:2] == ["set", "weight"] and len(tokens) == 3:
            _integer(tokens[2], 0, 65535, "weight")
            builder.sets.append(node.command)
        elif words[:3] == ["set", "ip", "next-hop"] and len(tokens) == 4:
            _address(tokens[3])
            builder.sets.append(node.command)
        else:
            raise _Reject("No semantic handler for this route-map statement")
        self._parsed(node)

    def _taint_route_map(self, name: str, line: int, why: str) -> None:
        state = self._route_map_state.setdefault(name, RouteMap(name=name))
        state.complete = False
        state.incomplete_reasons.append(f"line {line}: {why}")
        self._route_maps.setdefault(name, {})

    def _finish_route_maps(self) -> None:
        maps: list[RouteMap] = []
        for name, entries in self._route_maps.items():
            state = self._route_map_state.get(name)
            route_map = RouteMap(name=name)
            if state is not None:
                route_map.complete = state.complete
                route_map.incomplete_reasons = state.incomplete_reasons
            for sequence in sorted(entries):
                builder = entries[sequence]
                route_map.entries.append(
                    RouteMapEntry(
                        sequence=sequence,
                        action=builder.action,
                        match_conditions=tuple(builder.matches),
                        set_actions=tuple(builder.sets),
                        prefix_list_references=tuple(builder.prefix_lists),
                        acl_references=tuple(builder.acls),
                        source_reference=builder.reference,
                        acl_reference_sources=tuple(
                            builder.acl_reference_sources
                        ),
                    )
                )
            maps.append(route_map)
        self.document.route_maps = maps

    # ------------------------------------------------------------- references
    def _vrf_references(self) -> list[ConfigReference]:
        defined = set(self._vrfs)
        refs: list[ConfigReference] = []

        def add(source_type: str, source_name: str, vrf: str, line: int | None) -> None:
            refs.append(
                ConfigReference(
                    source_type, source_name, "vrf", "vrf", vrf, line, vrf in defined
                )
            )

        for interface in self.document.interfaces:
            if interface.vrf is not None:
                ref = interface.vrf_source_reference
                add(
                    "interface",
                    interface.name,
                    interface.vrf,
                    ref.start_line if ref else None,
                )
        for route in self.document.static_routes:
            if route.vrf is not None:
                line = route.attributes.get("line_number")
                add("static-route", str(route.network), route.vrf, line)
        for process in self.document.ospf_processes:
            if process.vrf is not None:
                add("ospf-process", f"ospf {process.process_id}", process.vrf, None)
        for bgp in self.document.bgp_processes:
            for family in bgp.vrf_address_families:
                ref = family.source_reference
                add(
                    "bgp-address-family",
                    f"AS{bgp.asn}/ipv4 vrf {family.vrf}",
                    family.vrf,
                    ref.start_line if ref else None,
                )
        return refs

    def _build_references(self) -> None:
        prefix_names = {p.name for p in self.document.prefix_lists}
        map_names = {m.name for m in self.document.route_maps}
        references: list[ConfigReference] = []
        for binding in self.document.acl_bindings:
            resolved, reason = self._resolve_acl_reference(binding.acl_name)
            binding_reference = binding.source_reference
            references.append(
                ConfigReference(
                    "interface",
                    binding.target_name,
                    f"access-group-{binding.direction}",
                    "acl",
                    binding.acl_name,
                    binding_reference.start_line if binding_reference else None,
                    resolved,
                    resolution_reason=reason,
                )
            )
        for route_map in self.document.route_maps:
            for entry in route_map.entries:
                for target in entry.prefix_list_references:
                    references.append(
                        ConfigReference(
                            "route-map",
                            route_map.name,
                            "match-prefix-list",
                            "prefix-list",
                            target,
                            (
                                entry.source_reference.start_line
                                if entry.source_reference
                                else None
                            ),
                            target in prefix_names,
                            entry.sequence,
                        )
                    )
                for index, target in enumerate(entry.acl_references):
                    source = (
                        entry.acl_reference_sources[index]
                        if index < len(entry.acl_reference_sources)
                        else entry.source_reference
                    )
                    resolved, reason = self._resolve_acl_reference(target)
                    references.append(
                        ConfigReference(
                            "route-map",
                            route_map.name,
                            "match-acl",
                            "acl",
                            target,
                            source.start_line if source else None,
                            resolved,
                            entry.sequence,
                            reason,
                        )
                    )
        for bgp in self.document.bgp_processes:
            peer_groups: list[tuple[str, list[BGPPeer]]] = [("", bgp.peers)]
            peer_groups += [
                (f"/vrf {a.vrf}", a.peers) for a in bgp.vrf_address_families
            ]
            for suffix, peers in peer_groups:
                for peer in peers:
                    for binding in peer.attributes.get("policy_bindings", []):
                        kind = binding["type"]
                        target_type = (
                            "route-map" if kind == "route-map" else "prefix-list"
                        )
                        names = map_names if kind == "route-map" else prefix_names
                        references.append(
                            ConfigReference(
                                "bgp-neighbor",
                                f"AS{bgp.asn}{suffix}/{peer.neighbor_address}",
                                f"{kind}-{binding['direction']}",
                                target_type,
                                binding["name"],
                                binding["line"],
                                binding["name"] in names,
                            )
                        )
            network_groups = [("", bgp.networks)]
            network_groups += [
                (f"/vrf {a.vrf}", a.networks) for a in bgp.vrf_address_families
            ]
            for suffix, networks in network_groups:
                for network in networks:
                    if network.route_map is not None:
                        references.append(
                            ConfigReference(
                                "bgp-network",
                                f"AS{bgp.asn}{suffix}/{network.network}",
                                "route-map",
                                "route-map",
                                network.route_map,
                                network.line_number,
                                network.route_map in map_names,
                            )
                        )
        references.extend(self._vrf_references())
        for config_reference in references:
            if config_reference.resolved is False:
                self.issues.append(
                    ParseIssue(
                        severity=IssueSeverity.INFO,
                        code=(
                            "VRF_DEFINITION_NOT_IN_INPUT"
                            if config_reference.target_type == "vrf"
                            else "DANGLING_REFERENCE"
                        ),
                        message=(
                            "A referenced VRF is not defined in the input."
                            if config_reference.target_type == "vrf"
                            else (
                                "ACL reference target is not defined in the parsed "
                                "configuration."
                                if config_reference.target_type == "acl"
                                else (
                                    f"{config_reference.source_type} "
                                    f"{config_reference.source_name} references "
                                    f"undefined {config_reference.target_type} "
                                    f"{config_reference.target_name!r} (it may be "
                                    "defined in unparsed or external configuration)."
                                )
                            )
                        ),
                        line_number=config_reference.line_number,
                        source_reference=(
                            self._reference(config_reference.line_number)
                            if config_reference.line_number
                            else None
                        ),
                    )
                )
            elif (
                config_reference.resolved is None
                and config_reference.target_type == "acl"
            ):
                self.issues.append(
                    ParseIssue(
                        severity=IssueSeverity.INFO,
                        code="AMBIGUOUS_REFERENCE",
                        message="ACL reference cannot be resolved unambiguously.",
                        line_number=config_reference.line_number,
                        source_reference=(
                            self._reference(config_reference.line_number)
                            if config_reference.line_number
                            else None
                        ),
                    )
                )
        self.document.references = references

    def _resolve_acl_reference(self, name: str) -> tuple[bool | None, str | None]:
        matches = [acl for acl in self.document.acls if acl.name.casefold() == name.casefold()]
        if not matches:
            return False, "No matching ACL definition was parsed."
        if len(matches) > 1:
            return None, "The identifier matches multiple ACL types."
        return True, None


def _walk(node: ConfigNode) -> list[ConfigNode]:
    nodes: list[ConfigNode] = []
    for child in node.children:
        nodes.append(child)
        nodes.extend(_walk(child))
    return nodes


def _is_ipv4(value: str) -> bool:
    try:
        IPv4Address(value)
    except AddressValueError:
        return False
    return True


def _discard(items: list[str], value: str) -> None:
    if value in items:
        items.remove(value)
