# IPv4 ACL and filter support

This document describes configuration parsing only. The framework does not
simulate packet matching, access decisions, implicit rules, stateful sessions,
or configuration changes on a device. All tests and fixtures are synthetic;
there is no device-output verification.

## Common models

- `ConfigDocument.acls` contains `ACL` definitions. The existing
  `ACL.entries: list[str]` field remains unchanged for compatibility; `rules`
  contains typed `ACLRule` objects.
- `ACLAddressCondition.kind` distinguishes `any`, `host`, `prefix`, and
  `wildcard`. An IPv4 wildcard address and mask remain separate values, even
  for a contiguous mask; non-contiguous wildcards are not converted to prefixes.
- `ACLPortCondition` stores only numeric values and the explicit operator
  (`eq`, `neq`, `lt`, `gt`, or `range`).
- `ACL.complete` and `ACL.incomplete_reasons` identify rules or sequence
  ambiguities that were not completely represented. The accompanying
  `incomplete_source_references` keep the affected line locations.
- `ConfigDocument.acl_bindings` stores each applied ACL. Binding order is kept
  in `attributes["filter_order"]` when an application line specifies a list.
- ACL relationships are also in `ConfigDocument.references`. `resolved=True`
  means only that exactly one parsed definition exists. `False` means the
  supported scope has no definition in this input. `None` means the identifier
  is ambiguous; `resolution_reason` explains this without copying the source
  condition into an issue.

No parser synthesizes an implicit deny rule. `complete=True` means all
represented configuration lines were interpreted, not that the ACL grants or
denies any particular packet.

## Evidence and implementation matrix

| Vendor / OS | Evidence consulted | Implemented subset | Not implemented / qualification |
|---|---|---|---|
| Cisco IOS / IOS XE | Cisco IOS XE 17.x Security Configuration Guide, [Access List Overview](https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/sec-vpn/b-security-vpn/m_sec-access-list-ov-0.html); Cisco [IP ACL configuration examples](https://www.cisco.com/c/en/us/support/docs/security/ios-firewall/23602-confaccesslists.html) | Numbered and named standard/extended IPv4 lists; standard source conditions; extended `ip`, `tcp`, `udp`, `icmp` entries; `any`, `host`, address/wildcard; numeric TCP/UDP operators; `remark`, `log`; interface `ip access-group ... in|out`; route-map `match ip address` reference; whole-ACL and interface-binding negation | Object groups, named ports/protocols, ICMP type/code, `log-input`, `established`, fragments, time ranges, dynamic/reflexive ACLs, `access-class`, IPv6, unsupported route-map reference scope. IOS XE syntax is reused from IOS; no IOS XE device capture was supplied |
| Yamaha RTX | Yamaha RT reference [ip filter](https://www.rtpro.yamaha.co.jp/RT/manual/rt-common/ip/ip_filter.html) and [ip interface secure filter](https://www.rtpro.yamaha.co.jp/RT/manual/rt-common/ip/ip_interface_secure_filter.html) | Static IPv4 `ip filter <id>` with documented `pass`/`reject` forms; literal host, prefix, or `*`; selected simple protocol and numeric single TCP/UDP ports; ordered static filter-number lists on supported `in`/`out` targets; `no` removal forms | `restrict*` is conditional and not mapped; FQDN, address ranges/lists, partial-octet wildcards, application mnemonics, protocol lists/special flags, named/range/list ports, ICMP type/code, filter sets and dynamic filters are not represented. Model-specific maximum binding-list sizes are not checked. PP/tunnel references require the existing selection context. No device capture supplied |
| Yamaha SWX | SWX2320/SWX3200 command-reference material used for the implemented SWX command set | None | ACL syntax and application points were not verified in the reviewed material. This is not a claim that SWX devices lack ACL support |
| Fortinet FortiOS | Existing FortiOS parser research covers global/interface/static-route sections, not an ACL-compatible CLI grammar | None | Firewall policies are not silently translated into stateless ACL rules. No stateful policy model is in this scope, and a source-verified mapping was not established |
| A10 ACOS | Existing ACOS configuration references cover system/interface/routing commands; the official CLI-reference endpoint consulted for ACLs requires customer authentication | None | ACL and VE/interface application syntax remain unverified; no API schema is used as CLI evidence |
| HPE / Comware | Existing Comware references verified in this repository cover routes, VPN instances, and interfaces; the HPE Comware 7 fundamentals reference was not retrievable anonymously | None | Basic/advanced ACL and interface `packet-filter` syntax were not validated against a specific official model/release; no device-capability claim is made |

Cisco and RTX behaviors have `TESTED_WITH_SYNTHETIC_DATA` status only. Documentation references confirm the command forms described above but do not certify support on a particular device or release.

## Cisco details

- Numbered list identifiers are kept as strings. Numeric identifiers are classified
  into the standard and extended ranges; unknown ranges are rejected rather than
  guessed as an ACL type.
- Standard entries accept `permit|deny` followed by `any`, `host IPv4`, or an
  IPv4 address with optional wildcard, then optional `log`.
- Extended entries accept only `ip`, `tcp`, `udp`, or `icmp`, source and
  destination conditions, optional numeric TCP/UDP port comparisons
  (`eq`/`neq`/`lt`/`gt`/`range`), and optional `log`. A port must be in
  0-65535; range endpoints must be ascending.
- `remark` is represented separately from permit/deny. If a sequence is
  explicit on every entry and unique, rules are sorted by that documented
  sequence while retaining `input_order`. With implicit sequences, declaration
  order is retained. A mixed explicit/implicit or duplicate sequence makes the
  ACL incomplete; the parser does not invent sequence values.
- Repeated declarations of one ACL type are collected in source order.
  Same-name standard and extended lists are kept separately; a reference to that
  name is `resolved=None` because the type cannot be determined from the
  reference.
- An unsupported or malformed entry is retained in `ACL.entries`,
  `ConfigDocument.unsupported_lines`, and `ParseResult.unparsed_ranges`. The
  rest of that ACL and unrelated configuration remain available.
- Interface application supports IPv4 `ip access-group <name-or-number> in|out`.
  VTY `access-class` is not treated as an interface binding. Route-map
  `match ip address` targets are resolved after all ACLs have been parsed, so
  definitions can appear later in the file.

## Yamaha RTX details

- An `ip filter` identifier is modelled as one ACL containing one rule;
  `sequence` stores the source filter ID, not an evaluation order.
- A secure-filter application line creates one `ACLBinding` per static filter
  ID and stores its position in the line. This preserves the documented
  application order; no permit/deny simulation is performed.
- `pass*` maps to common action `permit`, `reject*` to `deny`; the source action
  is retained in `ACLRule.attributes["vendor_action"]`. `log` is set only when
  the suffix explicitly expresses it.
- The reference documents that omitted destination and protocol have `*`
  meaning. Those documented defaults are represented as `any` and IPv4 `ip`.
  This does not generalize to other vendors.
- The stateless ACL models do not represent `restrict` or dynamic filtering.
  Such lines remain unsupported instead of being converted to an unconditional
  permit or deny.

## Synthetic verification

Focused synthetic tests are in `tests/unit/test_cisco_acl.py` and the ACL cases
in `tests/unit/test_vendor_configs.py`. The shared configuration example is
`tests/config/cisco_acl_synthetic.cfg`. `.gitignore` explicitly allows these
synthetic test sources and this fixture while leaving the rest of the local test
corpus ignored.
