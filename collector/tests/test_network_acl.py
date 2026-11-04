"""Pure tests of network ACL rule order, ranges and protocols (no AWS)."""

from scamallscope import network_acl as nacl


def acl(*entries):
    return {"Entries": [{"Egress": False, "CidrBlock": "0.0.0.0/0", **e} for e in entries]}


def test_first_matching_rule_wins_by_rule_number_not_list_order():
    a = acl({"RuleNumber": 200, "Protocol": "-1", "RuleAction": "allow"},
            {"RuleNumber": 100, "Protocol": "6", "RuleAction": "deny", "PortRange": {"From": 22, "To": 22}})

    assert nacl.allowed(a, "6", (22, 22), "ipv4") == []
    assert nacl.allowed(a, "6", (20, 25), "ipv4") == [(20, 21), (23, 25)]


def test_adjacent_allowed_parts_are_merged():
    a = acl({"RuleNumber": 1, "Protocol": "6", "RuleAction": "allow", "PortRange": {"From": 0, "To": 99}},
            {"RuleNumber": 2, "Protocol": "6", "RuleAction": "allow", "PortRange": {"From": 100, "To": 200}})

    assert nacl.allowed(a, "6", (50, 150), "ipv4") == [(50, 150)]


def test_rule_for_another_protocol_does_not_match():
    a = acl({"RuleNumber": 1, "Protocol": "17", "RuleAction": "allow", "PortRange": {"From": 53, "To": 53}})

    assert nacl.allowed(a, "6", (53, 53), "ipv4") == []


def test_outbound_rules_are_ignored():
    a = {"Entries": [{"RuleNumber": 1, "Egress": True, "Protocol": "-1", "RuleAction": "allow",
                      "CidrBlock": "0.0.0.0/0"}]}

    assert nacl.allowed(a, "6", (22, 22), "ipv4") == []


def test_ipv6_uses_ipv6_rules_only():
    a = {"Entries": [{"RuleNumber": 1, "Egress": False, "Protocol": "-1", "RuleAction": "allow",
                      "CidrBlock": "0.0.0.0/0"}]}

    assert nacl.allowed(a, "6", (22, 22), "ipv6") == []
    a["Entries"][0] |= {"Ipv6CidrBlock": "::/0"}
    del a["Entries"][0]["CidrBlock"]
    assert nacl.allowed(a, "6", (22, 22), "ipv6") == [(22, 22)]


def test_icmp_is_allowed_or_not_as_a_whole():
    a = acl({"RuleNumber": 1, "Protocol": "1", "RuleAction": "allow"})

    assert nacl.allowed(a, "1", None, "ipv4") == [None]
    assert nacl.allowed(acl(), "1", None, "ipv4") == []


def test_protocol_names_and_numbers():
    assert nacl.protocol_number("tcp") == "6"
    assert nacl.protocol_number("-1") == "-1"
    assert nacl.protocol_number(50) == "50"
    assert nacl.protocol_name("17") == "udp"
