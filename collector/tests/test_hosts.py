from scamallscope import hosts

import estate


def test_HST_1_index_keys():
    idx = hosts.build(estate.snapshot())
    for key in ("i-0web1", "prod-web-1", "ip-10-10-1-5"):
        assert idx["keys"][key] == {estate.iarn("i-0web1")}
    assert all(k == k.lower() for k in idx["keys"])


def test_HST_2_case_and_domain():
    idx = hosts.build(estate.snapshot())
    assert hosts.match(idx, "PROD-WEB-1") == estate.iarn("i-0web1")
    assert hosts.match(idx, "prod-web-1.example.internal") == estate.iarn("i-0web1")
    assert hosts.match(idx, "prod-app-1:9100") == estate.iarn("i-0app1")


def test_ambiguous_and_unknown_names_do_not_match():
    idx = hosts.build(estate.snapshot())
    assert hosts.match(idx, "twin") is None
    assert hosts.match(idx, "nobody") is None
    assert hosts.match(idx, None) is None


def test_host_tag_wins_over_nothing():
    snap = estate.snapshot()
    snap["resources"][2]["tags"]["scamallscope:host"] = "db-primary"
    assert hosts.match(hosts.build(snap), "db-primary") == estate.iarn("i-0db1")
