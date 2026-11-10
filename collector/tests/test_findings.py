from scamallscope import findings as F


def test_FND_1_severity_mapping():
    assert F.severity("Critical") == "critical"
    assert F.severity("High") == "high"
    assert F.severity("Informational") == "info"
    assert F.severity("Fatal") == "info"
    assert F.severity(None) == "info"


def test_FND_2_only_catalogue_best_practices_kept():
    assert F.known_bps(["SEC06-BP01", "XYZ", "SEC99-BP99", "SEC06-BP01"]) == ["SEC06-BP01"]


def test_FND_3_same_finding_same_id():
    a = F.make("x", "c", "t", "low", ["SEC06-BP01"], "arn:1", "n", "eu-west-1")
    b = F.make("x", "c", "t", "low", ["SEC06-BP01"], "arn:1", "n", "eu-west-1")
    assert a["id"] == b["id"] == "x:c:arn:1"
    assert a["pillar"] == "security"


def test_FND_4_catalogue_complete():
    bps = F.best_practices()
    assert len(bps) == 177
    for bp, info in bps.items():
        assert F.BP_PATTERN.match(bp)
        assert info["pillar"] in F.PILLARS and info["title"]
        assert info["url"].startswith("https://docs.aws.amazon.com/wellarchitected/")
    assert bps["SEC06-BP01"]["title"] == "Perform vulnerability management"


def test_pillar_from_best_practice_and_clip():
    assert F.pillar_of(["COST06-BP02"]) == "cost"
    assert F.pillar_of(["REL08-BP05"]) == "reliability"
    assert len(F.clip("x" * 500)) == 300
