from scamallscope import findings as F
from scamallscope.posture import scorecard


def bp(card, pillar, bp_id):
    return next(r for r in card[pillar]["best_practices"] if r["id"] == bp_id)


def test_POS_1_finding_marks_issues():
    f = F.make("wazuh", "c", "t", "high", ["SEC06-BP01"], None, "n", "r")
    card = scorecard([f], {})
    assert bp(card, "security", "SEC06-BP01")["status"] == "issues"
    assert bp(card, "security", "SEC06-BP01")["findings"] == 1


def test_POS_2_coverage_without_findings_is_clear():
    card = scorecard([], {"prowler": {"SEC01-BP02": {"passed": 1, "failed": 0}}})
    row = bp(card, "security", "SEC01-BP02")
    assert row["status"] == "clear" and row["checked_by"] == ["prowler"]


def test_POS_3_nothing_loaded_is_not_checked():
    card = scorecard([], {})
    for pillar in F.PILLARS:
        s = card[pillar]["summary"]
        assert s["issues"] == 0 and s["clear"] == 0 and s["not_checked"] > 0


def test_POS_4_issues_beat_clear():
    f = F.make("prowler", "c", "t", "low", ["SEC01-BP02"], None, "n", "r")
    card = scorecard([f], {"prowler": {"SEC01-BP02": {"passed": 3, "failed": 1}}})
    assert bp(card, "security", "SEC01-BP02")["status"] == "issues"


def test_POS_5_summary_adds_up():
    card = scorecard([], {"hygiene": {"COST03-BP02": {"passed": 1, "failed": 0}}})
    for pillar in F.PILLARS:
        s = card[pillar]["summary"]
        assert sum(s.values()) == len(card[pillar]["best_practices"])
    assert sum(len(card[p]["best_practices"]) for p in F.PILLARS) == 177
