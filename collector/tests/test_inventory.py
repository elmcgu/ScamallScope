import copy
import json
from datetime import datetime
from pathlib import Path

import pytest
import yaml

from scamallscope import inventory
from scamallscope.cli import main
from scamallscope.model import Resource, Snapshot, Unit

TEMPLATE = Path(__file__).resolve().parents[2] / "infra" / "inventory-table.yaml"
ACCT, REGION = "123456789012", "eu-west-1"
DAY1, DAY2, DAY3 = "2026-11-01T06:00:00+00:00", "2026-11-02T06:00:00+00:00", "2026-11-03T06:00:00+00:00"


@pytest.fixture
def table(session):
    """The table exactly as infra/inventory-table.yaml defines it, created in moto."""
    props = yaml.safe_load(TEMPLATE.read_text())["Resources"]["InventoryTable"]["Properties"]
    client = session.client("dynamodb", region_name=REGION)
    client.create_table(
        TableName="inv", BillingMode=props["BillingMode"], AttributeDefinitions=props["AttributeDefinitions"],
        KeySchema=props["KeySchema"], GlobalSecondaryIndexes=props["GlobalSecondaryIndexes"],
    )
    client.update_time_to_live(TableName="inv", TimeToLiveSpecification=props["TimeToLiveSpecification"])
    return session.resource("dynamodb", region_name=REGION).Table("inv")


def res(rid: str, type_: str = "instance", region: str = REGION, **config) -> Resource:
    return {"arn": f"arn:aws:ec2:{region}:{ACCT}:{type_}/{rid}", "account_id": ACCT, "region": region,
            "service": "ec2", "type": type_, "id": rid, "name": rid, "tags": {"Name": rid},
            "config": {"InstanceType": "t3.micro", **config}}


def unit(type_: str = "instance", region: str = REGION, status: str = "ok") -> Unit:
    return {"service": "ec2", "resource_type": type_, "region": region, "status": status,  # type: ignore[typeddict-item]
            "count": 0, "error": None if status == "ok" else "UnauthorizedOperation: denied"}


def snap(at: str, resources: list[Resource], units: list[Unit] | None = None, regions=(REGION,)) -> Snapshot:
    return {"schema_version": 1, "account_id": ACCT, "partition": "aws", "collected_at": at,
            "regions": list(regions), "units": units if units is not None else [unit()],
            "resources": resources, "links": []}


def current(table) -> dict:
    return inventory.load_current(table, ACCT, [REGION, "us-east-1"])


def test_template_matches_what_the_code_queries():
    props = yaml.safe_load(TEMPLATE.read_text())["Resources"]["InventoryTable"]["Properties"]
    assert [i["IndexName"] for i in props["GlobalSecondaryIndexes"]] == [inventory.INDEX_BY_ARN]
    assert props["TimeToLiveSpecification"] == {"AttributeName": "expires_at", "Enabled": True}
    assert props["PointInTimeRecoverySpecification"]["PointInTimeRecoveryEnabled"] is True
    assert props["DeletionProtectionEnabled"] is True


def test_first_run_creates_everything(table):
    run = inventory.apply(table, snap(DAY1, [res("i-1"), res("i-2")]))

    assert (run["created"], run["changed"], run["deleted"], run["unchanged"]) == (2, 0, 0, 0)
    assert set(current(table)) == {res("i-1")["arn"], res("i-2")["arn"]}
    events = inventory.changes_on(table, "2026-11-01")
    assert sorted(e["kind"] for e in events) == ["created", "created"]


def test_same_state_next_day_writes_no_changes(table):
    inventory.apply(table, snap(DAY1, [res("i-1")]))
    before = current(table)

    run = inventory.apply(table, snap(DAY2, [res("i-1")]))

    assert (run["created"], run["changed"], run["deleted"], run["unchanged"]) == (0, 0, 0, 1)
    assert inventory.changes_on(table, "2026-11-02") == []
    assert current(table) == before  # not even rewritten: last_changed is still day 1


def test_config_and_tag_changes_list_the_changed_fields(table):
    inventory.apply(table, snap(DAY1, [res("i-1")]))
    changed = res("i-1", InstanceType="t3.large")
    changed["tags"]["env"] = "prod"

    run = inventory.apply(table, snap(DAY2, [changed]))

    assert run["changed"] == 1
    [event] = inventory.changes_on(table, "2026-11-02")
    assert event["kind"] == "changed" and event["changed_fields"] == ["tags", "InstanceType"]
    item = current(table)[changed["arn"]]
    assert item["first_seen"] == DAY1 and item["last_changed"] == DAY2


def test_volatile_fields_and_list_order_are_not_changes(table):
    inventory.apply(table, snap(DAY1, [res("i-1", LaunchTime="2026-11-01T00:00:00", SecurityGroups=[{"GroupId": "a"}, {"GroupId": "b"}])]))

    run = inventory.apply(table, snap(DAY2, [res("i-1", LaunchTime="2026-11-02T09:00:00", SecurityGroups=[{"GroupId": "b"}, {"GroupId": "a"}])]))

    assert run["changed"] == 0


def test_missing_resource_is_deleted_when_its_unit_succeeded(table):
    inventory.apply(table, snap(DAY1, [res("i-1"), res("i-2")]))

    run = inventory.apply(table, snap(DAY2, [res("i-1")]))

    assert run["deleted"] == 1
    assert res("i-2")["arn"] not in current(table)
    [event] = inventory.changes_on(table, "2026-11-02")
    assert (event["kind"], event["arn"]) == ("deleted", res("i-2")["arn"])


def test_failed_unit_never_deletes(table):
    inventory.apply(table, snap(DAY1, [res("i-1"), res("vpc-1", "vpc")], [unit(), unit("vpc")]))

    run = inventory.apply(table, snap(DAY2, [res("vpc-1", "vpc")], [unit(status="error"), unit("vpc")]))

    assert run["deleted"] == 0
    assert res("i-1")["arn"] in current(table)


def test_region_not_collected_this_run_is_left_alone(table):
    east = res("i-9", region="us-east-1")
    inventory.apply(table, snap(DAY1, [res("i-1"), east], [unit(), unit(region="us-east-1")], regions=(REGION, "us-east-1")))

    run = inventory.apply(table, snap(DAY2, [res("i-1")], [unit()], regions=(REGION,)))

    assert run["deleted"] == 0
    assert east["arn"] in current(table)


def test_history_of_one_resource_oldest_first(table):
    inventory.apply(table, snap(DAY1, [res("i-1")]))
    inventory.apply(table, snap(DAY2, [res("i-1", InstanceType="t3.large")]))
    inventory.apply(table, snap(DAY3, []))

    events = inventory.history(table, res("i-1")["arn"])

    assert [(e["at"], e["kind"]) for e in events] == [(DAY1, "created"), (DAY2, "changed"), (DAY3, "deleted")]
    day1 = int(datetime.fromisoformat(DAY1).timestamp())
    assert events[0]["expires_at"] - day1 == inventory.CHANGE_TTL_DAYS * 86400


def test_running_the_same_snapshot_twice_is_safe(table):
    inventory.apply(table, snap(DAY1, [res("i-1")]))
    s2 = snap(DAY2, [res("i-1", InstanceType="t3.large")])

    inventory.apply(table, s2)
    again = inventory.apply(table, copy.deepcopy(s2))

    assert again["changed"] == 0
    assert len(inventory.changes_on(table, "2026-11-02")) == 1


def test_config_over_the_item_limit_is_flagged_and_still_tracked(table):
    big = res("i-1", UserData="x" * (inventory.MAX_CONFIG_BYTES + 1))
    inventory.apply(table, snap(DAY1, [big]))
    item = current(table)[big["arn"]]
    assert item.get("config_truncated") is True and "config_json" not in item

    bigger = res("i-1", UserData="y" * (inventory.MAX_CONFIG_BYTES + 1))
    run = inventory.apply(table, snap(DAY2, [bigger]))

    assert run["changed"] == 1
    assert inventory.changes_on(table, "2026-11-02")[0]["changed_fields"] == ["config"]


def test_cli_inventory_changes_and_history(table, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("scamallscope.cli._table", lambda args: table)
    f = tmp_path / "s.snapshot.json"
    f.write_text(json.dumps(snap(DAY1, [res("i-1")])))

    assert main(["inventory", str(f), "--table", "inv"]) == 0
    assert "1 created, 0 changed, 0 deleted" in capsys.readouterr().out

    assert main(["changes", "--table", "inv", "--date", "2026-11-01"]) == 0
    assert "created" in capsys.readouterr().out

    assert main(["history", "--table", "inv", "--arn", res("i-1")["arn"]]) == 0
    assert res("i-1")["arn"] in capsys.readouterr().out

    f.write_text(json.dumps(snap(DAY2, [], [unit(status="error")])))
    assert main(["inventory", str(f), "--table", "inv"]) == 2  # partial snapshot


def test_hash_ignores_fields_that_move_without_a_change():
    def db(restorable, last_used, backup):
        return {"name": "db", "tags": {}, "config": {
            "MultiAZ": True, "LatestRestorableTime": restorable, "RoleLastUsed": {"LastUsedDate": last_used},
            "Resources": [{"ResourceArn": "arn:x", "LastBackupTime": backup}],
            "Rows": [{"user": "a", "access_key_1_last_used_date": last_used, "access_key_2_last_used_date": "N/A"}]}}
    one = db("2026-11-10T10:00:00+00:00", "2026-11-10T09:00:00+00:00", "2026-11-10T01:00:00+00:00")
    two = db("2026-11-11T10:05:00+00:00", "2026-11-11T08:00:00+00:00", "2026-11-11T01:00:00+00:00")
    assert inventory.resource_hash(one) == inventory.resource_hash(two)  # type: ignore[arg-type]
    two["config"]["MultiAZ"] = False
    assert inventory.resource_hash(one) != inventory.resource_hash(two)  # type: ignore[arg-type]
