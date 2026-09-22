"""SARIF 导出：转换器单元测试 + 接口端到端测试。"""
import os
import tempfile

import pytest

# 在导入应用前指定临时数据库
_tmp = tempfile.mkdtemp()
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp}/test.db"

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.sarif import issue_fingerprint, report_to_sarif  # noqa: E402


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def _issue(direction="backward", path="#/properties/a", code="type_removed",
           severity="error", message="msg"):
    return {
        "direction": direction,
        "path": path,
        "code": code,
        "severity": severity,
        "message": message,
        "reason": "reason",
        "counterexample": None,
        "counterexample_path": None,
    }


# ---------------------------------------------------------------------------
# report_to_sarif 单元测试
# ---------------------------------------------------------------------------

def test_sarif_skeleton():
    log = report_to_sarif({"issues": []})
    assert log["version"] == "2.1.0"
    assert log["$schema"].endswith("sarif-2.1.0.json")
    run = log["runs"][0]
    assert run["tool"]["driver"]["rules"] == []
    assert run["results"] == []


def test_rules_deduplicated_by_code_and_sorted():
    report = {"issues": [
        _issue(code="required_added", path="#"),
        _issue(code="enum_added", path="#/properties/a"),
        _issue(code="required_added", path="#/properties/b"),
    ]}
    run = report_to_sarif(report)["runs"][0]
    assert [r["id"] for r in run["tool"]["driver"]["rules"]] == [
        "enum_added", "required_added",
    ]
    # 重复 issue 不去重，分别保留
    assert len(run["results"]) == 3
    # ruleIndex 与去重排序后的 rules 对应
    rules = run["tool"]["driver"]["rules"]
    for result in run["results"]:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]


def test_severity_maps_to_level_and_direction_to_properties():
    report = {"issues": [
        _issue(severity="error"),
        _issue(severity="warning", path="#/properties/b"),
    ]}
    results = report_to_sarif(report)["runs"][0]["results"]
    assert results[0]["level"] == "error"
    assert results[0]["properties"]["direction"] == "backward"
    assert results[1]["level"] == "warning"
    assert results[1]["properties"]["direction"] == "backward"


def test_unknown_severity_degrades_to_note():
    report = {"issues": [_issue(severity="info")]}
    result = report_to_sarif(report)["runs"][0]["results"][0]
    assert result["level"] == "note"


def test_schema_path_becomes_logical_location():
    report = {"issues": [_issue(path="#/properties/addresses/items")]}
    result = report_to_sarif(report)["runs"][0]["results"][0]
    logical = result["locations"][0]["logicalLocations"][0]
    assert logical["fullyQualifiedName"] == "#/properties/addresses/items"


def test_fingerprint_stable_against_message_changes():
    base = _issue(message="第一版文案", )
    changed_message = {**base, "message": "完全不同的文案"}
    changed_reason = {**base, "reason": "原因文案也变了"}
    assert issue_fingerprint(base) == issue_fingerprint(changed_message)
    assert issue_fingerprint(base) == issue_fingerprint(changed_reason)
    # 但业务关键字段变化会改变指纹
    assert issue_fingerprint(base) != issue_fingerprint({**base, "path": "#/other"})
    assert issue_fingerprint(base) != issue_fingerprint({**base, "code": "other_code"})
    assert issue_fingerprint(base) != issue_fingerprint({**base, "direction": "forward"})


def test_results_sorted_by_stable_key():
    report = {"issues": [
        _issue(direction="forward", path="#/a", code="x"),
        _issue(direction="backward", path="#/b", code="x"),
        _issue(direction="backward", path="#/a", code="y"),
        _issue(direction="backward", path="#/a", code="x"),
    ]}
    results = report_to_sarif(report)["runs"][0]["results"]
    keys = [
        (r["properties"]["direction"],
         r["locations"][0]["logicalLocations"][0]["fullyQualifiedName"],
         r["ruleId"])
        for r in results
    ]
    assert keys == [
        ("backward", "#/a", "x"),
        ("backward", "#/a", "y"),
        ("backward", "#/b", "x"),
        ("forward", "#/a", "x"),
    ]


def test_duplicate_issues_preserved_as_separate_results():
    report = {"issues": [_issue(), _issue()]}
    results = report_to_sarif(report)["runs"][0]["results"]
    assert len(results) == 2
    # 重复 issue 指纹相同是允许的（partial fingerprint），但结果必须分别保留
    assert results[0]["partialFingerprints"] == results[1]["partialFingerprints"]


def test_run_properties_carry_analysis_identity():
    log = report_to_sarif({"issues": []}, analysis_id=7, analysis_name="v1->v2")
    assert log["runs"][0]["properties"] == {"analysisId": 7, "analysisName": "v1->v2"}
    # 不传元数据时不产生 properties
    assert "properties" not in report_to_sarif({"issues": []})["runs"][0]


# ---------------------------------------------------------------------------
# GET /api/analyses/{id}/sarif 接口测试
# ---------------------------------------------------------------------------

SARIF_OLD = {
    "type": "object",
    "properties": {
        "status": {"type": "string", "enum": ["active", "disabled", "pending"]},
    },
}
SARIF_NEW = {
    "type": "object",
    "properties": {
        "status": {"type": "string", "enum": ["active", "disabled"]},
        "owner": {"type": "string"},
    },
    "required": ["status", "owner"],
}


def _create_analysis(client):
    resp = client.post("/api/analyses", json={
        "name": "sarif-case", "old_schema": SARIF_OLD, "new_schema": SARIF_NEW,
    })
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_sarif_endpoint_returns_sarif_media_type(client):
    analysis = _create_analysis(client)
    resp = client.get(f"/api/analyses/{analysis['id']}/sarif")
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"].startswith("application/sarif+json")

    log = resp.json()
    assert log["version"] == "2.1.0"
    run = log["runs"][0]

    issues = analysis["report"]["issues"]
    assert len(run["results"]) == len(issues)

    # rules 按 code 去重，result 的 ruleId 都能在其中找到
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert len(rule_ids) == len(set(rule_ids))
    assert set(rule_ids) == {i["code"] for i in issues}

    # 每条 result 与原始 issue 一一对应（按稳定键排序后）
    expected = sorted(issues, key=lambda i: (i["direction"], i["path"], i["code"]))
    for result, issue in zip(run["results"], expected):
        assert result["ruleId"] == issue["code"]
        assert result["level"] == {"error": "error", "warning": "warning"}[issue["severity"]]
        assert result["message"]["text"] == issue["message"]
        assert result["properties"]["direction"] == issue["direction"]
        logical = result["locations"][0]["logicalLocations"][0]
        assert logical["fullyQualifiedName"] == issue["path"]
        assert len(result["partialFingerprints"]["issueFingerprint/v1"]) == 16

    # run 元数据携带分析标识
    assert run["properties"]["analysisId"] == analysis["id"]
    assert run["properties"]["analysisName"] == "sarif-case"


def test_sarif_missing_analysis_returns_404(client):
    resp = client.get("/api/analyses/999999/sarif")
    assert resp.status_code == 404
    assert resp.json()["detail"] == "分析记录不存在"


def test_sarif_export_does_not_modify_report(client):
    analysis = _create_analysis(client)
    resp = client.get(f"/api/analyses/{analysis['id']}/sarif")
    assert resp.status_code == 200

    after = client.get(f"/api/analyses/{analysis['id']}").json()
    assert after["report"] == analysis["report"]
    assert after["old_schema"] == analysis["old_schema"]
    assert after["new_schema"] == analysis["new_schema"]
