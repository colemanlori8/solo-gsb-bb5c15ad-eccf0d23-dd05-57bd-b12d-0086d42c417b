"""SARIF 2.1.0 导出。

把已落库的分析报告转换为 SARIF（Static Analysis Results Interchange
Format）日志，便于接入 GitHub code scanning、Azure DevOps 等支持
SARIF 的代码扫描平台。

映射规则
========
* 每条 issue 转换为一个 result；重复 issue 不去重，分别保留；
* issue.code 生成去重后的 rule（按 id 排序），result 通过 ruleId /
  ruleIndex 关联；
* issue.direction 写入 result.properties.direction；
* issue.severity 映射为 SARIF level（error -> error、warning -> warning，
  未知级别降级为 note）；
* issue.path（schema 路径）写入 result.locations[0].logicalLocations[0]；
* partialFingerprint 由 direction + path + code 生成（SHA-256 前 16 个
  十六进制字符），不包含 message / reason —— 文案调整不影响指纹，
  同一业务问题在不同版本间可稳定追踪；
* results 按稳定键 (direction, path, code) 排序（稳定排序，重复 issue
  的相对顺序保持与报告一致），保证输出内容确定。

整个转换过程只读报告，不修改原报告。
"""
from __future__ import annotations

import hashlib
from typing import Any

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

TOOL_NAME = "json-schema-compat"
TOOL_VERSION = "1.0.0"

_FINGERPRINT_LEN = 16
_FIELD_SEP = "\x1f"

# severity -> SARIF level（未识别的级别按 note 处理）
_LEVEL_BY_SEVERITY = {
    "error": "error",
    "warning": "warning",
}


def issue_fingerprint(issue: dict) -> str:
    """生成稳定的 partialFingerprint（direction + path + code）。

    不包含 message / reason：引擎文案调整不会改变指纹，同一业务问题
    在报告版本演进中可被稳定追踪。
    """
    key = _FIELD_SEP.join([
        str(issue.get("direction", "")),
        str(issue.get("path", "")),
        str(issue.get("code", "")),
    ])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:_FINGERPRINT_LEN]


def _rule_name(code: str) -> str:
    """把 snake_case 的 issue code 转成 SARIF 惯例的 PascalCase rule name。"""
    return "".join(part.capitalize() for part in code.split("_") if part)


def _sort_key(issue: dict) -> tuple:
    return (
        str(issue.get("direction") or ""),
        str(issue.get("path") or ""),
        str(issue.get("code") or ""),
    )


def _result_for(issue: dict, rule_index: dict[str, int]) -> dict:
    code = str(issue.get("code", ""))
    severity = str(issue.get("severity", ""))
    path = str(issue.get("path", ""))
    return {
        "ruleId": code,
        "ruleIndex": rule_index[code],
        "level": _LEVEL_BY_SEVERITY.get(severity, "note"),
        "message": {"text": str(issue.get("message", ""))},
        "locations": [
            {
                "logicalLocations": [
                    {
                        "name": path,
                        "fullyQualifiedName": path,
                        "kind": "schema",
                    }
                ]
            }
        ],
        "partialFingerprints": {
            "issueFingerprint/v1": issue_fingerprint(issue),
        },
        "properties": {
            "direction": issue.get("direction"),
        },
    }


def report_to_sarif(report: dict, analysis_id: Any = None,
                    analysis_name: Any = None) -> dict:
    """把分析报告转换为 SARIF 2.1.0 日志（纯函数，不修改入参）。"""
    issues = sorted(report.get("issues", []) or [], key=_sort_key)

    # 按 code 去重生成 rules；按 id 排序使 ruleIndex 稳定
    codes = sorted({str(issue.get("code", "")) for issue in issues})
    rule_index = {code: i for i, code in enumerate(codes)}
    rules = [
        {
            "id": code,
            "name": _rule_name(code),
            "shortDescription": {"text": f"JSON Schema 兼容性检查：{code}"},
        }
        for code in codes
    ]

    results = [_result_for(issue, rule_index) for issue in issues]

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "version": TOOL_VERSION,
                "rules": rules,
            }
        },
        "results": results,
    }
    run_properties = {
        key: value
        for key, value in (("analysisId", analysis_id),
                           ("analysisName", analysis_name))
        if value is not None
    }
    if run_properties:
        run["properties"] = run_properties

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }
