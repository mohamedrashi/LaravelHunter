from __future__ import annotations
from pathlib import Path
import yaml
from laravelhunter.models import Finding, ScanReport

SEVERITIES = {"info", "low", "medium", "high", "critical"}


def load_rules(path: Path) -> list[dict]:
    rules = []
    if not path.exists():
        return rules
    for file in sorted(path.glob("*.yml")) + sorted(path.glob("*.yaml")):
        data = yaml.safe_load(file.read_text(encoding="utf-8")) or {}
        if isinstance(data, dict):
            rules.append(data)
    return rules


def evaluate_rules(report: ScanReport, rules: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    for rule in rules:
        when = rule.get("when", {})
        matched = True
        evidence: list[str] = []

        if "laravel_detected" in when:
            expected = bool(when["laravel_detected"])
            condition = report.fingerprint.detected == expected
            matched &= condition
            if condition:
                evidence.append(f"Laravel detected={report.fingerprint.detected}")

        if "min_laravel_confidence" in when:
            threshold = int(when["min_laravel_confidence"])
            condition = report.fingerprint.confidence >= threshold
            matched &= condition
            if condition:
                evidence.append(f"Laravel confidence={report.fingerprint.confidence}%")

        if "edge_challenge" in when:
            expected = bool(when["edge_challenge"])
            condition = report.edge.challenge_detected == expected
            matched &= condition
            if condition:
                evidence.append(f"Edge challenge={report.edge.challenge_detected}")

        if "component" in when:
            component_name = str(when["component"]).lower()
            component = next((c for c in report.components if c.name.lower() == component_name), None)
            condition = bool(component and component.detected)
            matched &= condition
            if condition and component:
                evidence.append(f"{component.name} confidence={component.confidence}%")
                evidence.extend(e.detail for e in component.evidence[:3])

        if not matched:
            continue

        # Include the strongest framework evidence in Laravel-related findings.
        if when.get("laravel_detected") is True:
            evidence.extend(e.detail for e in sorted(report.fingerprint.evidence, key=lambda x: x.weight, reverse=True)[:5])

        # De-duplicate while preserving order.
        evidence = list(dict.fromkeys(evidence))

        severity = str(rule.get("severity", "info")).lower()
        if severity not in SEVERITIES:
            severity = "info"

        findings.append(Finding(
            rule_id=str(rule.get("id", "RULE-UNKNOWN")),
            title=str(rule.get("title", "Untitled rule")),
            severity=severity,
            status=str(rule.get("status", "observed")),
            confidence=min(int(rule.get("confidence", 70)), report.fingerprint.confidence if when.get("laravel_detected") is True else 100),
            description=str(rule.get("description", "")),
            evidence=evidence,
            recommendation=str(rule.get("recommendation", "Review manually.")),
            references=list(rule.get("references", [])),
        ))
    return findings
