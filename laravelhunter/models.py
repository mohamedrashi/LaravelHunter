from __future__ import annotations
from typing import Any, Literal
from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high", "critical"]
AdvisoryStatus = Literal["affected-version", "not-affected-version", "not-evaluated"]
RuntimePrerequisiteStatus = Literal["observed", "partial", "not-observed", "not-tested"]


class Evidence(BaseModel):
    source: str
    detail: str
    weight: int = 0


class FingerprintResult(BaseModel):
    detected: bool
    confidence: int = Field(ge=0, le=100)
    version: str | None = None
    evidence: list[Evidence] = []


class VersionResult(BaseModel):
    version: str | None = None
    exact: bool = False
    confidence: int = Field(default=0, ge=0, le=100)
    source: str = "unresolved"
    constraints: list[str] = []
    candidate_majors: list[int] = []
    evidence: list[Evidence] = []


class ComponentResult(BaseModel):
    name: str
    detected: bool
    confidence: int = Field(ge=0, le=100)
    version_hint: str | None = None
    evidence: list[Evidence] = []


class EdgeResult(BaseModel):
    cloudflare: bool = False
    waf_detected: bool = False
    rate_limited: bool = False
    challenge_detected: bool = False
    provider: str | None = None
    confidence: int = Field(default=0, ge=0, le=100)
    protected_response: bool = False
    recommended_policy: str = "normal"
    evidence: list[Evidence] = []


class Finding(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    status: str
    confidence: int = Field(ge=0, le=100)
    description: str
    evidence: list[str] = []
    recommendation: str
    references: list[str] = []


class RuntimePrerequisiteResult(BaseModel):
    advisory_id: str
    status: RuntimePrerequisiteStatus
    confidence: int = Field(ge=0, le=100)
    summary: str
    evidence: list[Evidence] = []


class AdvisoryAssessment(BaseModel):
    advisory_id: str
    cve: str | None = None
    title: str
    severity: Severity
    package: str = "laravel/framework"
    status: AdvisoryStatus
    confidence: int = Field(ge=0, le=100)
    reason: str
    affected_ranges: list[str] = []
    patched_versions: list[str] = []
    prerequisites: list[str] = []
    references: list[str] = []
    runtime_status: RuntimePrerequisiteStatus = "not-tested"
    runtime_confidence: int = Field(default=0, ge=0, le=100)
    runtime_summary: str = "Runtime prerequisites were not tested."
    runtime_evidence: list[str] = []


class RouteSurface(BaseModel):
    url: str
    path: str
    kind: str = "page"
    source: str = "discovery"
    status_code: int | None = None
    fetched: bool = False
    evidence: list[Evidence] = []


class FeatureSurface(BaseModel):
    name: str
    observed: bool = True
    confidence: int = Field(ge=0, le=100)
    evidence: list[Evidence] = []


class FilamentPageSurface(BaseModel):
    url: str
    path: str
    status_code: int
    access_state: str = "unknown"
    review_priority: str = "normal"
    priority_reasons: list[str] = []
    component_names: list[str] = []
    resource_hints: list[str] = []
    resource_classes: list[str] = []
    page_classes: list[str] = []
    page_types: list[str] = []
    actions: list[str] = []
    page_actions: list[str] = []
    table_actions: list[str] = []
    bulk_actions: list[str] = []
    submit_actions: list[str] = []
    ui_state_actions: list[str] = []
    fields: list[str] = []
    form_fields: list[str] = []
    table_state_fields: list[str] = []
    authorization_surfaces: list[str] = []
    forms: list[str] = []
    evidence: list[Evidence] = []


class AuthorizationRoleSummary(BaseModel):
    label: str
    auth_state: str = "unknown"
    final_url: str
    reachable_pages: int = 0
    denied_pages: int = 0
    filament_pages: int = 0
    application_actions: int = 0
    authorization_surfaces: int = 0


class AuthorizationMatrixRow(BaseModel):
    path: str
    priority: str = "normal"
    resource: str | None = None
    page_identity: str | None = None
    a_status: int | None = None
    a_access: str = "not-observed"
    b_status: int | None = None
    b_access: str = "not-observed"
    a_actions: list[str] = []
    b_actions: list[str] = []
    only_a_actions: list[str] = []
    only_b_actions: list[str] = []
    a_authz_surfaces: list[str] = []
    b_authz_surfaces: list[str] = []
    only_a_authz_surfaces: list[str] = []
    only_b_authz_surfaces: list[str] = []
    access_diff: bool = False
    action_diff: bool = False
    authz_diff: bool = False
    notes: list[str] = []


class AuthorizationMatrixReport(BaseModel):
    target: str
    mode: str = "safe-active-read-only"
    role_a: AuthorizationRoleSummary
    role_b: AuthorizationRoleSummary
    rows: list[AuthorizationMatrixRow] = []
    metadata: dict[str, Any] = {}


class HttpSnapshot(BaseModel):
    url: str
    status_code: int
    headers: dict[str, str]
    cookies: dict[str, str]
    body_sample: str
    elapsed_ms: int


class ScanReport(BaseModel):
    target: str
    final_url: str
    fingerprint: FingerprintResult
    framework_version: VersionResult = VersionResult()
    components: list[ComponentResult]
    edge: EdgeResult
    findings: list[Finding]
    advisories: list[AdvisoryAssessment] = []
    runtime_prerequisites: list[RuntimePrerequisiteResult] = []
    routes: list[RouteSurface] = []
    features: list[FeatureSurface] = []
    filament_pages: list[FilamentPageSurface] = []
    snapshots: list[HttpSnapshot]
    metadata: dict[str, Any] = {}
