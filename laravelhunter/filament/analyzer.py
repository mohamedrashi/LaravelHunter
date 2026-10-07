from __future__ import annotations

import html
import re
from collections import defaultdict
from urllib.parse import urlparse

from laravelhunter.models import Evidence, FilamentPageSurface, HttpSnapshot

# Review priority is a triage hint only. It is never a vulnerability severity.
HIGH_INTEREST_TERMS = {
    "token": "token/credential management surface",
    "secret": "secret-management surface",
    "credential": "credential-management surface",
    "session": "session-management surface",
    "role": "role/authorization administration surface",
    "permission": "permission administration surface",
    "users": "user administration surface",
    "userresource": "user administration resource",
    "impersonat": "impersonation-related surface",
}
MEDIUM_INTEREST_TERMS = {
    "audit": "audit trail surface",
    "logs": "application log surface",
    "export": "data export surface",
    "import": "data import surface",
    "bulk": "bulk-operation surface",
    "notice": "administrative notification surface",
    "classification": "classification/metadata administration surface",
    "data-quality": "data-quality administration surface",
    "compliance": "compliance/reporting surface",
}

GENERIC_ACTION_METHODS = {
    "$refresh", "$commit", "refresh", "dispatch", "js",
    "mountaction", "callmountedaction", "replacemountedaction",
    "mounttableaction", "callmountedtableaction",
    "mounttablebulkaction", "callmountedtablebulkaction",
    "selectalltablerecords", "deselectalltablerecords",
    "toggletablereordering", "reordertable", "sorttable",
    "loadtable", "resettablesearch", "resettablefiltersform",
    "resetpage", "gotopage", "nextpage", "previouspage",
    "updatetablecolumnstate", "togglecolumn",
}

# UI/state methods are useful inventory signals but are not application actions.
# Keep them in a separate bucket so they do not inflate authorization review.
UI_STATE_ACTIONS = {
    "applytablefilters",
    "resettablecolumnmanager",
    "resettablefilters",
    "resettablesearch",
    "createanother",
    "reorder",
    "clone",
}
UI_STATE_ACTION_PATTERNS = (
    re.compile(r"^set[A-Za-z0-9_]*ChipFilter$", re.I),
    re.compile(r"^select(?:AllMatching|Visible)[A-Za-z0-9_]*$", re.I),
    re.compile(r"^clearCreateGroupAccounts$", re.I),
    re.compile(r"^resetTable[A-Za-z0-9_]*$", re.I),
)

INTERNAL_FIELD_PREFIXES = (
    "mountedActions.", "mountedTableActions.", "defaultAction",
    "defaultTableAction", "componentFileAttachments", "discoveredSchemaNames",
    "toggledTableColumns", "tableGrouping", "tableReordering",
)
INTERNAL_FIELDS = {
    "isTableLoaded", "areSchemaStateUpdateHooksDisabledForTesting",
    "defaultActionContext", "defaultActionArguments", "defaultTableActionArguments",
    "defaultTableActionRecord",
}

AUTHZ_ACTION_TERMS = {
    "create", "edit", "update", "delete", "forcedelete", "restore", "view",
    "attach", "detach", "associate", "dissociate", "replicate", "impersonate",
    "export", "import", "approve", "reject", "revoke", "rotate", "reset",
}


def _unique(values: list[str], limit: int = 80) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        value = html.unescape(value).strip()
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
        if len(out) >= limit:
            break
    return out


def _canonical_path(url: str) -> str:
    path = urlparse(url).path or "/"
    if path != "/":
        path = path.rstrip("/") or "/"
    return path


def _extract_component_names(body: str) -> list[str]:
    names = re.findall(r'wire:name=["\']([^"\']+)["\']', body, re.I)
    names += re.findall(r'&quot;name&quot;:&quot;([^&]+?)&quot;', body, re.I)
    return _unique([n.replace("\\\\", "\\") for n in names], 60)


def _component_identity(component_names: list[str]) -> tuple[list[str], list[str], list[str]]:
    resources: list[str] = []
    pages: list[str] = []
    types: list[str] = []
    for name in component_names:
        m = re.search(r'\\Resources\\([^\\]+?Resource)(?:\\|$)', name)
        if m:
            resources.append(m.group(1))
        m = re.search(r'\\Pages\\([^\\]+)$', name)
        if m:
            page = m.group(1)
            pages.append(page)
            low = page.lower()
            if low.startswith("list"):
                types.append("list")
            elif low.startswith("create"):
                types.append("create")
            elif low.startswith("edit"):
                types.append("edit")
            elif low.startswith("view"):
                types.append("view")
            elif low.startswith("manage"):
                types.append("manage")
            else:
                types.append("custom")
    return _unique(resources, 30), _unique(pages, 40), _unique(types, 10)


def _is_internal_field(value: str) -> bool:
    if value in INTERNAL_FIELDS:
        return True
    return any(value.startswith(prefix) for prefix in INTERNAL_FIELD_PREFIXES)


def _normalize_field(value: str) -> str | None:
    value = html.unescape(value).strip()
    if value.startswith("data."):
        value = value[5:]
    if not value or _is_internal_field(value):
        return None
    return value


def _extract_field_groups(body: str) -> tuple[list[str], list[str], list[str]]:
    all_fields: list[str] = []
    form_fields: list[str] = []
    table_state: list[str] = []

    for raw in re.findall(r'wire:model(?:\.[\w.-]+)?=["\']([^"\']+)["\']', body, re.I):
        value = _normalize_field(raw)
        if not value:
            continue
        all_fields.append(value)
        low = value.lower()
        if low.startswith("table") or low.startswith("selectedtablerecords"):
            table_state.append(value)
        else:
            form_fields.append(value)

    for regex in (
        r'<(?:input|select|textarea)\b[^>]*\bname=["\']([^"\']+)["\']',
        r'<(?:input|select|textarea)\b[^>]*\bid=["\'](form\.[^"\']+)["\']',
    ):
        for raw in re.findall(regex, body, re.I):
            value = _normalize_field(raw)
            if not value:
                continue
            if value.startswith("form."):
                value = value[5:]
            all_fields.append(value)
            form_fields.append(value)

    return _unique(all_fields, 140), _unique(form_fields, 120), _unique(table_state, 60)


def _simple_action_name(raw: str) -> str | None:
    value = html.unescape(raw).strip()
    if not value or len(value) > 160:
        return None
    lower = value.lower()
    if any(token in lower for token in (
        "mountaction(", "callmountedaction(", "mounttableaction(",
        "callmountedtableaction(", "mounttablebulkaction(",
        "callmountedtablebulkaction(",
    )):
        return None
    match = re.match(r'^\s*(?:\$wire\.)?([A-Za-z_][\w]*)\s*(?:\(|$)', value)
    if not match:
        return None
    name = match.group(1)
    if name.lower() in GENERIC_ACTION_METHODS:
        return None
    return name


def _is_ui_state_action(name: str) -> bool:
    low = name.lower()
    if low in UI_STATE_ACTIONS:
        return True
    return any(pattern.match(name) for pattern in UI_STATE_ACTION_PATTERNS)


def _extract_action_groups(body: str) -> tuple[list[str], list[str], list[str], list[str], list[str], list[str]]:
    page_actions: list[str] = []
    table_actions: list[str] = []
    bulk_actions: list[str] = []
    submit_actions: list[str] = []
    ui_state_actions: list[str] = []

    # Direct Livewire methods can be application actions or page/table UI state.
    # Separate the latter so they do not inflate authorization-review counts.
    for raw in re.findall(r'wire:submit(?:\.[\w.-]+)?=["\']([^"\']+)["\']', body, re.I):
        name = _simple_action_name(raw)
        if name:
            if _is_ui_state_action(name):
                ui_state_actions.append(name)
            else:
                submit_actions.append(name)
    for raw in re.findall(r'wire:click(?:\.[\w.-]+)?=["\']([^"\']+)["\']', body, re.I):
        name = _simple_action_name(raw)
        if name:
            if _is_ui_state_action(name):
                ui_state_actions.append(name)
            else:
                page_actions.append(name)

    # Filament wrappers preserve action context and are kept as application actions.
    page_actions += re.findall(r'\b(?:mountAction|callMountedAction)\(\s*["\']([^"\']+)["\']', body, re.I)
    table_actions += re.findall(r'\b(?:mountTableAction|callMountedTableAction)\(\s*["\']([^"\']+)["\']', body, re.I)
    bulk_actions += re.findall(r'\b(?:mountTableBulkAction|callMountedTableBulkAction)\(\s*["\']([^"\']+)["\']', body, re.I)

    def clean(items: list[str]) -> list[str]:
        return _unique([x for x in items if x and x.lower() not in GENERIC_ACTION_METHODS], 80)

    page_actions = clean(page_actions)
    table_actions = clean(table_actions)
    bulk_actions = clean(bulk_actions)
    submit_actions = clean(submit_actions)
    ui_state_actions = clean(ui_state_actions)
    all_actions = _unique([*page_actions, *table_actions, *bulk_actions, *submit_actions], 120)
    return all_actions, page_actions, table_actions, bulk_actions, submit_actions, ui_state_actions


def _extract_forms(body: str) -> list[str]:
    forms: list[str] = []
    forms += re.findall(r'<form\b[^>]*\bid=["\']([^"\']+)["\']', body, re.I)
    for raw in re.findall(r'<form\b[^>]*\bwire:submit(?:\.[\w.-]+)?=["\']([^"\']+)["\']', body, re.I):
        name = _simple_action_name(raw)
        if name:
            forms.append(name)
    return _unique(forms, 40)


def _review_priority(path: str, resource_hints: list[str]) -> tuple[str, list[str]]:
    haystack = " ".join([path, *resource_hints]).lower()
    reasons: list[str] = []
    for term, reason in HIGH_INTEREST_TERMS.items():
        if term in haystack:
            reasons.append(reason)
    if reasons:
        return "high", _unique(reasons, 8)
    for term, reason in MEDIUM_INTEREST_TERMS.items():
        if term in haystack:
            reasons.append(reason)
    if reasons:
        return "medium", _unique(reasons, 8)
    return "normal", []


def _access_state(status_code: int) -> str:
    if 200 <= status_code < 300:
        return "reachable"
    if status_code in {401, 403}:
        return "denied"
    if 300 <= status_code < 400:
        return "redirect"
    if status_code == 404:
        return "not-found"
    return "other"


def _authorization_surfaces(path: str, page_types: list[str], page_actions: list[str], table_actions: list[str], bulk_actions: list[str], submit_actions: list[str]) -> list[str]:
    surfaces: list[str] = []
    for kind, actions in (
        ("page-action", page_actions),
        ("table-record-action", table_actions),
        ("bulk-action", bulk_actions),
        ("form-submit", submit_actions),
    ):
        for action in actions:
            low = action.lower()
            if any(term in low for term in AUTHZ_ACTION_TERMS):
                surfaces.append(f"{kind}:{action}")
    # Numeric record/detail paths are useful authorization review surfaces but are
    # not vulnerabilities on their own.
    if re.search(r'/\d+(?:/|$)', path):
        surfaces.append("record-identifier:path")
    if any(t in {"create", "edit", "view", "manage"} for t in page_types):
        surfaces.append("resource-page:" + ",".join(page_types))
    return _unique(surfaces, 60)


def analyze_filament_pages(snapshots: list[HttpSnapshot]) -> list[FilamentPageSurface]:
    """Build a passive Filament resource/action inventory from already-fetched HTML.

    No requests are generated here and no action/form is executed. Query-string
    variants are merged by canonical path.
    """
    grouped: dict[tuple[str, str, str], list[HttpSnapshot]] = defaultdict(list)
    for snap in snapshots:
        parsed = urlparse(snap.url)
        key = (parsed.scheme.lower(), parsed.netloc.lower(), _canonical_path(snap.url))
        grouped[key].append(snap)

    results: list[FilamentPageSurface] = []
    for (_scheme, _host, path), group in grouped.items():
        component_names: list[str] = []
        fields: list[str] = []
        form_fields: list[str] = []
        table_state_fields: list[str] = []
        actions: list[str] = []
        page_actions: list[str] = []
        table_actions: list[str] = []
        bulk_actions: list[str] = []
        submit_actions: list[str] = []
        ui_state_actions: list[str] = []
        forms: list[str] = []
        filament_seen = False

        representative = next((s for s in group if 200 <= s.status_code < 300), group[0])

        for snap in group:
            body = snap.body_sample
            names = _extract_component_names(body)
            if "filament" in body.lower() or any("filament" in n.lower() for n in names):
                filament_seen = True
            component_names.extend(names)
            all_f, form_f, table_f = _extract_field_groups(body)
            fields.extend(all_f)
            form_fields.extend(form_f)
            table_state_fields.extend(table_f)
            all_a, page_a, table_a, bulk_a, submit_a, ui_a = _extract_action_groups(body)
            actions.extend(all_a)
            page_actions.extend(page_a)
            table_actions.extend(table_a)
            bulk_actions.extend(bulk_a)
            submit_actions.extend(submit_a)
            ui_state_actions.extend(ui_a)
            forms.extend(_extract_forms(body))

        if not filament_seen:
            continue

        component_names = _unique(component_names, 60)
        fields = _unique(fields, 140)
        form_fields = _unique(form_fields, 120)
        table_state_fields = _unique(table_state_fields, 60)
        actions = _unique(actions, 120)
        page_actions = _unique(page_actions, 80)
        table_actions = _unique(table_actions, 80)
        bulk_actions = _unique(bulk_actions, 80)
        submit_actions = _unique(submit_actions, 80)
        ui_state_actions = _unique(ui_state_actions, 80)
        forms = _unique(forms, 40)
        resource_classes, page_classes, page_types = _component_identity(component_names)
        resource_hints = _unique([*resource_classes, *page_classes], 40)
        priority, reasons = _review_priority(path, resource_hints)
        authz = _authorization_surfaces(path, page_types, page_actions, table_actions, bulk_actions, submit_actions)

        results.append(FilamentPageSurface(
            url=representative.url,
            path=path,
            status_code=representative.status_code,
            access_state=_access_state(representative.status_code),
            review_priority=priority,
            priority_reasons=reasons,
            component_names=component_names,
            resource_hints=resource_hints,
            resource_classes=resource_classes,
            page_classes=page_classes,
            page_types=page_types,
            actions=actions,
            page_actions=page_actions,
            table_actions=table_actions,
            bulk_actions=bulk_actions,
            submit_actions=submit_actions,
            ui_state_actions=ui_state_actions,
            fields=fields,
            form_fields=form_fields,
            table_state_fields=table_state_fields,
            authorization_surfaces=authz,
            forms=forms,
            evidence=[
                Evidence(source="filament-passive", detail=f"Filament markers parsed from {path}", weight=80),
                Evidence(source="filament-passive", detail=f"Merged {len(group)} canonical-path snapshot(s)", weight=20 if len(group) > 1 else 0),
                Evidence(source="filament-passive", detail=f"Correlated {len(resource_classes)} resource class(es), {len(page_classes)} page class(es), {len(actions)} application-action marker(s), {len(ui_state_actions)} UI-state marker(s), {len(fields)} field marker(s)", weight=45),
            ],
        ))

    return sorted(results, key=lambda p: p.path)
