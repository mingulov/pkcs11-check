"""Cross-provider correlation and per-group enrichment.

:func:`correlate` finds *universal themes* - the same ``(reason, kind, mechanism)``
signature seen across two or more providers - plus single-provider *outliers*.

:func:`enrich` annotates each group in place with a triage ``category`` and a
``routing`` target, re-tagging known module-issues matches and flagging the
soft-token padding-oracle caveat. It is deliberately simple: substring / keyword
matching against the relevant provider section of the known-issue text.
"""

from __future__ import annotations

from typing import Any

from pkcs11_check.classification import HARNESS_REASONS

ThemeKey = tuple[str, str | None, str | None]


def _theme_key(group: dict[str, Any]) -> ThemeKey:
    return (str(group.get("reason", "")), group.get("kind"), group.get("mechanism"))


def correlate(provider_groups: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    """Return universal themes (signature shared by >=2 providers) + outliers.

    ``provider_groups`` maps provider name -> its list of group dicts.
    """
    # provider set per theme key
    theme_providers: dict[ThemeKey, set[str]] = {}
    for provider, groups in provider_groups.items():
        for group in groups:
            if group.get("reason") in HARNESS_REASONS:
                continue
            theme_providers.setdefault(_theme_key(group), set()).add(provider)

    universal: list[dict[str, Any]] = []
    outliers: list[dict[str, Any]] = []
    for key, providers in theme_providers.items():
        reason, kind, mechanism = key
        entry = {
            "reason": reason,
            "kind": kind,
            "mechanism": mechanism,
            "providers": len(providers),
            "provider_names": sorted(providers),
        }
        if len(providers) >= 2:
            universal.append(entry)
        else:
            outliers.append(entry)

    universal.sort(key=lambda e: (-int(e["providers"]), str(e["reason"]), str(e["mechanism"])))
    outliers.sort(key=lambda e: (str(e["provider_names"]), str(e["reason"])))
    return {"universal_themes": universal, "outliers": outliers}


def _provider_section(module_issues_text: str, provider: str) -> str:
    """Return the slice of module-issues text for ``provider`` (best effort).

    Sections are ``## <Provider …>`` headings. We match the first heading whose
    text contains the provider token (case-insensitive) and return up to the next
    heading. If nothing matches we fall back to the whole document so a global
    match still works.
    """
    token = provider.lower()
    lines = module_issues_text.splitlines()
    start: int | None = None
    for i, line in enumerate(lines):
        if line.startswith("## ") and token in line.lower():
            start = i
            break
    if start is None:
        return module_issues_text
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if lines[j].startswith("## "):
            end = j
            break
    return "\n".join(lines[start:end])


def _known_issue_match(group: dict[str, Any], section_text: str) -> bool:
    """True if the group's mechanism/operation/kindword appears in the section.

    Requires at least one *discriminating* token (mechanism or operation) to be
    present so a bare kindword does not over-match. Substring match, lowercased.
    """
    if not section_text.strip():
        return False
    haystack = section_text.lower()
    discriminators = [
        str(group.get(field)) for field in ("mechanism", "operation") if group.get(field)
    ]
    if not any(d.lower() in haystack for d in discriminators):
        return False
    # also require the kindword (e.g. "crypto"/"policy") OR a summary keyword to
    # corroborate, keeping it simple but a little less trigger-happy.
    kindword = group.get("kind")
    if kindword and kindword.lower() in haystack:
        return True
    # summary corroboration: any 5+ char word from summary present
    summary = str(group.get("summary", "")).lower()
    for word in summary.split():
        if len(word) >= 5 and word in haystack:
            return True
    # discriminator alone is acceptable corroboration when no kind present
    return kindword is None


# Per-reason routing for xfail deviations. An xfail is a recorded deviation to
# investigate, not a blanket "docs-only"; honest_deviation is a positive-op
# operability failure that may be a real bug.
_XFAIL_ROUTING = {
    "not_operational": "CAPABILITY_AUDIT",
    "nonspec_reject": "SPEC_REVIEW",
    "honest_deviation": "INVESTIGATE",
    "undeclared_capability": "METADATA_REVIEW",
}


def enrich(groups: list[dict[str, Any]], module_issues_text: str, provider: str) -> None:
    """Annotate each group in place with ``category`` + ``routing`` (and caveats).

    * fails default to ``category=PROVIDER_BUG`` / ``routing=PROVIDER_REPORT``
    * xfails -> ``category="deviation"`` / ``routing=DOCS_ONLY``
    * harness errors -> ``category=HARNESS_OR_UNMIGRATED`` / ``routing=HARNESS_FIX``
    * unclassified -> provider fail evidence with the default provider-report route
    * a module-issues match re-tags ``category=KNOWN_ISSUE`` / ``routing=DOCS_ONLY``
    * oracle/crypto (padding-oracle class) get ``soft_token_caveat=True``
    """
    section = _provider_section(module_issues_text, provider)
    for group in groups:
        reason = str(group.get("reason", ""))
        outcome = group.get("outcome")

        if reason in HARNESS_REASONS:
            group["category"] = "HARNESS_OR_UNMIGRATED"
            group["routing"] = "HARNESS_FIX"
        elif outcome == "xfail":
            group["category"] = "deviation"
            group["routing"] = _XFAIL_ROUTING.get(reason, "DEVIATION_REVIEW")
        else:  # any fail (incl. crash)
            group["category"] = "PROVIDER_BUG"
            group["routing"] = "PROVIDER_REPORT"
            if _known_issue_match(group, section):
                group["category"] = "KNOWN_ISSUE"
                group["routing"] = "DOCS_ONLY"

        # Soft-token caveat: ONLY genuine timing/value-oracle findings (reason
        # "oracle"). Do NOT tag crypto accepted_invalid / crash breaks - those are
        # real on any backend and must not be softened.
        if reason == "oracle":
            group["soft_token_caveat"] = True
