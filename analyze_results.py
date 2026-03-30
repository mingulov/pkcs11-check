#!/usr/bin/env python3
"""Analyze pkcs11-check Docker test results - identify real issues vs expected skips."""

import json
from pathlib import Path
from collections import defaultdict, Counter

PROVIDERS = ["bouncyhsm", "kryoptic-main", "nss-pqc", "opencryptoki-master", "softhsm2-main"]

ARTIFACTS_DIR = Path("/home/user/src/m/pkcs11-check/artifacts")


def load_results(provider):
    """Load results.json for a provider."""
    path = ARTIFACTS_DIR / provider / "results.json"
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return None


def is_real_failure(outcome, reason=""):
    """Determine if a failure is a real issue vs expected behavior."""
    if outcome == "xfailed":
        # Expected failure - not a real issue
        return False
    if outcome == "skipped":
        # Skip is expected if it's about missing mechanisms or capabilities
        skip_reasons = [
            "not supported",
            "not supported (cached)",
            "not available",
            "Cannot import",
            "v30, module has v2.40",
            "v32, module has",
            "No PIN configured",
            "Token is write-protected",
            "fault-proxy not built",
            "destructive",
            "No CKO_",
            "not present",
            "not exposed",
        ]
        reason_lower = reason.lower()
        for skip in skip_reasons:
            if skip.lower() in reason_lower:
                return False
        return True  # Unexpected skip
    return outcome == "failed"  # Actual failures are real issues


def analyze_all():
    """Analyze all providers and find real issues."""
    all_data = {}
    for provider in PROVIDERS:
        data = load_results(provider)
        if data:
            all_data[provider] = data

    print(f"Loaded data for {len(all_data)} providers: {', '.join(all_data.keys())}")
    print()

    # Track test outcomes
    test_outcomes = defaultdict(lambda: defaultdict(list))
    test_failure_reasons = defaultdict(lambda: defaultdict(list))

    for provider, data in all_data.items():
        for unit in data.get("units", []):
            for test in unit.get("tests", []):
                nodeid = test.get("nodeid", "")
                outcome = test.get("outcome", "")
                wasxfail = test.get("wasxfail", "")
                longrepr = test.get("longrepr", "")

                test_outcomes[nodeid][provider].append(
                    {"outcome": outcome, "reason": wasxfail or longrepr}
                )

                if outcome == "failed":
                    test_failure_reasons[nodeid][provider].append(
                        longrepr[:200] if longrepr else "Unknown"
                    )

    # Categorize tests
    real_failures = []  # Failed on at least one provider (not xfailed)
    universal_xfails = []  # XFailed on ALL providers (expected/documented issues)
    partial_xfails = []  # XFailed on some, passed on others
    mechanism_skips = []  # Skipped due to missing mechanisms (expected)

    for test_id, provider_results in test_outcomes.items():
        providers_with_results = list(provider_results.keys())

        if not providers_with_results:
            continue

        # Analyze outcomes
        has_failure = False
        has_xfail = False
        has_pass = False
        has_real_skip = False

        for provider, results in provider_results.items():
            for r in results:
                outcome = r["outcome"]
                reason = r["reason"]

                if outcome == "failed":
                    has_failure = True
                elif outcome == "xfailed":
                    has_xfail = True
                elif outcome == "passed":
                    has_pass = True
                elif outcome == "skipped":
                    if is_real_failure(outcome, reason):
                        has_real_skip = True

        # Categorize
        if has_failure:
            # Count how many providers it failed on
            failure_count = sum(
                1 for p, rs in provider_results.items() for r in rs if r["outcome"] == "failed"
            )
            xfail_count = sum(
                1 for p, rs in provider_results.items() for r in rs if r["outcome"] == "xfailed"
            )
            total = len(providers_with_results)

            if failure_count > 0:
                real_failures.append(
                    (test_id, failure_count, xfail_count, total, dict(provider_results))
                )

        elif has_xfail and not has_pass:
            # XFailed on all that ran it
            xfail_count = sum(
                1 for p, rs in provider_results.items() for r in rs if r["outcome"] == "xfailed"
            )
            universal_xfails.append((test_id, xfail_count, len(providers_with_results)))

        elif has_xfail and has_pass:
            # Some passed, some xfailed
            partial_xfails.append((test_id, dict(provider_results)))

    # Print real failures
    print("=" * 100)
    print("REAL FAILURES - Tests that FAILED (not xfailed) on at least one provider")
    print("=" * 100)
    print(f"Total: {len(real_failures)}\n")
    print("Top 50 by failure count:\n")

    real_failures_sorted = sorted(real_failures, key=lambda x: x[1], reverse=True)[:50]
    for test_id, fail_count, xfail_count, total, provider_results in real_failures_sorted:
        print(f"\n{test_id}")
        print(f"  Failed: {fail_count}/{total} providers, XFailed: {xfail_count}")

        reasons = test_failure_reasons.get(test_id, {})
        for provider, results in sorted(provider_results.items()):
            for r in results:
                if r["outcome"] == "failed":
                    print(f"    {provider}: FAILED")
                    if provider in reasons:
                        for reason in reasons[provider][:1]:
                            print(f"      -> {reason[:120]}")

    # Print universal xfails (known/documented issues)
    print("\n" + "=" * 100)
    print("UNIVERSAL XFAILS - Tests that are XFailed on ALL providers (Known Issues)")
    print("=" * 100)
    print(f"Total: {len(universal_xfails)}\n")
    print("Top 30:\n")

    universal_xfails_sorted = sorted(universal_xfails, key=lambda x: x[1], reverse=True)[:30]
    for test_id, xfail_count, total in universal_xfails_sorted:
        print(f"  {test_id}")
        print(f"    XFailed on {xfail_count}/{total} providers")
        # Get the xfail reason
        reasons = []
        for provider, results in test_outcomes[test_id].items():
            for r in results:
                if r["outcome"] == "xfailed" and r["reason"]:
                    reasons.append(r["reason"][:80])
        if reasons:
            print(f"    Reason: {reasons[0]}")

    # Summary by test file
    print("\n" + "=" * 100)
    print("FAILURES BY TEST FILE (Real failures only)")
    print("=" * 100)

    file_failures = Counter()
    for test_id, fail_count, _, _, _ in real_failures:
        file_path = test_id.split("::")[0] if "::" in test_id else test_id
        file_failures[file_path] += fail_count

    for file_path, count in file_failures.most_common(20):
        print(f"  {count:5d} failures: {file_path}")

    # Summary
    print("\n" + "=" * 100)
    print("SUMMARY")
    print("=" * 100)
    print(f"\nTotal unique tests with results: {len(test_outcomes)}")
    print(
        f"Tests with real failures: {len(real_failures)} ({len(real_failures) / len(test_outcomes) * 100:.1f}%)"
    )
    print(
        f"Universal xfails (known issues): {len(universal_xfails)} ({len(universal_xfails) / len(test_outcomes) * 100:.1f}%)"
    )
    print(
        f"Partial xfails: {len(partial_xfails)} ({len(partial_xfails) / len(test_outcomes) * 100:.1f}%)"
    )

    # Most problematic patterns
    print("\n" + "=" * 100)
    print("MOST COMMON FAILURE PATTERNS (Real failures)")
    print("=" * 100)

    patterns = Counter()
    for test_id, _, _, _, _ in real_failures:
        # Extract test class/method patterns
        parts = test_id.split("::")
        if len(parts) >= 2:
            pattern = parts[-1].split("[")[0]  # Remove parametrized part
            patterns[pattern] += 1

    for pattern, count in patterns.most_common(20):
        print(f"  {count:4d}x: {pattern}")


if __name__ == "__main__":
    analyze_all()
