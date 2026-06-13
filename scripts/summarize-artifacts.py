import json
from pathlib import Path

targets = []
for p in Path("artifacts2").glob("*-pooled"):
    results_path = p / "results.json"
    if not results_path.exists():
        continue

    with open(results_path) as f:
        data = json.load(f)

    summary = data.get("summary", {})
    units = data.get("units", [])

    quality_path = p / "quality.json"
    file_skipped = 0
    if quality_path.exists():
        with open(quality_path) as f:
            qdata = json.load(f)
            # file_skipped_units is a list of dicts in the new schema
            file_skipped = len(qdata.get("file_skipped_units", []))

    target_name = p.name.replace("-pooled", "")
    targets.append(
        {
            "target": target_name,
            "shards": len([d for d in Path("artifacts2").glob(f"{target_name}-shard-*")]),
            "files": len(units),
            "total": summary.get("total", 0),
            "passed": summary.get("passed", 0),
            "failed": summary.get("failed", 0),
            "skipped": summary.get("skipped", 0),
            "xfailed": summary.get("xfailed", 0),
            "errors": summary.get("error", 0),
            "crashed": summary.get("crashed", 0),
            "timeout": summary.get("timeout", 0),
            "file_skipped": file_skipped,
            "duration": sum(u.get("duration_s", 0) for u in units),
        }
    )

order = [
    "softhsm2",
    "softhsm2-generated-iv",
    "softhsm2-main",
    "kryoptic",
    "kryoptic-main",
    "kryoptic-fips",
    "nss",
    "nss-pqc",
    "nss-main",
    "nss-slot0",
    "nss-pqc-slot0",
    "nss-main-slot0",
    "opencryptoki",
    "opencryptoki-master",
    "wolfpkcs11",
    "wolfpkcs11-master",
    "corepkcs11",
    "corepkcs11-main",
    "tpm2",
    "pkcs11-mock",
    "bouncyhsm",
]

targets.sort(key=lambda x: order.index(x["target"]) if x["target"] in order else 999)

print(
    "| Docker target | Shards | Files | Total | Passed | Failed | Skipped | Xfailed | Errors | Crashed | Timeout | File-skipped units |"
)
print("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
for t in targets:
    print(
        f"| `{t['target']}` | {t['shards']} | {t['files']} | {t['total']:,} | {t['passed']:,} | {t['failed']:,} | {t['skipped']:,} | {t['xfailed']:,} | {t['errors']:,} | {t['crashed']:,} | {t['timeout']:,} | {t['file_skipped']} |"
    )

print("\n\n")
for t in targets:
    d = t["duration"]
    h = int(d // 3600)
    m = int((d % 3600) // 60)
    s = int(d % 60)
    dur_str = f"{h}h {m}m {s}s" if h > 0 else f"{m}m {s}s"
    print(f"| `{t['target']}` | {t['shards']} | {t['files']} | {dur_str} |")
