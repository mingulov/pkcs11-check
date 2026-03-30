#!/usr/bin/env bash
# Fetch third-party test vector data from GitHub archives.
# Reads data/sources.toml for pinned commits, checksums, and include filters.
#
# Usage:
#   bash scripts/fetch-data.sh all           # fetch everything
#   bash scripts/fetch-data.sh wycheproof    # just one source
#   bash scripts/fetch-data.sh --status      # show what's present/missing
#   bash scripts/fetch-data.sh --checksums   # download and print SHA-256 (for updating sources.toml)

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

MANIFEST="data/sources.toml"
DATA_DIR="data"

if [ ! -f "$MANIFEST" ]; then
    echo "ERROR: $MANIFEST not found. Are you in the project root?" >&2
    exit 1
fi

# Parse a source entry from sources.toml via Python tomllib.
# Usage: _parse_source <name> <field>
# Returns the value of sources[name][field], or empty string if missing.
_parse_source() {
    local name="$1" field="$2"
    _P11_MANIFEST="$MANIFEST" _P11_NAME="$name" _P11_FIELD="$field" \
    uv run python -c "
import tomllib, json, os
with open(os.environ['_P11_MANIFEST'], 'rb') as f:
    sources = tomllib.load(f)
src = sources.get(os.environ['_P11_NAME'], {})
val = src.get(os.environ['_P11_FIELD'], '')
if isinstance(val, list):
    print(json.dumps(val))
else:
    print(val)
"
}

# Get all source names from the manifest.
_list_sources() {
    _P11_MANIFEST="$MANIFEST" \
    uv run python -c "
import tomllib, os
with open(os.environ['_P11_MANIFEST'], 'rb') as f:
    sources = tomllib.load(f)
for name in sources:
    print(name)
"
}

# Show status of each source (present/missing).
_show_status() {
    echo "Test vector data status (from $MANIFEST):"
    echo ""
    for name in $(_list_sources); do
        local desc
        desc=$(_parse_source "$name" "description")
        if [ -d "$DATA_DIR/$name" ]; then
            printf "  ✓ %-14s %s\n" "$name" "$desc"
        else
            printf "  ✗ %-14s %s (run: bash scripts/fetch-data.sh %s)\n" \
                "$name" "$desc" "$name"
        fi
    done
    echo ""
}

# Fetch a single source by name.
_fetch_one() {
    local name="$1"
    local repo commit sha256 include_json

    repo=$(_parse_source "$name" "repo")
    commit=$(_parse_source "$name" "commit")
    sha256=$(_parse_source "$name" "archive_sha256")
    include_json=$(_parse_source "$name" "include")

    if [ -z "$repo" ] || [ -z "$commit" ]; then
        echo "ERROR: source '$name' not found in $MANIFEST" >&2
        return 1
    fi

    local url="https://github.com/${repo}/archive/${commit}.zip"
    local dest="$DATA_DIR/$name"
    local tmpdir
    tmpdir=$(mktemp -d)

    # Clean up temp dir on exit from this function
    trap "rm -rf '$tmpdir'" RETURN

    echo "Fetching $name from $url ..."
    curl -fsSL "$url" -o "$tmpdir/archive.zip"

    # Verify checksum (skip if PLACEHOLDER — first-time bootstrap)
    if [ "$sha256" != "PLACEHOLDER" ] && [ -n "$sha256" ]; then
        local actual
        actual=$(sha256sum "$tmpdir/archive.zip" | cut -d' ' -f1)
        if [ "$actual" != "$sha256" ]; then
            echo "ERROR: SHA-256 mismatch for $name!" >&2
            echo "  Expected: $sha256" >&2
            echo "  Actual:   $actual" >&2
            return 1
        fi
        echo "  Checksum OK"
    else
        echo "  Checksum: PLACEHOLDER (skipping verification)"
    fi

    # Extract to temp, stripping the GitHub prefix dir ({Repo}-{commit}/)
    unzip -q "$tmpdir/archive.zip" -d "$tmpdir/extracted"

    # GitHub archives have a single top-level dir: {RepoName}-{full-commit}/
    local prefix_dir
    prefix_dir=$(ls -d "$tmpdir/extracted"/*/ | head -1)

    if [ -z "$prefix_dir" ]; then
        echo "ERROR: unexpected archive structure for $name" >&2
        return 1
    fi

    # Apply include filter if specified
    if [ -n "$include_json" ] && [ "$include_json" != "" ]; then
        mkdir -p "$tmpdir/filtered"
        # Parse JSON array of include paths via Python
        _P11_INCLUDE="$include_json" _P11_SRC="$prefix_dir" _P11_DST="$tmpdir/filtered" \
        uv run python -c "
import json, shutil, sys, os
from pathlib import Path

include = json.loads(os.environ['_P11_INCLUDE'])
src = Path(os.environ['_P11_SRC'])
dst = Path(os.environ['_P11_DST'])

for pattern in include:
    source = src / pattern.rstrip('/')
    if not source.exists():
        print(f'  Warning: include path not found: {pattern}', file=sys.stderr)
        continue
    target = dst / pattern.rstrip('/')
    if source.is_dir():
        shutil.copytree(source, target, dirs_exist_ok=True)
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    print(f'  Included: {pattern}')
"
        # Use filtered content
        rm -rf "$dest"
        mv "$tmpdir/filtered" "$dest"
    else
        # No filter — use everything
        rm -rf "$dest"
        mv "$prefix_dir" "$dest"
    fi

    echo "  Installed to $dest"
}

# Print checksums for all sources (for populating sources.toml)
_print_checksums() {
    echo "Downloading archives and computing SHA-256 checksums..."
    echo ""
    for name in $(_list_sources); do
        local repo commit
        repo=$(_parse_source "$name" "repo")
        commit=$(_parse_source "$name" "commit")
        local url="https://github.com/${repo}/archive/${commit}.zip"
        local tmpfile
        tmpfile=$(mktemp)
        echo "  $name: $url"
        curl -fsSL "$url" -o "$tmpfile"
        local checksum
        checksum=$(sha256sum "$tmpfile" | cut -d' ' -f1)
        echo "  archive_sha256 = \"$checksum\""
        echo ""
        rm -f "$tmpfile"
    done
}

# --- Main ---

case "${1:-help}" in
    --status|status)
        _show_status
        ;;
    --checksums|checksums)
        _print_checksums
        ;;
    all)
        for name in $(_list_sources); do
            _fetch_one "$name"
            echo ""
        done
        echo "Done. All sources fetched."
        ;;
    help|--help|-h)
        echo "Usage: $0 {<source-name>|all|--status|--checksums}"
        echo ""
        echo "Commands:"
        echo "  <name>       Fetch a single source (e.g., wycheproof, acvp)"
        echo "  all          Fetch all sources from data/sources.toml"
        echo "  --status     Show which sources are present/missing"
        echo "  --checksums  Download all archives and print SHA-256"
        echo "               (for updating sources.toml)"
        echo ""
        echo "Sources are defined in data/sources.toml."
        ;;
    *)
        _fetch_one "$1"
        ;;
esac
