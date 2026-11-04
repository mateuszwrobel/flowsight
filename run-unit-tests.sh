#!/usr/bin/env bash
# Run the flowsight test suite plus the clippy gate and the archspec legs.
#
# Safe to run from inside a git hook: we strip inherited GIT_* env so any
# `git` subprocess spawned during the run uses the test fixture's repo,
# not the enclosing repo's GIT_DIR.
set -euo pipefail

unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_PREFIX \
      GIT_COMMON_DIR GIT_NAMESPACE GIT_OBJECT_DIRECTORY \
      GIT_ALTERNATE_OBJECT_DIRECTORIES

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Test scratch lives on disk, not tmpfs (repo TMPDIR law); build output goes
# to the per-lane cache, never into the worktree tree.
export TMPDIR="${TMPDIR:-/var/tmp}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/flowsight-target}"

echo "Running flowsight tests..."
# nextest (hardening lane A): per-test timeouts (see .config/nextest.toml).
# Doctest parity: doc tests stay on cargo test (nextest does not run them).
cargo nextest run --no-tests=pass --config-file "$SCRIPT_DIR/.config/nextest.toml" --manifest-path "$SCRIPT_DIR/Cargo.toml" "$@"
cargo test --doc --manifest-path "$SCRIPT_DIR/Cargo.toml"

echo "Running flowsight clippy gate..."
cargo clippy --manifest-path "$SCRIPT_DIR/Cargo.toml" --all-targets -- -D warnings

# Family-binary resolution law (speckit wave 3): ARCHSPEC env -> PATH ->
# fail closed, naming the binary. The binaries come from the global
# install: specs/install/install-spec-tools.sh (no relative target/ builds).
ARCHSPEC="${ARCHSPEC:-}"
if [ -z "$ARCHSPEC" ]; then
    ARCHSPEC="$(command -v archspec 2>/dev/null || true)"
fi
if [ -z "$ARCHSPEC" ] || [ ! -x "$ARCHSPEC" ]; then
    echo "archspec binary not found — set ARCHSPEC=/path/to/archspec or install the family binaries globally: specs/install/install-spec-tools.sh" >&2
    exit 1
fi

echo "Running archspec verify --strict for flowsight..."
"$ARCHSPEC" verify "$SCRIPT_DIR" --strict

# Non-vacuity leg: a spec over a module graph with no edges would verify
# green while proving nothing. The scan's inter-module edge count (test
# modules excluded) must stay at or above the count the spec header declares.
echo "Running archspec scan non-vacuity guard..."
EDGE_FLOOR=10
EDGES="$("$ARCHSPEC" scan "$SCRIPT_DIR" --output - | python3 -c '
import json, sys
m = json.load(sys.stdin)
print(sum(
    1 for e in m["module_edges"]
    if e["from"] != e["to"]
    and "::tests" not in e["from"]
    and "::tests" not in e["to"]
))')"
if [ "$EDGES" -lt "$EDGE_FLOOR" ]; then
  echo "non-vacuity: scan found $EDGES inter-module edges (< $EDGE_FLOOR) — the module graph shrank below what the spec header declares; fix the code or update the spec and this floor together" >&2
  exit 1
fi
echo "non-vacuity: $EDGES inter-module edges (floor $EDGE_FLOOR)"

echo "flowsight unit lane green"
