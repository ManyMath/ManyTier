#!/bin/bash
# macOS privileged live lane: the utun round-trip test, then the two-node
# data-plane test with tcpdump on both utuns. Usage: sudo tests/shadow/run-macos-live.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=tests/shadow/validation-paths.sh
source "$ROOT/tests/shadow/validation-paths.sh"

if [ "$(uname -s)" != "Darwin" ]; then
    echo "LIVE LANE MISCONFIGURATION: this lane is macOS-only; use tests/shadow/run-privileged-live.sh on Linux." >&2
    exit 1
fi
if [ "$(id -u)" -ne 0 ]; then
    echo "LIVE LANE MISCONFIGURATION: creating utun interfaces requires root. Re-run as: sudo $0" >&2
    exit 1
fi
for tool in ifconfig route tcpdump ping; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "LIVE LANE MISCONFIGURATION: required tool '$tool' is not on PATH." >&2
        exit 1
    fi
done

OWNER_UID="${SUDO_UID:-}"
OWNER_GID="${SUDO_GID:-}"
TARGET_DIR="$(manytier_validation_target_dir)"
SCRATCH_ROOT="$(manytier_validation_scratch_root)"

# Use the invoking user's toolchain.
CARGO_BIN="${MANYTIER_CARGO_BIN:-}"
if [ -z "$CARGO_BIN" ] && [ -n "${SUDO_USER:-}" ]; then
    SUDO_HOME="$(dscl . -read "/Users/$SUDO_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
    PINNED_TOOLCHAIN="$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' "$ROOT/rust-toolchain.toml" | head -n 1)"
    if [ -n "$SUDO_HOME" ] && [ -n "$PINNED_TOOLCHAIN" ]; then
        for tdir in "$SUDO_HOME/.rustup/toolchains/$PINNED_TOOLCHAIN-"*; do
            if [ -x "$tdir/bin/cargo" ]; then
                CARGO_BIN="$tdir/bin/cargo"
                break
            fi
        done
    fi
    if [ -z "$CARGO_BIN" ] && [ -n "$SUDO_HOME" ] && [ -x "$SUDO_HOME/.cargo/bin/cargo" ]; then
        export RUSTUP_HOME="${RUSTUP_HOME:-$SUDO_HOME/.rustup}"
        CARGO_BIN="$SUDO_HOME/.cargo/bin/cargo"
    fi
fi
CARGO_BIN="${CARGO_BIN:-cargo}"
if ! command -v "$CARGO_BIN" >/dev/null 2>&1; then
    echo "LIVE LANE MISCONFIGURATION: cargo not found (looked for the invoking user's toolchain; set MANYTIER_CARGO_BIN)." >&2
    exit 1
fi
if [ "$CARGO_BIN" != "cargo" ]; then
    export PATH="$(dirname "$CARGO_BIN"):$PATH"
fi

TIMESTAMP="$(manytier_validation_timestamp)"
if [[ -n "${MANYTIER_ARTIFACT_ROOT:-}" ]]; then
    ARTIFACT_ROOT="$(manytier_validation_ensure_repo_local "macOS artifact root" "$MANYTIER_ARTIFACT_ROOT")"
else
    ARTIFACT_ROOT="$(manytier_validation_artifact_parent)/run-$TIMESTAMP-macos"
fi
mkdir -p "$ARTIFACT_ROOT" "$ARTIFACT_ROOT/tmp" "$TARGET_DIR" "$SCRATCH_ROOT"

fix_ownership_on_exit() {
    if [ -z "$OWNER_UID" ] || [ -z "$OWNER_GID" ]; then
        return
    fi
    # Hand root-owned output back to the user.
    chown -R "$OWNER_UID:$OWNER_GID" "$TARGET_DIR" "$ARTIFACT_ROOT" "$SCRATCH_ROOT" "$CARGO_HOME" 2>/dev/null || true
}
trap fix_ownership_on_exit EXIT

export CARGO_TARGET_DIR="$TARGET_DIR"
export MANYTIER_WORKSPACE_ROOT="$ROOT"
export MANYTIER_VALIDATION_SCRATCH_ROOT="$SCRATCH_ROOT"
export MANYTIER_VALIDATION_ENVIRONMENT_SHAPE="${MANYTIER_VALIDATION_ENVIRONMENT_SHAPE:-macos-host}"
export MANYTIER_VALIDATION_RUNNER_KIND="${MANYTIER_VALIDATION_RUNNER_KIND:-host}"
export MANYTIER_PRIVILEGED_LIVE=1
export MANYTIER_ARTIFACT_ROOT="$ARTIFACT_ROOT"
export TMPDIR="$ARTIFACT_ROOT/tmp"
# Stable cargo home outside ~/.cargo.
export CARGO_HOME="${MANYTIER_CARGO_HOME:-$TARGET_DIR/macos-cargo-home}"
mkdir -p "$CARGO_HOME"

echo "Artifacts will be collected in: $ARTIFACT_ROOT"
echo "Cargo: $CARGO_BIN ($("$CARGO_BIN" -V)), target dir: $TARGET_DIR"

{
    echo "--- Start of macOS Live Run $TIMESTAMP ---"
    sw_vers
    uname -a
    ifconfig -l

    echo "Step 1: utun round-trip probe (create, configure, read, write)..."
    if ! "$CARGO_BIN" test -p zerotier-service --lib -- \
        --ignored --exact platform::tun::macos_tests::utun_roundtrip_requires_root --nocapture; then
        echo "LIVE LANE MISCONFIGURATION: the utun round-trip probe failed; the two-node lane was not run."
        exit 1
    fi

    echo "Step 2: two ManyTier nodes exchanging routed packets over utun..."
    "$CARGO_BIN" test -p shadow-node --test shadow_harness \
        harness::tests::test_manytier_joins_manytier_controller_fallback \
        -- --ignored --exact --nocapture

    echo "--- End of macOS Live Run $TIMESTAMP ---"
} 2>&1 | tee "$ARTIFACT_ROOT/run.log"

# Collect the evidence into the artifact root.
EVIDENCE_DIR="$ARTIFACT_ROOT/macos-evidence"
mkdir -p "$EVIDENCE_DIR"
TEST_SCRATCH="$SCRATCH_ROOT/manytier-joins-manytier-controller-fallback"
for f in "$TEST_SCRATCH"/fallback-data-plane-evidence.txt \
         "$TEST_SCRATCH"/fallback-mt-handshake-evidence.txt \
         "$TEST_SCRATCH"/*-icmp.pcap; do
    [ -f "$f" ] && cp "$f" "$EVIDENCE_DIR/"
done
echo
echo "Evidence:"
ls -1 "$EVIDENCE_DIR" 2>/dev/null | sed "s|^|  $EVIDENCE_DIR/|"
echo "Node logs: $ARTIFACT_ROOT/host-assisted-fallback/*/host-native.stderr"
echo "Full log: $ARTIFACT_ROOT/run.log"
