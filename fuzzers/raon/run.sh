#!/bin/bash
##
## raon fuzzer integration for Magma — run.sh
##
## Launches one campaign. Magma wraps this in `timeout $TIMEOUT` and runs its
## monitor loop alongside (sampling canaries.raw into $SHARED/monitor/<sec>).
## After the campaign, raon reads that monitor tree + the crashing inputs to
## produce triaged, deduplicated, ranked findings.
##
set -e

mkdir -p "$SHARED/findings"

export ASAN_OPTIONS="abort_on_error=1:symbolize=1:detect_leaks=0"
export UBSAN_OPTIONS="print_stacktrace=1"

# libFuzzer campaign. $ARGS/$PROGRAM come from the target's configrc; seeds from
# the target corpus. Crashes land in $SHARED/findings as crash-*/leak-*.
"$OUT/$PROGRAM" \
    -artifact_prefix="$SHARED/findings/" \
    -print_final_stats=1 \
    $ARGS \
    "$SHARED/corpus" \
    "$TARGET/corpus/$PROGRAM" \
    2>&1

# Post-run (best effort): triage crashes and summarize the monitor ground truth.
# Requires the raon package (see build.sh) and $SHARED/monitor from Magma.
if command -v raon >/dev/null 2>&1; then
    for poc in "$SHARED"/findings/crash-* "$SHARED"/findings/leak-*; do
        [ -e "$poc" ] || continue
        "$OUT/$PROGRAM" "$poc" 2> "$poc.san" || true
        raon triage "$poc.san" --target-id "$TARGET/$PROGRAM" \
            --reproducer "$poc" --db "$SHARED/raon.sqlite" || true
    done
    raon report --db "$SHARED/raon.sqlite" > "$SHARED/raon_report.json" || true
fi
