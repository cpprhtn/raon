#!/bin/bash
##
## raon fuzzer integration for Magma — instrument.sh
##
## Compiles the TARGET with raon's instrumentation: clang + libFuzzer +
## AddressSanitizer/UndefinedBehaviorSanitizer + SanitizerCoverage. Magma's
## canary flags are layered on top by $MAGMA/build.sh. This mirrors Magma's
## stock libfuzzer integration (raon's engine is libFuzzer-based) — raon's
## contribution is the post-run triage/dedup/ranking, not a new instrumentation.
##
set -e

export CC="clang"
export CXX="clang++"

# fuzzer-no-link on the objects; the final driver links -fsanitize=fuzzer.
export CFLAGS="$CFLAGS -fsanitize=fuzzer-no-link,address,undefined -fsanitize-coverage=trace-pc-guard -g"
export CXXFLAGS="$CXXFLAGS -fsanitize=fuzzer-no-link,address,undefined -fsanitize-coverage=trace-pc-guard -g"
export LIBS="$LIBS -fsanitize=fuzzer"

# Apply Magma canary patches + build the instrumented target.
"$MAGMA/build.sh"
"$TARGET/build.sh"
