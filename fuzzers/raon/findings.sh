#!/bin/bash
##
## raon fuzzer integration for Magma — findings.sh
##
## Prints newline-separated paths of fuzzer-generated crashing test cases so the
## Magma harness can collect/triage them.
##
set -e
find "$SHARED/findings" -type f \( -name 'crash-*' -o -name 'leak-*' -o -name 'timeout-*' \) 2>/dev/null || true
