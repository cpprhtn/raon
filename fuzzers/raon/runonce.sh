#!/bin/bash
##
## raon fuzzer integration for Magma — runonce.sh
##
## Runs the instrumented target on a single test case (used by Magma for PoC
## reproduction / crash triage). Exit code and sanitizer output on stderr.
##
set -e
"$OUT/$PROGRAM" "$1"
