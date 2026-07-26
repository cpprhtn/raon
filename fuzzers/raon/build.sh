#!/bin/bash
##
## raon fuzzer integration for Magma — build.sh
##
## Builds the fuzzer's own tooling into the image. raon drives an in-process
## libFuzzer engine, so the only requirement is clang with the libFuzzer runtime
## (already present in Magma's build image) plus the raon package for post-run
## triage/dedup. Nothing else to compile here.
##
## Magma calls this once per (fuzzer,target) image build. See Magma docs:
## https://hexhive.epfl.ch/magma/docs/technical.html
##
set -e

# raon is used after the campaign to triage crashes and read the monitor output.
pip3 install --no-cache-dir raon || echo "warning: raon pip install failed; triage step will be unavailable"
