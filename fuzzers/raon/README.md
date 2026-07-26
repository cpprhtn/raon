# raon — Magma fuzzer integration

These five scripts plug raon into the [Magma](https://github.com/HexHive/magma) benchmark,
following Magma's fuzzer-integration contract (`fuzzers/<name>/`):

| Script | Role |
|---|---|
| `build.sh` | Build the fuzzer's own tooling into the image (installs `raon` for post-run triage). |
| `instrument.sh` | Compile the target with clang + libFuzzer + ASan/UBSan + SanitizerCoverage. |
| `run.sh` | Run one campaign; after it, triage crashes and record findings. |
| `runonce.sh` | Run the target on a single test case (PoC reproduction). |
| `findings.sh` | List crashing test cases the campaign produced. |

raon's engine is libFuzzer-based, so instrumentation mirrors Magma's stock `libfuzzer`
integration. raon's contribution is **after** the campaign: it reads the crashing inputs and
Magma's `monitor` output (canary ground truth) and produces triaged, deduplicated,
exploitability-ranked findings via `raon triage` / `raon report` and `raon.bench`.

## Status

> **Not yet run here.** Magma requires an **x86_64 Linux host with Docker** (no arm64/macOS
> support). These scripts are the integration contract, ready to run on such a host; measured
> Magma results are not published yet (see [`docs/evaluation.md`](../../docs/evaluation.md)).

## Usage (on an x86_64 Linux host)

Copy this directory into a Magma checkout at `fuzzers/raon/`, then:

```bash
# from the magma repo
FUZZER=raon TARGET=libpng ./tools/captain/build.sh
FUZZER=raon TARGET=libpng PROGRAM=libpng_read_fuzzer \
  SHARED=./workdir POLL=5 TIMEOUT=1h ./tools/captain/start.sh
```

After the run, `$SHARED/raon_report.json` holds the ranked findings and `$SHARED/monitor/`
holds the canary time series; feed the latter to `raon.bench.parse_monitor_dir` for
reached/triggered metrics.
