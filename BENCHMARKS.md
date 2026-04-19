# Benchmarks

`actix-web-csp` uses Criterion for repeatable performance checks around the parts
of the crate that are most likely to regress under production traffic.

## What The Suite Covers

- policy creation
- header generation
- nonce generation
- hash generation
- compiled policy snapshot reads
- verification paths
- JSON interop and preset construction

The benchmark entry point is `benches/csp_benchmark.rs`.

## Run The Suite

```bash
cargo bench --bench csp_benchmark
```

Criterion writes HTML reports to:

```text
target/criterion/report/index.html
```

That report is usually the fastest way to inspect hot paths after a change.

## Save A Baseline

When you want to compare a branch against a known-good run:

```bash
cargo bench --bench csp_benchmark -- --save-baseline main
```

Then compare later work against that saved baseline:

```bash
cargo bench --bench csp_benchmark -- --baseline main
```

## Profiling-Friendly Runs

Criterion can keep each benchmark running long enough for an external profiler:

```bash
cargo bench --bench csp_benchmark -- --profile-time 5
```

Use this mode before attaching your profiler of choice. It is especially useful
when investigating:

- header generation regressions
- compiled snapshot read performance
- verifier hot paths
- JSON import/export overhead

## CI And Artifacts

The repository includes a `Benchmarks` GitHub Actions workflow. It runs the
Criterion suite on demand and uploads the generated `target/criterion` directory
as a build artifact so benchmark reports stay visible outside a local machine.
