# Release and QA archive

The documents under `release/day2-final/`, `release/benchmarks/`, and `release/qa-reports/` preserve reports from earlier local runs. Some include test, model, replay, or UI status claims that depend on datasets, model binaries, and generated outputs that are not committed here. Read those claims as historical evidence, not as the current state of `main`.

Before citing a benchmark or saying the system is submission-ready:

1. Check out the current `main` revision.
2. Obtain the authorized organizer data and label mapping.
3. Regenerate model artifacts, evaluation reports, and replay outputs.
4. Record the code revision and input hashes with the results.
5. Confirm current GitHub Actions checks and rerun the full local-data workflow.

The root [README](../README.md), [data audit](../docs/data-intelligence.md), [evaluation guide](../docs/evaluation.md), and live GitHub Actions badges are the current entry points. Challenge data, model binaries, and generated submissions should remain outside Git unless organizers explicitly authorize publication.
