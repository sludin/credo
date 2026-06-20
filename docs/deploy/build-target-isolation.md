# Build Target Isolation in CI/CD

## Risk of Shared Target Directories with Mixed RUSTFLAGS

When builds run with different compiler flags (for example `target-cpu=goldmont` for Synology vs generic x86_64) in the same target directory, Cargo artifacts can get mixed in ways that are hard to spot.

- Artifacts can be reused across incompatible flag sets.
- Binary behavior can differ from expected CPU baseline.
- Failures often only appear on specific hardware.

## Why Parallel Builds Make This Worse

Parallel jobs targeting the same directory increase race conditions.

- One job may overwrite intermediate artifacts used by another job.
- Cache invalidation becomes nondeterministic.
- You may only see runtime faults after deployment.

## Recommended Approach

Use isolated build directories by setting `CARGO_TARGET_DIR` from a hash of target + profile + effective build flags.

Example approach:
- Compute a short hash from rust target, profile, and build override flags.
- Set `CARGO_TARGET_DIR` to `target/build-<hash>` for that build only.
- Run `cargo zigbuild` with that isolated target dir.

## When Sharing Is Safe

Shared target directories are generally safe only when all of the following are true:

- Same rust target triple.
- Same profile.
- Same effective compiler flags.
- No parallel builds touching that directory.

## Rollout Checklist

- Add per-build `CARGO_TARGET_DIR` derivation in deploy script.
- Include the derived directory in `--print-build-cmd` output.
- Verify artifacts are emitted from isolated target paths.
- Run parallel deploy tests for mixed x86_64 variants.
- Validate on Synology hardware for illegal instruction errors.
- Document the policy in deploy docs and runbook.
