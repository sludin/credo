## Plan: Synology Build Overrides

Use one generic build override block in deploy config so operators can pass arbitrary build arguments and environment per target, instead of adding dedicated config keys for every new compiler switch. For the Synology requirement, set RUSTFLAGS to include `-C target-cpu=goldmont`.

**Steps**
1. Add a generic optional config object for Rust targets, for example `buildOverrides`, with:
- `env` (string map) applied only to the build subprocess
- `args` (string array) appended to `cargo zigbuild`
2. Keep current defaults unchanged when `buildOverrides` is absent.
3. Implement parser/validation in deploy script:
- `env` must be object of string:string
- `args` must be array of strings
4. Update build invocation to run cargo zigbuild with per-target env + args.
5. Configure Synology targets to use:
- `rustTarget: x86_64-unknown-linux-musl`
- `buildOverrides.env.RUSTFLAGS: -C target-cpu=goldmont`
6. Document precedence and safety:
- target-specific overrides beat shell/session env for reproducibility
- overrides apply only during compile, never during rsync/deploy steps
7. Add verification checklist for Synology artifacts and runtime.

**Relevant files**
- `/Users/sludin/Documents/projects/credo/scripts/deploy` — parse and apply generic build overrides.
- `/Users/sludin/Documents/projects/credo/deploy/deploy-script.md` — document `buildOverrides` schema and examples.
- `/Users/sludin/Documents/projects/credo/.deploy.json` — add overrides for Synology-hosted services.
- `/Users/sludin/Documents/projects/credo/.deploy-remote.json` — if used for Synology, add missing rustTarget and overrides there too.
- `/Users/sludin/Documents/projects/credo/docs/deploy/synology.md` — reference concrete deploy config snippet.

**Verification**
1. Dry run a Synology target deploy and confirm command includes target and extra args/env.
2. Confirm artifact path is under `target/x86_64-unknown-linux-musl/release/`.
3. On NAS, run `file` and `ldd` checks.
4. Start service and validate no illegal instruction errors.

**Sketch: `--print-build-cmd`**
1. Add a global CLI flag in `scripts/deploy`:
- `--print-build-cmd` prints the exact Rust build command (including per-target env and args) before execution.
2. Output format should be shell-copyable and explicit:
- show working directory (`cd <crate_dir> && ...`)
- prefix with effective build env overrides (for example `RUSTFLAGS=-C\ target-cpu=goldmont`)
- include final command and arguments exactly as executed
3. Interaction with existing modes:
- normal run: print command, then execute build
- with `--dry-run`: still print the command while keeping the remote sync and restart steps non-destructive
- with `--parallel`: print one line per target prefixed with job label to avoid ambiguity
4. Scope guardrails:
- only print build-related env keys from `buildOverrides.env` (do not dump unrelated process env)
- keep log output single-line by default; optionally add a multiline verbose form later if needed
5. Example output:
- `[deploy][corgi/corgi-02] BUILD_CMD: cd /repo/corgi && RUSTFLAGS=-C\ target-cpu=goldmont cargo zigbuild --target x86_64-unknown-linux-musl --release --locked`
6. Failure behavior:
- if build fails, include the same printed command in the error footer for quick rerun and debugging.

**Decisions**
- Use one extensible config surface (`buildOverrides`) rather than feature-specific fields.
- For rustc tuning flags, prefer `RUSTFLAGS` via `buildOverrides.env`.
- Keep rustTarget separate because it is a first-order deploy routing key.

**Further Considerations**
1. Add optional allowlist for env keys if you want to prevent accidental unsafe overrides.
2. If quoting/escaping across shells becomes noisy, add a JSON output mode later (for CI parsing) while keeping the human-readable default.