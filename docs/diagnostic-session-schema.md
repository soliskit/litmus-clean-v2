# Session v1 fields

The diagnostic session is separate from recorder receipt v1 and bundle manifest
v1. It carries no signature, app qualification or root-cause verdict.

- version: integer 1.
- ci: null outside GitHub Actions, otherwise explicit allowlisted caller
  environment claims for repository/run/attempt/job/event/ref and event SHA.
  These are not independently authenticated. Event SHA never replaces the
  checkout commit. No derived guessed URLs or arbitrary environment dump.
- source_before/source_after: observed Git commit, tree and worktree_clean at
  each boundary. source_after may be null if the read fails, making evidence
  incomplete. Dirty state is not silently attributed to committed source.
- observed_clean_checkout_unchanged: true only for equal clean observations
  and matching recorder launch commit/clean state. It does not prove that
  intermediate bytes were never changed and restored.
- tool_source: observed Git state of the tool checkout, not target checkout.
  The tool must be run from its checkout root with tracked core files.
- tool_files: prelaunch SHA256 of diagnostic.py, recorder.py and local_mirror.py.
- mirror: null by default, or local live-view completeness plus written,
  dropped and unmirrored bytes versus the authoritative frozen log. It never
  upgrades app result or evidence_status.
- runtime: explicit Python/system/architecture/Git facts. A Node/npm command
  adds path_node_probe, a best-effort version query through PATH, not a claim
  about a path-qualified executable. Error/timeout becomes unknown.
- repo_label/check/scope: caller-selected profile text, not authenticated
  repository identity, discovered test coverage or an authorization grant.
- profile/receipt: fixed local filenames with SHA256 of their original bytes.
- command_exit: propagated actual outcome, reconciled to the receipt by the
  verifier. Timeout is 124; signal termination is 128+signal. A command failure
  remains failure even if expected attachments cannot be collected.
- evidence_status: complete/incomplete for the requested capture only. An
  intact incomplete capture remains incomplete. Success with incomplete
  evidence exits 125, retaining command_exit=0.
- attachments: ordered explicit source paths; captured entries name fixed
  local payload files plus SHA256/bytes. Unavailable entries do not invent
  payloads. The verifier checks the profile's entire attachment census.
  A declared artifact that already exists at launch and is the same file,
  byte-for-byte, afterwards was not produced by this run: it is unavailable
  with reason unchanged_since_launch. This is staleness detection only; a
  command that rewrites or touches the file is captured as usual.
- claims: fixed statement limiting the result to one selected check.
- session_write_failed: returned in memory only if final session publication
  fails. No completed on-disk session is claimed.

Profile v1 has exactly version/repo/check/scope/argv/artifacts. All labels are
nonempty strings, argv is an explicit nonempty string vector, and artifacts
are distinct canonical relative regular-file paths without traversal. Profiles
are executable trusted input, never automatically discovered or executed from
external messages. Size limit 64 KiB; maximum 32 attachments, 16 MiB each, 32 MiB total.
Unavailable/unstable/link/special/oversize evidence is incomplete, not a pass.
These are initial conservative limits, not measured repo budgets. Recorder log
size is not bounded by attachment limits.

Verification rehashes receipt/profile/log/payloads and reconciles argv, outcome,
labels, scope and complete census. It re-derives the fixed claims statement, the
source observation shape and observed_clean_checkout_unchanged, requires typed
outcome and byte fields, and rejects an in-memory session_write_failed flag or
complete evidence without a final source observation. It is not a public
export, safety approval, source authenticity check or substitute for the
bundle verifier. There is no
upload, telemetry, environment dump or hosted output in this interface.
