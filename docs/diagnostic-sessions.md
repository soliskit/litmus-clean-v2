# Diagnostic sessions (draft implementation contract)

This addition is not yet qualified or published. Existing recorder receipt v1,
bundle manifests and verifier contracts do not change. Recorder execution now
has an optional LocalMirror object; its default wait path is unchanged. The
changed recorder must be qualified and reviewed as changed source.

## Current local slice

`python3 diagnostic.py PROFILE DESTINATION --cwd CHECKOUT [--timeout SECONDS]` selects an explicit
trusted profile and launches its exact argv once through the existing recorder.
Profiles are executable input. Never select one from an untrusted attachment or
check it out from a pull request and run it with privileged credentials.

DESTINATION must not exist and is created mode 0700. Profile bytes, recorder
receipt and original combined output remain local. No upload or bundle publish
is performed. The command inherits the caller's environment just as a direct
invocation would; this is not an isolation or secrets-protection boundary.
The manifest does not dump that environment. The repo field is currently only
a caller-supplied label, not authenticated repository identity. The tool must
run from its own Git checkout root with tracked recorder/packager/verifier
files. Copying diagnostic.py into a target repo is not a supported install.

The profile's explicit scope describes the question this command can answer.
A result never means the whole repo passed, and never replaces a release,
coverage, skip-roster, mutation-completeness or platform gate.

Exit behavior:

- Preserve a failing command's actual propagated status.
- A successful command with unavailable declared evidence returns 125, with
  command_exit=0 and evidence_status=incomplete in the session manifest.
- Failure to start, interrupted capture or failure to create a final session
  does not claim a complete diagnostic. A missing session is not success.
- Exit 125 is overloaded: a command that itself exits 125, a successful command
  with incomplete evidence, and a refused or unstartable run all return it.
  Read command_exit and evidence_status in session.json, or use --verify, to
  tell them apart; a refused run has no session.json.
- No timeout is added by default. An explicit finite positive --timeout uses
  the existing recorder process-group deadline and preserves its 124 outcome.
  Profiles do not silently cut off or retry an existing command.

Attachments are explicit regular-file paths within CHECKOUT, not globs or
recursive directory captures. Path traversal, duplicate paths and symbolic
links are refused. Each path component is opened with no-follow directory
anchors. Each file must remain stable while read. Attachment payloads are
copied byte-for-byte into separately hashed files. Current implementation
budgets are at most 32 files, 16 MiB per file and 32 MiB in total. An attachment
outside this envelope is unavailable and evidence is incomplete. These limits
are an initial conservative implementation envelope, not measured repo budgets
or user-supplied limits, and must be reviewed before adoption. Original recorder
log growth is NOT bounded by these attachment limits.

## Local integrity check

`python3 diagnostic.py --verify DESTINATION` re-reads the local files and checks
their recorded hashes, argv/outcome consistency and attachment census. It is
not a signature or proof of authorship, a safety approval or an app verdict.
An intact incomplete session stays incomplete. The before/after source facts
show observed commit/tree/clean state only, not proof that files were unchanged
throughout the run. Dirty worktrees remain explicitly dirty. Tool file hashes
are observed before launch.

## Required before pilot adoption

- Review/complete local live FIFO output, preserving command status and
  interruption semantics. Current local tests cover small output equality,
  backpressure with timeout, unavailable FIFO and non-FIFO refusal. Active
  macOS mirror behavior still needs qualification.
- Independently authenticated CI/repository binding and explicit shard input.
  Current CI allowlist records caller environment claims only, not live provider
  identity; it does not substitute event SHA for checkout identity.
  Current before/after checkout commit/tree/clean observations and prelaunch
  tool-file hashes are facts, not proof of unchanged bytes through execution.
  Runtime facts are Python/system/architecture/Git plus PATH-resolved Node version probe for a
  Node/npm profile, unknown on missing executable/error/timeout. This is NOT
  the version of a path-qualified argv executable or proof of npm child versions. No other environment values are recorded.
- Remaining parallel/shard/platform/evidence-failure coverage and review.
  Local qualification includes real timeout/SIGTERM plus CLI, evidence-budget,
  malformed/missing evidence and failure-status tests. These are wrapper tests.
- Explicit source and platform review. Mac support is not established by Linux
  tests. Bundle publication remains on the supported Linux x86-64 route.
- Matching CI discovery and strict type-check inclusion for the new source/tests.
  The credit guard currently rejects workflow-tree changes and requires its
  separately trusted bootstrap review; do not bypass it.
- Per-repo runtime verification, measured overhead and real Node/browser/Mac CI
  adoption. Synthetic wrapper tests are not app runs.
- Public output is a separate reviewed typed-fact export, never an automatic
  upload of raw logs or native files. No such export is implemented here.

## Profile status

The checked-in candidate profiles are recipes grounded in original repo source.
They are not adopted integrations or evidence that those commands have run.
Replacement repos must be checked at their accepted working-target revision
before rollout. Foundry upkeep remains out of scope. Native Tetris and full
Arx native/fixture recipes remain to be prepared on their supported runners.

## Optional local live output

`--mirror-fifo PATH` selects an existing caller-owned FIFO with an already-open
reader. It never creates a FIFO, launches a viewer, mutates inherited descriptor
flags, opens a PTY/TTY or writes a regular-file sink. The writer is opened
independently O_NONBLOCK and actual FIFO ownership/type is checked before any
write. Unsupported/unavailable sinks are incomplete mirrors, not app failures.
The option is refused in GitHub Actions as accident prevention, not a security boundary. Raw logs are not uploaded.

The changed recorder wait loop reads at most 16 KiB and attempts one nonblocking
FIFO write per 20 ms wait interval, using the wait-phase monotonic timeout origin. It
makes one final fixed-EOF drain bounded to 1 MiB or 10 ms, not an unbounded chase of descendants. Large or
backpressured output may be incomplete live; the frozen original receipt log
remains authoritative. Mirror written/dropped/unmirrored counts are separate
from command and evidence status. This is best-effort local viewing, not hard
realtime, full-delivery or general terminal support. macOS is not yet qualified.
