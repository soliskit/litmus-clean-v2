# Qualification evidence

Checked November 10, 2026. This record covers the proposed sweep inspection and locked-staging-name change. It does not close every open verifier or sweep finding.

## Executed source

| File | SHA-256 |
| --- | --- |
| packager.py | 1f17546c3045b01628efb13b103c28296864fdbb8a1c5ff2a4d3ccd1d601611e |
| verifier.py | 99368cc8e95ffb30956872f4812cb765c58b80648459e7f5fec5db5e44e27179 |
| checks.py | b3a8be741ffaef197c83b63b0bbed7c6da8e1f256960c3ad8e8d00e81613cf44 |

## Gate result

The unchanged 16-check gate main passed all sixteen checks, with zero failures, on these source bytes. Runtime was CPython 3.10.12 on Linux x86-64, an unprivileged account without effective capabilities.

The accepted invocation imported the unchanged checks module and called its original main. It set TMPDIR to a fresh owned primary temporary directory and assigned the checks module's SECOND_FS to a fresh owned directory on a real second filesystem. Every check, assertion, order and failure-loop behavior remained unchanged. This was not bare `python3 checks.py` startup. Both owned roots were observed empty afterward. The execution completed in about 0.933 seconds; the stated limits were cooperative, not hard bounds over blocked system calls or memory allocation.

## Focused evidence

The following focused, formal and three-test contrast evidence ran on packager SHA-256 `68815e83cc7df65a3156bc39efd84ef9ea4d0dd0ccf11afa41f087ec1ec3641a` on November 9. The current source differs only by removing the unused `tempfile` import. Those earlier checks were not repeated or attributed to the new hash. The unchanged gate was rerun on the current hash as recorded above.

The original sweep aborts at an unreadable entry after removing an earlier entry, leaving a later removable entry unexamined. The inspection fix removes both independent entries and reports the unreadable, locked and symlinked entries as skipped. Before-and-after inode and content inventories establish what remained. Controlled open, stat and fstat errors are separate injected cases, not native failure claims.

The staging change was checked at controlled schedules around real mkdir, open, flock, rename and sweep operations. An independent process could lock an unlocked reservation while the sweep still left it alone. It could not lock a staging directory whose producer held the lock. Resumed packs published complete evidence. A planned kill before the staging-name change left the exact reservation and no published bundle.

Real namespace collision retry and exhaustion checks preserved existing rival entries. Separate controlled identity mismatches and exceptions checked refusal paths and descriptor restoration; they do not prove resistance to hostile concurrent path changes. A combined-source case checked reservations and unreadable-entry continuation in the same namespace.

Additional source-aware formal checks exercised native final-target refusal, four actual pause-point kills, a real filesystem permission error, a live locked sweep followed by publication, and an actual cross-device refusal. The ordinary checks also verified complete existing-bundle identity and bytes on republish refusal, stronger than the original gate's one-file marker check.

## Published regression source

The exact three-test file ran through a bounded custom unittest-class runner. All three tests were reached on both sources, without skips. On the original source, reservation reporting and staging-lock assertions failed and unreadable-entry recovery raised PermissionError. On the combined candidate, all three passed. The unittest bodies took about 0.002 seconds on the original and 0.003 seconds on the candidate.

The runner loaded the source modules in memory and selected the test class. This establishes the exact test bodies' fail-before/pass-after behavior, not execution of the documented literal discovery command or final repository import layout. The wrapper's exit zero means its expected baseline failures matched, not that the original unittest result passed. Owned temporary test fixtures were observed empty afterward and descriptor inventories were restored.

## Limits that remain

- Issue #21 remains: the unchanged verifier accepts a fully written unpublished staging directory. A killed after-manifest staging directory actually returned VALID. A passing gate does not make the contract's broader consumption promise true.
- Issue #24's malformed-manifest acceptance is unchanged. The aggregate invalid-framing cases do not prove every field is checked.
- Issue #31's isolated stored-verdict field coverage is separate from the gate's aggregate stale/foreign cases.
- The original gate's C1-h message says "before staging", but its assertions prove refusal and no final publication, not that timing. Its C1-e message mentions `/tmp`; the accepted run used the recorded owned primary root instead.
- Partial recursive removal can still be reported as skipped. Skipped does not mean untouched.
- Earlier producers retain their creation-to-lock gap. Reservations are never swept and require informed operator handling.
- No power-loss durability, hostile namespace safety, hard memory bound or escaped-process cleanup guarantee is claimed.

This change uses non-closing references to #37 and #38 until their remaining scope is reviewed. Gate evidence is version-specific, not a claim that every contract statement or open issue is settled.

## What the existing checks missed

The unreadable-entry defect sits between the gate's simple symlink skip case and its live-locked staging case. Neither original gate fixture places an unreadable staging entry between earlier and later removable entries. The missing ordering case explains why those passing checks did not detect the lost report. The new unreadable-entry regression targets that exact gap.

The original live-staging check pauses a pack after its manifest is written, when its staging lock is already held. It does not inspect the interval between allocating the directory and acquiring that lock. That missing transition explains why it passed while the allocation-to-lock promise was false. The regression checks the earlier staging-creation hook; the independent controlled schedule checks the reservation window separately.

These are source-checked explanations of two specific missed fixtures, supported by their original-failure and proposed-pass results. They do not establish that every defect shares the same cause or that every state transition is now covered. The accepted full gate still passes while unpublished complete staging is accepted, so its green result is not proof of the broader consumption promise.

## Unused-import correction

The first pull-request CI run stopped at Ruff F401: `tempfile` remained imported after reservation allocation replaced its last use. No regression assertion failed in that run. The pre-publication qualification did not include the repository's Ruff check, so it did not catch the unused import. The correction removes that import only.

On November 10, Ruff 0.17.4 passed `python3 -m ruff check --select E4,E7,E9,F .` on the corrected source and existing repository files. The unchanged 16-check gate also passed on the current hashes through the accepted owned-directory invocation. Earlier custom-runner results remain scoped to their original bytes; literal discovery and final import-layout execution remain untested.
