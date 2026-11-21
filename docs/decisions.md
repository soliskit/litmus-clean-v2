# Decisions and limits

This focused proposal records the chosen E0/F2 direction. Rows remain Pending work until the approved pull request includes their source, requirements and tests, and verification for its actual revision. It does not settle all of issues #37 or #38.

## LM-D37

| Status | Effect | Decision and limits |
| --- | --- | --- |
| Pending work | Continue a sweep after an entry cannot be inspected without changing its interface. | Implement only the per-entry open/stat/fstat OSError catch boundary in [LM-37-INSPECT](requirements.md). Preserve existing flock/removal skip handling and descriptor close. Do not add a failure schema or claim skipped means untouched after a partial recursive removal. Root-listing failure, non-OSError, close failure and hostile path replacement are not repaired by this change. |

## LM-D38

| Status | Effect | Decision and limits |
| --- | --- | --- |
| Pending work | Give this version's staging entries a held lock before their staging names become visible; leave reservations for informed operator handling. | Adopt the full policy below with [LM-38-NAMESPACE](requirements.md). No automatic reservation cleanup, parent lock, namespace split or guarantee for old producers is included. |

The full chosen policy has one home in [the qualification contract](qualification-contract.txt), under "Live staging namespace is locked for cooperating participants". The row records the choice; it does not duplicate that policy.

## Intended staging states

The model follows the chosen policy, not an assumption that current code is correct.

| State | Entry condition | Allowed next state | Interruption or failure leaves |
| --- | --- | --- | --- |
| No allocation | No reservation or staging entry exists for this attempt. | Reservation, after exclusive directory creation. | Nothing allocated by this attempt. |
| Reservation, not yet locked | An entry exists outside valid bundle names and the staging namespace. A sweep must not open or delete it. | Locked reservation, after opening the exact directory and acquiring flock. | An unswept reservation. Its name alone does not establish whether it is in use. |
| Locked reservation | The producer holds the directory lock and verifies the named entry has the held identity. | Locked staging, by an atomic no-overwrite namespace rename and another identity check. | Reservation residue if the transition did not happen; staging residue if it did. No final bundle is promised. |
| Locked staging | The directory has a staging name and its producer holds the lock. A cooperating sweep skips it. | Complete locked staging, after evidence and manifest writes and attempted pre-publish fsync. | Unpublished, untrusted staging residue; no final path. |
| Complete locked staging | Evidence and manifest are complete; final publication has not happened. | Published, through atomic no-overwrite final rename only. | Complete staging can remain. The verifier refuses it: only the exact published directory, named as its manifest declares, validates. |
| Published | The final rename succeeded. | Return success, with any post-publish directory-fsync failure reported only as a warning. | A complete published bundle may remain after a kill. This is not power-loss durability proof. |

Lock lifetime must cover the whole interval from staging-name visibility through final rename. Namespace collision never authorizes replacing an existing entry. A failure before final publication must not claim a published result. Process death releases kernel locks, but it does not prove to an operator that any similarly named reservation is unused. Path replacement by non-cooperating processes is outside the advisory protocol.

For sweep inspection, each selected entry starts unclassified. It becomes removed only after recursive removal returns successfully, or skipped when the applicable lock, inspection or removal path refuses it. An inspection OSError must not discard already-recorded removals or block later entries. An attempted recursive removal can partly change a skipped entry; neither the tuple nor this model claims rollback.
