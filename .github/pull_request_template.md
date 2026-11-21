# Pull Request

A checklist for change class, behavior, and safeguards.

## What this changes

<!-- Complete this description: replace the four question prompts with answers after their bold labels. Select all applicable classes; do not combine No Class Needed with another class. The guarantees these classes refer to live in docs/qualification-contract.txt and docs/run-receipt-contract.txt. -->


## Class

* [ ] **Refactor:** tool code changes, behavior does not. Contract entries are unchanged and the gates pass; checks change only to follow renamed or moved code.
* [ ] **Bug Fix:** tool code is brought back in line with an existing contract entry. Which entry, and which check failed before the fix?
* [ ] **Intentional Change:** behavior is added, changed or removed. Which contract entries changed in the same commit, and which checks now check them?
* [ ] **Clarification:** contract entries now describe behavior the tools already have. Which entries, and which checks check them?
* [ ] **No Class Needed:** no tool code (`*.py` at the repo root) and no contract entries change. The review questions still apply.

## Review questions

* **Behavior:** does this change what the tools accept, record, publish or verify? If so, which contract entries changed in the same commit?
* **Protection:** does this loosen, remove or move a runtime check, or a check that proves one works? If so, which contract change allows it and what replaces it, or which check proves the same input still gets the same outcome at the same boundary? Types don't count.
* **Gates:** does this lower or remove the existing check, review, privacy or zero-cost gates? That is not allowed.
* **Description:** is any new behavior described by a contract entry and a check? Behavior that isn't has no guarantee.
