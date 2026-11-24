# Candidate profile readiness

These profiles select existing commands. They are not generic whole-repo gates,
changed-file oracles or adopted integrations. No dependency setup is run by the
diagnostic wrapper. Use the target's existing pinned setup once, not an extra
install for each check. Do not reuse a fixture build without binding its actual
source/toolchain/artifact identity. Unknown cross-cutting changes use the repo's
ordinary broader check, not a guessed focused pass.

| Profile | Existing check | Required setup | Does not prove |
| --- | --- | --- | --- |
| pinto-typecheck | npm run typecheck | Node26.13.0, target locked deps | app/browser/mutation behavior |
| salutant-source | npm test | Node26.13.0, target measurement provision step | WebKit or mutation results |
| arx-web-logic | node --test scripts/web-logic.test.mjs | Node26.13.0, matching served logic source | DOM/browser/native/Reminders behavior |
| arx-web-startup | node --test scripts/browser-startup.test.mjs | Node26.13.0, matching scripts | real browser startup, Mac UI |
| tetris-delivery-unit | npm run test:delivery:unit | Node26.13.0 and target locked setup | release/browser/whole-game qualification |
| profile-typecheck | npm run typecheck | Node26.13.0 and target locked deps | Next build, browser behavior |
| site-unit | npm test | Node26.13.0 and target locked setup | Tetris publication qualification |

Candidates were read from original repo source. Before any clean-target pilot,
compare command, source pin, setup and scope to the actual approved destination.
No automated selection claims that a changed filename maps completely to tests.
Native Tetris and full Arx Mac profiles remain to be prepared on supported CI.
WebKit stays on CI. Foundry upkeep remains excluded.

## Measurement method, not results

Measure the same approved check and source before/with diagnostic capture on the
same runner/toolchain/dependency state. Keep setup, command wall time, recorder
runtime, evidence collection and queue time distinct. Include bytes and mirror
completeness. Do not compare a warm focused run to a cold whole-suite run and
attribute the difference to Litmus. Do not claim a speed improvement until it
is observed. Small command runs are sensitive to scheduling/noise; report raw
observations and enough context rather than a universal percentage.

Local wrapper synthetic tests establish no app speed or adoption. Node, browser
and Mac CI pilot results must retain their original reports and scope. Imported
historical evidence is labeled imported, not counted as a new diagnostic run.
No automatic benchmark/retry or raw CI upload is enabled by these profiles.

## Observed on private clones (Nov 24, 2026)

Local sessions on fresh clones, Node 26.13.0, no CI. Each is one observation, not a benchmark.

- salutant source-tests: exit 0, 222 tests, 5.1 s.
- soliskit.github.io unit: exit 0, 2 tests, 0.2 s.
- pinto typecheck: exit 0 after `npm ci --ignore-scripts`, 8.5 s.
- profile typecheck: exit 0 after `npm ci --ignore-scripts`, 4.1 s. The check wrote an untracked tsconfig.tsbuildinfo, and the session recorded the checkout as changed.
- tetris-js delivery-unit: exit 1 on a bare clone because `.release-evidence/release.json` was missing. After `npm ci --ignore-scripts` and `npm run build` it exited 0, 5 tests, 3.6 s. The profile needs that prerequisite stated.

Toolchain note: those sessions ran under Node 26.13.0 with npm 11.20.0. tetris-js declares `engines.npm >=12.2.0` and its workflows install npm 12.2.0. No `.npmrc` makes the engine strict, so npm only warned (EBADENGINE) and both Tetris runs used the older npm. The session records the PATH Node probe but not the npm version, so the npm version is a caller fact here, not a recorded one. Results on npm 12.2.0 were not observed.
