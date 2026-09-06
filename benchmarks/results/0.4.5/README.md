# 0.4.5 release preparation evidence

The Juice Shop audit passed all 12 expected status/location checks on the clean
pinned commit `5658473cf8814459bf89000ce373b20ed0b4eb37`.
It ran with bundled rules and the local timing/retry-budget changes, while the
test app still reported version 0.4.4. This is pre-release evidence, not a fresh
audit of a published 0.4.5 binary.

Duration: 659 seconds; provider attempts: 11; maximum attempts in one batch: 3
against a cap of 6. The cap was not reached, so this run does not establish its
effect on performance. Repeat-run AI consistency remains unverified.

The raw report is archived locally at `release/0.4.5/evidence/juice-shop.sarif`.
Only derived metrics and its checksum are tracked. Benchmark precision/recall
cover the manifest's scope, not every vulnerability in Juice Shop.
