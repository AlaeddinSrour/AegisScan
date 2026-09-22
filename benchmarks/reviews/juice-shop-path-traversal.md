# Juice Shop path-traversal adjudication — 2026-09-18

Status: existing CONFIRMED expectations require review. Do not add automatic
confirmation merely to satisfy the benchmark.

Repository: `5658473cf8814459bf89000ce373b20ed0b4eb37` (clean local checkout).
Audit preserved at `release/0.4.6/evidence/juice-shop-e13703d4b35b.sarif`.

## Observed source evidence

- `routes/vulnCodeFixes.ts:70–81`: request body key passes through `readFixes`;
  the metadata read is in the branch where `fixData.fixes.length` is nonzero.
- `routes/vulnCodeFixes.ts:20–45`: `readFixes` enumerates a fixed directory and
  accepts filenames starting with `${key}_`. The cache is populated from those
  results. A normal string key containing a directory separator cannot match a
  basename returned by this enumeration. The existence check alone would not
  stop traversal; the preceding file-selection condition matters.
- `routes/vulnCodeSnippet.ts:34–40`: `retrieveCodeSnippet` returns a value only
  when the key is present in the map from `getCodeChallenges`.
- `routes/vulnCodeSnippet.ts:69–90`: null results and thrown errors return before
  the metadata read. The path uses the same request key.
- `lib/codingChallenges.ts`: map keys are derived from snippet markers in local
  repository files, not directly inserted from the request.

A read-only inventory found 161 regular files in the codefixes directory and
no basename containing slash or backslash. A bounded inventory of source
markers in routes, lib, data, frontend/src/app, models, and infrastructure found
22 distinct keys and no slash, backslash, or `..` in those keys. This inventory
is supporting evidence, not an exhaustive runtime execution test.

## Interpretation and limits

Raw request-to-file concatenation is present, but a taint match alone does not
prove traversal past the preceding helper checks. The latest Needs review
verdicts are defensible. Earlier CONFIRMED labels and the benchmark manifest
are not independent proof of exploitability.

Handler-level execution tests are now recorded below. Mutable repository files,
HTTP middleware behavior, filesystem races, global prototype pollution, and
deployment modifications remain outside their scope.
Do not turn these observations into a broad false-positive suppression rule.

## Handler execution results

Harness: `scripts/juice_shop_path_traversal_harness.mjs`.
Evidence: `benchmarks/reviews/juice-shop-path-traversal-results.json`.
Reproduction (Node 26.7.0 used for the recorded run):

```sh
node --experimental-strip-types --experimental-test-module-mocks \
  scripts/juice_shop_path_traversal_harness.mjs /path/to/pinned/juice-shop
```

The original TypeScript handlers execute directly, including original
`readFixes`, `retrieveCodeSnippet`, and `getCodeChallenges`. The actual map
builder found 35 challenge keys with no path separators or `..`; this supersedes
the earlier, partial 22-key static inventory. The map is built before request
tests, so its source discovery reads are explicitly excluded from request-time
metadata-read assertions. No claim of a cold-map request test is made.

Twenty-eight inputs run in two passes through both complete handlers: 112
handler invocations. Valid requests bracket malformed/traversal inputs. The
second pass reuses caches populated in the first pass. Inputs cover raw,
encoded, double-encoded, absolute, null-byte, mixed and repeated separator
paths, prototype property names, numbers, booleans, null, arrays, and objects.
These are direct handler inputs, not HTTP requests: JSON body keys are not
automatically percent-decoded by this harness.

Results:

- No tested handler read escaped `data/static/codefixes`.
- Valid keys returned 200 and reached expected metadata reads. A singleton
  array containing a valid key was coerced to the same safe key by `readFixes`;
  the snippet map rejected that array by exact Map membership.
- Independent vulnerable and guarded controls exercised a real harmless
  sentinel outside a temporary allowed directory. The trace detected the
  vulnerable read, the guarded implementation blocked it, and a valid guarded
  read succeeded.
- Twelve fixes-handler invocations threw TypeError: five inherited cache-key
  names plus an object with a non-callable `toString`, each in two passes.
  These never reached a file read. They are separate handler robustness
  observations, not evidence of traversal or whole-process denial of service.
  A null response status in the JSON means the handler threw before responding.
- The snippet handler caught the non-callable-toString error and returned an
  error body with status 200; other unknown keys returned 404.
- Git status remained clean before and after execution. Source hashes, harness
  hash, actual commit, runtime version, response bodies, and call traces are saved.

The YAML parser, logging, accuracy persistence, challenge-completion side
effects, error formatter, and HTTP response object are stubbed. No auth,
network stack, deployment behavior, malicious filesystem mutation, or complete
application integration is evaluated. This is executable evidence supporting
the guards under the pinned source state, not universal proof of safety.

## Adjudication recommendation

The two unconditional CONFIRMED traversal expectations are unsupported under
the tested conditions. Treat these as guarded negative controls for ordinary
JSON request inputs and an unchanged repository, or retain Needs review while
the broader claim is unresolved. Do not claim that a 10/12 result means two
demonstrated exploitable traversals were missed.

Any benchmark revision must state this scope, version its expectations, and
keep old SARIF files and scores intact. Independent unguarded traversal
fixtures should continue to test positive detection. The handler robustness
issue should be tracked separately from these path-traversal candidates.

No scanner rule, expected finding, or benchmark gate was changed by this review.
