# v0.4.6 benchmark evidence

This result uses the revised Juice Shop triage contract
`benchmarks/juice-shop-triage-v2.json`. The original v19 contract remains
unchanged and its historical scores remain valid for that contract.

The pinned Juice Shop checkout is commit
`5658473cf8814459bf89000ce373b20ed0b4eb37`, and the exported SARIF is the
user-provided report `juice.sarif` with SHA-256
`39ec9a5e0e27f1337052376f00f5e2792f33426e2cc951f206b60bd39581791b`.

The revised contract passed: 12/12 expected verdicts, precision 1.0, recall
1.0, 3 unresolved findings (the guarded traversal candidates plus the existing
check-then-use candidate), and no unexpected or forbidden findings. The report
completed successfully on a clean checkout with no runtime scan gaps.

The two path-traversal candidates are expected as `NEEDS_REVIEW` under this
contract because the handler-level evidence found no escape for the tested
inputs. This is a verdict-contract result, not a claim of universal safety or
an HTTP deployment exploitability result. See
`benchmarks/reviews/juice-shop-path-traversal.md` and its JSON trace.
