---
title: A synchronous infinite loop hangs Jest silently
doc_kind: note
doc_function: canonical
purpose: 'Read when a Jest run or a test file hangs with no output, especially around RSA signing with a mocked crypto.getRandomValues.'
derived_from:
  - ../engineering/testing-policy.md
status: draft
---
# A synchronous infinite loop hangs Jest silently

A test that enters a synchronous infinite loop (RSA blinding in micro-rsa-dsa-dh with a bad random source) hangs the whole Jest run: no per-test timeout fires and nothing is printed. Each test passed in isolation while the full `review6.test.ts` hung. The cause was one test (`-t "only the first"`) whose source passed the probe once.

To find such a test, run each `describe` with `-t` under a watchdog. On macOS there is no `timeout` command; use a background job and `kill`:

```sh
( npx jest FILE -t "NAME" > /tmp/x.log 2>&1 & pid=$!; for i in $(seq 1 30); do sleep 1; kill -0 $pid 2>/dev/null || break; done; kill -0 $pid 2>/dev/null && { kill $pid; echo HANG; } )
```

Found on 2026-10-17, third review round.
