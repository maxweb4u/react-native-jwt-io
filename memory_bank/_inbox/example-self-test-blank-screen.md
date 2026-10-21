---
title: The example self-test shows a blank screen while it runs
doc_kind: note
doc_function: canonical
purpose: 'Read before checking example/ on the Android phone from the command line, when the screen or a uiautomator dump comes back empty right after launch.'
derived_from:
  - ../ops/development.md
status: draft
---
# The example self-test shows a blank screen while it runs

The self-test in `example/` runs synchronously on the JS thread at launch and renders nothing until every check is done. On the Realme RMX3363, Release build, that takes about six seconds: RS256 and PS256–512 each sign in about 0.85 s. Until then a screenshot shows an empty white screen, a `uiautomator dump` has no text, and logcat shows no JS output. This is not a crash.

To read the result without looking at the phone, poll the dump until the text `Self-test N/N passed` (or `failed`) appears:

```sh
adb shell am force-stop com.jwtexample && adb shell am start -n com.jwtexample/.MainActivity
adb shell "uiautomator dump /sdcard/ui.xml >/dev/null; cat /sdcard/ui.xml" | grep -o 'text="[^"]*"'
```

The phone shows up on USB (`system_profiler SPUSBDataType`) before `adb devices` lists it. It is listed only after USB debugging is enabled and the computer is allowed on the phone.
