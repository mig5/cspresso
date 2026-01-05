## 0.1.3

 * Fix bug in `--evaluate` mode, which would inject the CSP into third party domains, which they would then throw violations for and trip the result

## 0.1.2

 * Add `--bypass-csp` option to ignore an existing enforcing CSP to avoid it skewing results
 * Add `--evaluate` option to test a proposed CSP without needing to install it (best to use in conjunction with --bypass-csp`)

## 0.1.1

 * Fix prog name
 * Add --ignore-non-html option to skip pages that weren't HTML (which might trigger Chromium's 'sha256-4Su6mBWzEIFnH4pAGMOuaeBrstwJN4Z3pq/s1Kn4/KQ=' hash)
 * Fix detection of Python for AppImage if it needs to install browsers via playwright

## 0.1.0

 * Initial release
