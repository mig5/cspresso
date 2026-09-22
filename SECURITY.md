# Security and threat model

CSPresso executes website code in Chromium. It is a local developer/CI tool for
sites the operator is authorized to inspect, not a hardened public URL-scanning
service or proof that a site is free from XSS.

## Two different protection layers

Chromium's process sandbox isolates browser processes from the host. It is
now enabled by default and does not prevent ordinary CSP resource discovery.
A failed sandbox launch must be fixed through the account/OS configuration; the
application never silently disables it.

CSP is a document-level restriction. `--bypass-csp` removes existing same-origin
HTML response headers so that discovery can observe otherwise blocked loads.
It does not remove meta CSP or turn off the Chromium sandbox. Remaining meta
CSP is disclosed and prevents a clean evaluation result.

The public [security notes](https://cspresso.cafe/security.html) correctly warn
that bypassing CSP may enable previously blocked injected code. That warning
still applies with Chromium sandboxing enabled. Use disposable isolation when
content is not trusted. `--no-sandbox` is only an explicit compatibility option
for suitably isolated, trusted workloads.

## Assets and trust boundaries

| Asset/boundary | Risk | Controls and remaining responsibility |
| --- | --- | --- |
| Host files, CI credentials and process privileges | Malicious content may exploit a browser vulnerability. | Browser sandbox enabled; fresh non-persistent context; run non-root with no sensitive mounts/credentials. Keep browser dependencies updated. |
| Runner network access | Pages/subresources can contact internal services, loopback or link-local addresses. | Top-level crawl scope is enforced, but is not an egress firewall. Apply network policy outside the process if required, covering DNS, redirects, IPv4/IPv6 and API fetches. Private development targets remain supported. |
| Target application state | JavaScript can POST or invoke state-changing GET endpoints. | Scan staging/test accounts where possible. Exclusions reduce navigation scope but do not make a scan read-only. Non-GET redirects are not replayed. |
| Policy output | Compromised content can cause dangerous permissions to be suggested. | URL/token validation prevents metadata becoming CSP syntax. Source maps are metadata only. Permission provenance is reported. Human review is still essential; hashes can authorize malicious observed code. |
| Evaluation result | Skipped injection or incomplete coverage can look like a pass. | Explicit document injection checks, scoped structured reports, syntax diagnostics and exit 2 for incomplete/error. Page budgets still define finite coverage. A hostile page is not a trusted witness. |
| Executable cache | Another local user could substitute a browser or abuse a predictable write probe. | Verified private cache paths, no shared temporary fallback, no predictable probe, and OS locks released after process death. Administrators and same-account attackers remain outside this protection boundary. |
| Resources | Hostile pages can consume CPU, memory, bandwidth and disk. | Time/request/observation bounds, disclosed truncation and disabled accepted downloads. Apply process/container memory and network quotas: response buffering and browser allocations are not fully bounded here. |
| Reports | URLs and violation records may expose query tokens, paths or internal hosts. | Restrict report access and retention. Terminal controls are escaped, but URL-secret redaction is not automatic. |
| Installation/build dependencies | Package, browser or CI-action compromise can execute code. | Lock/review dependencies, verify releases, use disposable runners and narrowly scoped publishing credentials. Runtime protections do not establish supply-chain trust. |

Actors include a compromised target, a malicious third-party script/widget
provider, a local user who can write shared directories, and compromised
installation/build dependencies. They have different prerequisites: a website
cannot normally create a symlink in a private host cache, and disabling CSP is
not by itself a demonstrated host compromise.

CSPresso uses subprocess argument arrays, not shell interpolation of page input.
It does not load your normal browser profile or import authentication cookies.
Browsers start with a fresh context; cookies set during the scan still exist
within that scan and can affect later pages.

## Evaluation and discovery limitations

- A successful evaluation means no candidate violations were observed during
  completed selected coverage. It is not a complete security or functional test.
- Report-only policies do not reproduce every consequence of enforcement.
  Exercise forms, embedding, login states and actual interactions separately.
- Service workers are blocked to avoid invisible interception paths. Worker-
  dependent behavior needs a separate test. Some worker/data/shadow-DOM loads
  are outside current collection coverage.
- Same-origin and inherited-policy frames contribute to the policy; foreign
  frame subresources do not. Ambiguous WebSocket ownership is reported as
  incomplete instead of broadening permissions speculatively.
- Redirect hops are fetched without automatic following, then GET destinations
  are navigated explicitly at their actual URLs. This preserves origin/base-URL
  interpretation but changes timing/history and can trigger an aborted-load
  event at the old URL. Late redirects are marked incomplete. Test redirect-
  sensitive application flows independently.
- Console messages authored by a page are not trusted as policy violations.
  Candidate/frame checks reduce contamination, but a compromised page may
  manipulate its DOM or exposed instrumentation; this is not a tamper-proof
  verifier.

For untrusted scans, use a non-root disposable environment, the Chromium
sandbox, minimal filesystem access, network egress restrictions appropriate to
the target, and external resource limits. Never automatically deploy a generated
policy merely because the scan exited successfully.

## References

- [Playwright launch sandbox option](https://playwright.dev/python/docs/api/class-browsertype#browser-type-launch)
- [Playwright guidance for untrusted crawling](https://playwright.dev/python/docs/docker)
- [Routing, redirects and service workers](https://playwright.dev/python/docs/api/class-browsercontext#browser-context-route)
- [Content Security Policy specification](https://www.w3.org/TR/CSP3/)
