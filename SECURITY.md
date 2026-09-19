# Security Policy

## Supported version

Security fixes are applied to the current `main` branch and the deployment built
from it. Historical commits and forks are not supported release lines.

## Reporting a vulnerability

Please use [GitHub private vulnerability reporting](https://github.com/systemslibrarian/crypto-lab-kyber-vault/security/advisories/new).
Do not disclose a suspected vulnerability in a public issue, discussion, pull
request, or social post before a fix is available.

Include, when possible:

- the affected commit, URL, browser, and operating system;
- a minimal reproduction or proof of concept;
- the security impact and required attacker capabilities;
- whether the issue affects the educational UI, build/deployment chain, or
  cryptographic behavior; and
- any suggested remediation or disclosure constraints.

The maintainer will aim to acknowledge a complete report within 7 days, provide
an initial assessment within 14 days, and coordinate a fix and disclosure based
on severity. These are response targets, not a service-level agreement or bug
bounty promise.

## Scope

In scope are vulnerabilities introduced by this repository, including unsafe
cryptographic composition, incorrect security claims, leakage of generated
secrets, cross-site scripting, dependency or workflow compromise, and
deployment-integrity failures.

Upstream defects in browsers, GitHub Pages, or `@noble/post-quantum` should also
be reported to the relevant upstream project. If this demo makes an upstream
defect exploitable, please report it privately here as well so the integration
can be mitigated.

This is an educational demo, not a production cryptographic service. Its known
and residual risks are documented in [KNOWN-LIMITATIONS.md](./KNOWN-LIMITATIONS.md)
and [THREAT-MODEL.md](./THREAT-MODEL.md).
