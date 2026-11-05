# mnemowall

A firewall plus version control for AI agent memory. **Pre-release: nothing usable yet.**

Mnemowall records provenance on every memory write, applies a write policy (untrusted content can never become a standing instruction), wraps low-trust memories on read, and versions every memory so you can see who read a bad version and roll it back.

Wrapping and detection *reduce* risk; they are not guarantees.

Licensed under Apache-2.0. Report vulnerabilities to security@mnemowall.com (see SECURITY.md).
