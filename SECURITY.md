# Security policy

> DRAFT. The response targets below are proposals awaiting founder approval (FOUNDER_TASKS F-14).

## Reporting a vulnerability

Email **security@mnemowall.com**, or use GitHub's **private vulnerability reporting** on this repository (Security tab → "Report a vulnerability").

Please do not open public issues for vulnerabilities.

Include affected versions, a description, reproduction steps and the impact you expect. Do not include real personal data or real memory contents from production systems.

## What to expect (proposed targets)

| Step | Target |
|---|---|
| Acknowledge receipt | 3 business days |
| Initial triage and severity | 7 calendar days |
| Fix or mitigation, critical/high | 30 days |
| Fix or mitigation, medium/low | 90 days |

We coordinate disclosure with the reporter. We credit reporters who want credit.

## Supported versions

Pre-release (0.x): only the latest release receives security fixes.

## Scope

**In scope:**
- the `mnemowall` Python package;
- the red-team pack;
- the gate service and adapters in this repository.

**Out of scope:**
- vulnerabilities in the memory backends or frameworks we wrap. Report those upstream; we're glad to help coordinate.

## EU Cyber Resilience Act

For actively exploited vulnerabilities and severe incidents, we intend to meet the reporting obligations of Regulation (EU) 2024/2847 through the ENISA single reporting platform. Counsel has not yet confirmed how those obligations apply to us.

## Note on guarantees

Mnemowall reduces the risk of memory poisoning. It does not eliminate it. Read-time wrapping and detectors are risk reductions, not guarantees.

## Known limitation: in-process signing key (M1a)

In 0.x, memory versions are signed inside the process that runs the Mnemowall SDK, with a key from the OS keychain or a local key file. **If your agent can execute code in that process (a code-interpreter or shell tool), it can read the signing key and produce valid signatures.** In that setup, a valid signature shows only that a version was written through a process holding the key, not that Mnemowall's policy approved it. A separate signer process, keeping the key out of the agent's process, is planned for the gate (M2). `mnemowall keys status` prints this note.
