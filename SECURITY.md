# Security Policy

## Security Model

This repository hosts dependency crates that are linked into the **trusted side**
of TEE applications, so the entire repository is part of the Trusted Computing
Base of its consumers. For the trust model, what the review unit is (the diff
from upstream), the target-dependent security primitives, supply-chain /
provenance considerations, and guidance for developers and automated security
reviewers, see [docs/security-model.md](docs/security-model.md).

## Reporting a Vulnerability

We take a very active stance in eliminating security problems in Teaclave. We
strongly encourage folks to report such problems to our private mailing list
first ([private@teaclave.apache.org](mailto:private@teaclave.apache.org)),
before disclosing them in a public forum.
