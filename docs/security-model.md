# Security Model

This document describes the security model of the Apache Teaclave™ dependency
crates repository (`teaclave-crates`). It has two audiences:

1. **Developers** who depend on these `teaclave-*` crates when building SGX
   enclaves or TrustZone Trusted Applications, and **maintainers** who port and
   adapt crates here.
2. **Automated reviewers (including LLM-based audit agents)**, who need an
   explicit statement of what is being trusted, what the review unit is, and
   where the security-critical seams live — so that findings are calibrated and
   effort is not wasted re-auditing unmodified upstream code.

This repository is **not an application** and does not itself contain a
trust boundary (there is no ECALL/OCALL edge or Normal/Secure-world split here).
Instead it hosts the **dependencies that are linked into the trusted side** of
TEE applications built with the
[Teaclave SGX SDK](https://github.com/apache/teaclave-sgx-sdk) and the
[Teaclave TrustZone SDK](https://github.com/apache/teaclave-trustzone-sdk).
Its security model is therefore about **what gets pulled into someone else's
Trusted Computing Base**, and about **provenance** — the integrity of the port
relative to its upstream.

---

## 1. Trust model: this repository is TCB

Every crate published from this repository is intended to be **linked into the
trusted side of a TEE application** — inside an SGX enclave or a TrustZone TA.

The consequence is blunt:

> **There is no privilege separation between these crates and the secrets of the
> enclave/TA that links them.** A bug or backdoor in any crate here executes
> inside the TEE, with access to keys, sealing/attestation material, and
> plaintext data. A single weakness propagates to **every downstream application
> that depends on the affected `teaclave-*` crate.**

So the unit of trust is the whole repository. Unlike the SDK repositories — where
the security story is "validate untrusted input at the boundary" — here the story
is **"do not let the port weaken, or drift away from, the security properties the
upstream crate provides, and do not let anything untrusted enter the TCB through
the supply chain."**

### Adversary

The adversary is inherited from the downstream SDK and is the same untrusted
world those SDKs assume:

- For **SGX** consumers: the untrusted host (OS, hypervisor, host app) controls
  all OCALL results and untrusted memory.
- For **TrustZone** consumers: the Normal World (rich OS, root) controls all
  parameters and shared memory crossing into the TA.

In addition, this repository faces a **supply-chain adversary**: anyone able to
influence the ported source, a patch, a pinned upstream snapshot, a build script,
or a prebuilt binary artifact can compromise every consumer.

### What is trusted vs. relied-upon

- **Trusted (must be correct):** the entire ported crate source, every patch, the
  build scripts, and any prebuilt artifacts that end up in the enclave/TA binary.
- **Relied-upon (provenance):** that the pinned upstream snapshot is authentic,
  that the published `teaclave-*` artifact on crates.io matches this repository,
  and that upstream security fixes are tracked and re-ported.

### Out of scope

The platform-level threats are out of scope here exactly as in the SDKs:
microarchitectural / speculative side channels, availability/DoS, and rollback
of data persisted outside the TEE. A finding that depends only on those is not a
bug in this repository.

---

## 2. What this repository is, and what the review unit is

Per the README, crates are hosted in one of two ways, and this determines what an
auditor must actually look at:

1. **Patch-bundle approach** — a pinned upstream snapshot plus Teaclave/TEE
   adaptation patches kept in-tree. Examples:
   - `libc-0.2.182-e879ee9/optee-0001-libc-adaptation.patch`
     (`Base-Commit: e879ee90…`)
   - `rust-1.93.1-01f6ddf/optee-0001-std-adaptation.patch`
     (`Base-Commit: 01f6ddf7…`) — this patches the **Rust standard library**
     itself for the OP-TEE target.
2. **Full crate import** — the adapted crate source is copied in directly.
   Examples: `ring-0.17.14/`, `getrandom-0.2.16/`. By convention the commit
   history makes the adaptation diffable: a `Download <crate> <version> from
   crates.io` commit imports the **pristine upstream source** (including
   `.cargo_vcs_info.json`, which records the upstream revision for provenance),
   and the following commit(s) apply the TEE port.

Crates are published to crates.io under the `teaclave-*` namespace (e.g. an
adaptation of `ring` is published as `teaclave-ring`) so downstream code can
depend on them with ordinary Cargo syntax. The repository keeps **only the latest
ported version** of each crate.

**The review unit is the diff from upstream, not the whole crate.** The README
states it directly: *"Each crate undergoes a security review focused on diffs
from the upstream."* The overwhelming majority of bytes in `ring-0.17.14/` or the
std snapshot are unmodified upstream code that has already been reviewed by the
upstream community. The security-relevant change is:

- for a **patch bundle**: the `.patch` file (and confirming the `Base-Commit`
  snapshot is authentic);
- for a **full import**: the delta against the pristine upstream source, which
  the repository preserves as the `Download ... from crates.io` commit — i.e.
  `git diff <download-commit> HEAD -- <crate-dir>/` (cross-check
  `.cargo_vcs_info.json` against the upstream release for provenance).

---

## 3. Trust-posture / what-to-scrutinize map

Every path here is TCB. The table instead points to **what each port adapts** and
**the security-critical seam** an auditor should focus on.

| Path | Upstream | What it adapts for TEE | Security-critical seam |
|---|---|---|---|
| `getrandom-0.2.16/` | `getrandom` | The **randomness source**. Adds TEE backends — `src/optee.rs` (OP-TEE) alongside `src/rdrand.rs` (used under SGX). | Entropy **must** come from a hardware/TEE RNG (`RDRAND`/`sgx_read_rand`, OP-TEE TRNG) — **never** from an untrusted-host or predictable source. This is the single most security-sensitive primitive in the repo: a weak `getrandom` silently undermines every key and nonce generated in the TEE. |
| `libc-0.2.182-e879ee9/` | `libc` | Adds the `optee` target (`target_os = "optee"`) and a new `src/optee/mod.rs` syscall surface. | libc calls route to the TEE OS / untrusted world. Results crossing back (return values, `errno`, buffers) are **untrusted** and must not be trusted by callers for security decisions. Review the added syscall declarations for correctness and for anything that leaks or trusts host data. |
| `rust-1.93.1-01f6ddf/` | Rust `std` / compiler | Adds OP-TEE target specs and adapts **`std`** (`library/std`) for the target. | `std` is in the TCB. Scrutinize adapted `fs`, `time`, `env`, `net`, `thread`, panic/abort, and allocation paths — anything that reaches an untrusted service or changes a security-relevant default. A `std` weakness affects *all* TrustZone std TAs. |
| `ring-0.17.14/` | `ring` | Full import of the crypto crate adapted to build for the TEE target. | Crypto primitives are TCB. Note the **prebuilt binary artifacts** under `pregenerated/` (`.S`, `.asm`, and even a checked-in `.o` object) and the ~1000-line `build.rs` — these are TCB code that is *not* easily source-reviewable and run/link at build time. Confirm they correspond to the asm sources and the named upstream. |

When new crates are added, classify each the same way: *what upstream security
primitive does this port touch, and does the adaptation preserve or weaken it?*

---

## 4. Target-dependent security primitives (the heart of the audit)

The README frames the repository's purpose as "Adapting With Target-Dependent
Security Primitives." These are precisely the seams where a port can go wrong,
because the upstream implementation assumed a normal OS and the TEE port must
substitute a different mechanism:

- **Randomness.** Must be sourced from the TEE/hardware RNG. A port that falls
  back to a host syscall, `/dev/urandom` via an untrusted FS, a fixed seed, or a
  non-CSPRNG is a critical vulnerability. (`getrandom` backends.)
- **Filesystem / persistence.** The host filesystem is untrusted. A port must not
  treat file contents as trusted, and must not silently weaken confidentiality
  or integrity expected by callers.
- **Time and clocks.** Time obtained from the untrusted world is attacker-
  controlled; it must not be used as a security oracle (e.g. for certificate
  expiry or token freshness) without an authenticated source.
- **Syscalls / libc surface.** Each syscall added for the TEE target crosses into
  the untrusted world; return values and buffers are untrusted input.
- **Panic / abort behaviour.** In a TEE, an unwinding/panic path that leaks state
  to the untrusted side, or that fails open, is a security concern.

For each of these, the auditor's question is the same: **does the TEE adaptation
preserve the security property the upstream crate guarantees on a normal OS, or
does it weaken it?**

---

## 5. Supply chain and provenance

Because the whole repository is TCB and is consumed as binary `teaclave-*`
packages by other projects, provenance is a first-class security property here —
arguably *the* security property.

- **Diff integrity.** For a patch bundle, the security depends on the pinned
  `Base-Commit` snapshot being authentic and the patch being exactly what was
  reviewed. Verify the upstream commit hash; do not review the patch against an
  unverified tree.
- **Upstream-fix drift.** The repository holds only the latest ported version.
  When upstream issues a security fix (e.g. a RUSTSEC advisory for `ring`,
  `libc`, or `getrandom`, or a Rust `std` soundness fix), the port must be
  re-based and re-published. **Stale ports silently retain fixed
  vulnerabilities** — check the ported version against the latest upstream
  advisories.
- **Binary artifacts in the TCB.** Prebuilt objects and assembly (e.g.
  `ring-0.17.14/pregenerated/*.o` / `*.S` / `*.asm`) and build scripts execute
  or link into the enclave/TA and cannot be fully source-reviewed. Treat them as
  high-trust artifacts: confirm they match their asm sources and the upstream
  release, and flag any that cannot be reproduced from source.
- **Build-time code execution.** `build.rs` and proc-macros run on the build/CI
  host and determine the binary that is measured (`MRENCLAVE`) or signed (TA).
  The build host and CI are part of the trust chain.
- **Publish provenance.** The `teaclave-*` artifact a downstream project pulls
  from crates.io must correspond to the reviewed source in this repository.
  A mismatch between the published crate and this repo is a supply-chain break.

### Recommendations

- Record and verify the **upstream version / `Base-Commit`** for every crate, and
  keep the adaptation diff minimal and reviewable.
- Track **RUSTSEC advisories** for every upstream and re-port promptly; consider
  `cargo audit` / `cargo deny` in CI.
- Prefer **reproducible-from-source** artifacts over checked-in binaries; where a
  prebuilt artifact is unavoidable, document how to regenerate and verify it.
- Ensure the **published `teaclave-*` crate is built from this repository** with
  a verifiable trail.

---

## 6. Guidance for automated / LLM security review

> **Note to the reviewing agent:** Treat **everything in this repository as
> Trusted Computing Base** — it is linked into downstream enclaves/TAs. But
> **review the *diff from upstream*, not the entire vendored crate.** The bulk of
> a full import (e.g. `ring-0.17.14/`) or the std snapshot is unmodified,
> already-reviewed upstream code; auditing it line-by-line as if it were
> first-party is wasted effort and produces false positives. Identify the change
> set first:
> - For a **patch bundle**, read the `.patch` file and the `Base-Commit` it
>   targets; the patch *is* the review.
> - For a **full import**, diff the TEE port against the pristine upstream the
>   repo preserves in its own history — the `Download <crate> <version> from
>   crates.io` commit: `git diff <download-commit> HEAD -- <crate-dir>/`. Review
>   only that delta plus the build-time and binary artifacts, and cross-check
>   `.cargo_vcs_info.json` against the upstream release.
> If you cannot obtain the upstream baseline to diff against, say so explicitly
> and treat the port as unreviewed rather than assuming it matches upstream.

To keep findings high-signal:

**Where real findings concentrate**
- The **randomness path** (`getrandom` backends): is entropy sourced from a
  TEE/hardware RNG, never from an untrusted or predictable source?
- The **adapted syscall / libc surface** and any `std` path that reaches an
  untrusted service (fs, time, env, net): does the port trust untrusted return
  values it shouldn't?
- **Weakened security properties** in the diff: a removed check, a relaxed
  default, a stubbed-out verification, a `cfg`-gated branch that behaves
  differently on the TEE target.
- **Upstream-fix drift:** the ported version lagging a known upstream security
  fix (RUSTSEC / Rust std soundness).
- **Build-time and binary artifacts:** `build.rs`, proc-macros, and prebuilt
  objects/assembly that enter the TCB and can't be source-reviewed.

**Expected non-findings (avoid these false positives)**
- Reporting bugs in **unmodified upstream code** as if they were introduced here.
  If the line is identical to upstream, it is out of scope for this repository's
  review (report it upstream instead).
- Treating ordinary, unchanged upstream `unsafe`/FFI as a new finding.
- Platform-level issues outside the TEE threat model (side channels, speculative
  execution, availability) attributed to a port.

**Before reporting**, state whether the code is **part of the adaptation diff or
unmodified upstream**, and which target-dependent security primitive (§4) or
supply-chain property (§5) the issue affects. If a finding is in unmodified
upstream code, it is almost certainly out of scope here.

---

## 7. Reporting vulnerabilities

Security issues should be reported privately first, per
[`SECURITY.md`](../SECURITY.md), before any public disclosure. Vulnerabilities
that originate in unmodified upstream code should additionally be reported to the
upstream project.
