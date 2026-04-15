# Security policy

## Audit status

**`ark-piop` has not undergone an independent security audit.** It is
research-grade code. Do not use it to secure funds, identity, or other
high-value assets without first commissioning an audit.

## Reporting a vulnerability

If you believe you have found a soundness or safety issue in `ark-piop`,
**please do not open a public GitHub issue**. Instead, email the
maintainer(s) directly with:

- A clear description of the vulnerability.
- Steps to reproduce, including a minimal test case if possible.
- The version (commit hash) of `ark-piop` you tested against.

We will acknowledge your report within a reasonable time frame and
coordinate a fix and disclosure timeline with you.

## Scope

The following kinds of issues are in scope for this policy:

- **Soundness:** a prover can produce a proof that a false claim holds
  and the verifier accepts it.
- **Completeness:** an honest prover's proof is rejected by the verifier
  for a true claim.
- **Panics on attacker-controlled input:** the verifier panics on a
  malformed proof rather than returning an error.
- **Memory safety:** any `unsafe` code path that can be reached with
  attacker-controlled input.

The following are out of scope:

- Performance regressions.
- Feature requests.
- API ergonomics.
- Bugs in downstream crates that depend on `ark-piop`.

## Known limitations

- No independent audit has been performed.
- The Fiat-Shamir transcript uses Merlin, which is well-studied but
  has not been formally verified for this specific protocol usage.
- The framework relies on the security of its polynomial commitment
  schemes (`kzg10`, `pst13`) which in turn depend on the trusted setup
  (SRS) being generated honestly.
