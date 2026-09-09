# solana-ed25519-program: on-chain signature verification for Solana

A minimal Solana SBF program that re-verifies Ed25519 signatures on-chain using
the Curve25519 and SHA-512 syscalls.

## Motivation

The goal is to migrate the native [ed25519 precompile] to SBF so it can be
maintained and deployed like any other on-chain program. The instruction format
is intentionally identical to the precompile for current-instruction data, so
clients can reuse the standard Ed25519 instruction layout.

Being a regular SBF program also unlocks CPI: another program can invoke this
one and act on the explicit pass/fail result, rather than relying on
`sysvar::instructions` inspection to confirm a parallel precompile instruction
succeeded.

[ed25519 precompile]: https://docs.solanalabs.com/runtime/programs#ed25519-program

## Syscalls used

| Syscall                     | Wrapper or entry point                                                                              |
| --------------------------- | --------------------------------------------------------------------------------------------------- |
| `sol_sha512`                | `solana_sha512_hasher::hashv`                                                                       |
| `sol_curve_group_op`        | `solana_curve25519::edwards::{add_edwards, subtract_edwards}`                                       |
| `sol_curve_multiscalar_mul` | Fixed two-term wrapper using `solana_define_syscall::definitions::sol_curve_multiscalar_mul` on SBF |

`sol_sha512` is not live on mainnet yet. The wrapper crate is published as
`solana-sha512-hasher`, and a local/custom VM must enable the SHA-512 syscall
feature before SBF execution will work.

## Instruction format

The program verifies a single signature. Instruction data is:

```text
[0 .. 32]     public key A (32 bytes)
[32 .. 96]    signature R‖S (64 bytes)
[96 ..]       message
```

The `verify` helper in `solana-ed25519-verify` builds this layout. The crate
also declares the program's canonical on-chain address via `declare_id!`,
exposed as `ID` and `id()`:

```rust
use solana_ed25519_verify::{verify, ID};

let instruction = verify(&ID, &public_key, &signature, message);
```

### Constraints

- **Verification criteria.** The program always applies [ZIP-215]: the
  cofactored equation `[8](S·B − H(R‖A‖M)·A − R) == identity`.
  Small-order and non-canonical points are accepted. Programs needing a
  different variant (e.g. `verify_strict`) should depend on the
  `solana-ed25519-verify` library directly (see
  [Verification criteria](#verification-criteria-library)).
- **No accounts.** The program takes no account arguments and returns
  `InvalidArgument` if any are supplied.
- **Minimum length.** Instruction data shorter than the 96-byte
  `A || R‖S` header is rejected with `InvalidInstructionData`.
- **Error surface.** Every signature-verification failure — malformed
  encoding, a small-order or non-canonical rejection, or a signature that
  simply doesn't verify — surfaces uniformly as `InvalidInstructionData`,
  regardless of the underlying cause. Callers needing to distinguish failure
  reasons should depend on `solana-ed25519-verify` directly and inspect the
  [`Ed25519VerifyError`](#error-handling-library) returned by
  `Ed25519Verifier::verify_signature`.

[ZIP-215]: https://zips.z.cash/zip-0215

## Verification criteria (library)

Ed25519 "validity" is not one definition — implementations differ on cofactoring,
non-canonical encodings, and small-order rejection (see Henry de Valence's
[It's 255:19AM]). The `solana-ed25519-verify` crate exposes these as independent
knobs via `VerificationCriteria`:

| Knob                   | Effect when enabled                                                                          | Extra curve syscalls                            |
| ---------------------- | -------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| `cofactored`           | Use `[8](S·B − H·A − R) == identity` instead of the cofactorless `S·B − H·A − R == identity` | none; torsion lookup on the fallback difference |
| `require_canonical_a`  | Reject public keys whose `y`-coordinate is `≥ p`                                             | none                                            |
| `require_canonical_r`  | Reject signature `R` whose `y`-coordinate is `≥ p`                                           | none                                            |
| `reject_small_order_a` | Reject small-order (torsion) public keys                                                     | +1 addition (473 CU), plus a torsion lookup     |
| `reject_small_order_r` | Reject small-order signature `R` values                                                      | +1 addition (473 CU), plus a torsion lookup     |

The verifier first compares the computed point encoding with `R`. If they differ,
it subtracts `R` and checks the resulting point. The cofactored profile tests this
canonical difference against the torsion encodings, replacing three doublings
with a lookup. This lookup is skipped when the initial comparison succeeds.

Each small-order input check adds the identity to validate the input and produce
a canonical encoding before the lookup. This preserves support for valid
non-canonical encodings and rejects inputs that do not decompress. The 473 CU
figure above is the addition syscall charge in the benchmark runtime; the total
check also includes the surrounding SBF instructions.

Canonical `S` (`S < L`) has no knob. Every profile worth targeting requires it â€”
accepting `S ≥ L` reintroduces signature malleability and
`sol_curve_multiscalar_mul` enforces it regardless, converting scalars through
`Scalar::from_canonical_bytes` and rejecting out-of-range values before any group
operation runs.

```rust
use solana_ed25519_verify::{Ed25519Verifier, VerificationCriteria};

// Default: the ZIP-215 preset (cofactored).
let verifier = Ed25519Verifier::new();

// `ed25519-dalek`'s verify_strict semantics.
let strict = Ed25519Verifier::with_criteria(VerificationCriteria::dalek_verify_strict());

// Or compose a variant by overriding individual knobs.
let custom = Ed25519Verifier::with_criteria(VerificationCriteria {
    reject_small_order_a: true,
    ..VerificationCriteria::zip215()
});

// See "Error handling" below for the possible failure reasons.
verifier.verify_signature(&signature, &public_key, message)?;
```

Named presets:

| Preset                  | `cofactored` | `canonical_a` | `canonical_r` | `small_order_a` | `small_order_r` |
| ----------------------- | ------------ | ------------- | ------------- | --------------- | --------------- |
| `zip215()` (default)    | ✓            |               |               |                 |                 |
| `dalek_verify_strict()` |              |               | ✓             | ✓               | ✓               |

`dalek_verify_strict()` matches `ed25519_dalek::VerifyingKey::verify_strict`
exactly (cross-checked in the test suite), including the detail that a
non-canonically encoded public key `A` is _not_ rejected. Further presets
(libsodium, RFC 8032 / FIPS 186-5) can be added in follow-ups.

The on-chain program always applies the `zip215()` preset. A program needing a
different variant should depend on this crate directly and build an
`Ed25519Verifier` from the desired `VerificationCriteria`.

[It's 255:19AM]: https://hdevalence.ca/blog/2020-10-04-its-25519am/

## Error handling (library)

`Ed25519Verifier::verify_signature` returns `Result<(), Ed25519VerifyError>`.
The library crate has no dependency on `solana-program-error` or any other
Solana-runtime error type — `Ed25519VerifyError` is a plain, dependency-free
enum, so consumers outside a Solana program aren't forced into a
Solana-specific type.

| Variant                 | Meaning                                                                |
| ----------------------- | ---------------------------------------------------------------------- |
| `NonCanonicalPublicKey` | `A`'s `y`-coordinate is `≥ p` (`require_canonical_a` only)             |
| `NonCanonicalR`         | `R`'s `y`-coordinate is `≥ p` (`require_canonical_r` only)             |
| `SmallOrderPublicKey`   | `A` is a small-order (torsion) point (`reject_small_order_a` only)     |
| `SmallOrderR`           | `R` is a small-order (torsion) point (`reject_small_order_r` only)     |
| `InvalidEncoding`       | `A` doesn't decode to a valid point, or `S` is non-canonical (`S ≥ L`) |
| `SignatureMismatch`     | Every input decoded successfully, but the equation doesn't hold        |

`InvalidEncoding` does not distinguish a malformed public key from a
non-canonical `S` scalar: the syscall that consumes both reports only overall
success or failure. Telling them apart would mean an explicit `S < L` comparison,
or decoding `A` ahead of the syscall — compute units spent on every signature for
precision that only helps malformed input.

The on-chain program collapses all of these to
`ProgramError::InvalidInstructionData` — see [Constraints](#constraints).

## Cargo features

`solana-ed25519-verify` has two independent features, both enabled by default:

| Feature       | Unlocks                                                         | Pulls in                                    |
| ------------- | --------------------------------------------------------------- | ------------------------------------------- |
| `verify`      | `Ed25519Verifier`, `VerificationCriteria`, `Ed25519VerifyError` | `solana-curve25519`, `solana-sha512-hasher` |
| `instruction` | `verify()`, `id()`, `ID` (the client-side instruction builder)  | `solana-instruction`, `solana-address`      |

A pure client that only needs to construct instructions for CPI or a
transaction — and never verifies a signature itself — can depend on
`instruction` alone, without pulling in the curve/hash syscall wrappers:

```toml
solana-ed25519-verify = { version = "0.1.0", default-features = false, features = [
    "instruction",
] }
```

## Build and test

Stable Rust `1.93.1` is pinned in `rust-toolchain.toml`. Some make targets
also require the nightly Rust chain `nightly-2026-01-22`.

```sh
# Unit tests (host, no SBF toolchain required)
cargo test --manifest-path program/Cargo.toml

# SBF build only
cargo build-sbf --arch v2 --manifest-path program/Cargo.toml

# SBF build via Makefile
make build-sbf-program

# Confirm the pure-client configuration compiles without the curve/hash
# syscall wrappers
cargo check --manifest-path ed25519-verify/Cargo.toml --no-default-features --features instruction

# Host unit tests, then SBF integration tests via Mollusk
make test-program

# Print Mollusk compute-unit measurements for the SBF program
make cu-program
```

The Mollusk tests execute `target/deploy/solana_ed25519_program.so`. They skip
unless `SBF_OUT_DIR` is set. Because published Mollusk/Agave crates do not yet
register `sol_sha512`, `program/tests/mollusk.rs` installs a local SHA-512
syscall shim before loading the SBF program. A production/localnet VM must
register the real `sol_sha512` syscall instead.

## Compute units

The measurements below were collected on September 8, 2026, using an SBF v2
release build, Mollusk `0.13.1`, and the metered SHA-512 test syscall shim. They
include execution of the program wrapper and the syscall charges in that
harness. These are compute-unit measurements, not host execution times.

The signature corpus contains 32 cases: signing-key seeds `7`, `42`, `99`, and
`201`, each tested with the eight message lengths below. For each message length,
all four seeds consumed the same number of compute units in the final measured
build.

|     Message bytes | Default ZIP-215 CU |    Strict CU |
| ----------------: | -----------------: | -----------: |
|                 0 |              3,847 |        4,980 |
|                 1 |              3,847 |        4,980 |
|                38 |              3,856 |        4,989 |
|                47 |              3,860 |        4,993 |
|                48 |              3,861 |        4,994 |
|                49 |              3,861 |        4,994 |
|               128 |              3,901 |        5,034 |
|             1,024 |              4,349 |        5,482 |
| **32-case total** |        **125,528** |  **161,784** |
| **Mean per case** |       **3,922.75** | **5,055.75** |

The separate 38-byte signature fixture also consumes **3,856 CU** with ZIP-215
and **4,989 CU** with `VerificationCriteria::dalek_verify_strict()`. The strict
column was measured using a separate build of the same program wrapper with
that preset selected. The shipped program continues to use ZIP-215.

Other measured paths in the default ZIP-215 build:

| Test case                                        |                                 CU |
| ------------------------------------------------ | ---------------------------------: |
| Accepted small-order public-key fixture          |                              4,388 |
| Accepted torsion encodings, 14 cases             | 3,848-4,400 per case; 60,898 total |
| Tampered message or public key                   |                         4,403 each |
| Non-canonical `S` or invalid public-key encoding |                         3,836 each |
| Unexpected accounts                              |                                 18 |
| Instruction shorter than 96 bytes                |                                 21 |

To reproduce the default program measurements:

```sh
cargo build-sbf --arch v2 --manifest-path program/Cargo.toml \
    --sbf-out-dir "$PWD/target/deploy"
SBF_OUT_DIR="$PWD/target/deploy" cargo test --locked \
    -p solana-ed25519-program --test mollusk \
    -- --nocapture --test-threads=1
```

Changing the SBF toolchain, dependencies, or syscall cost model can change these
results. Compare builds using the same corpus and metered syscall shim.
