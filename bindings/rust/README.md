# s2n-tls rust bindings

**NOTICE: These bindings are currently subject to change and should not be used without the expectation
of future breakage.**

## Installation

In order to generate rust bindings for s2n-tls, you need to have the following installed:

* Rust - this can be easily installed with [rustup](https://rustup.rs/)
* libclang - this is usually installed through your system's package manager
* libssl-dev
* pkg-config

## Usage

Generating rust bindings can be accomplished by running the `generate.sh` script:

```
$ ./bindings/rust/generate.sh
```

This script generates the low-level bindings in the crate `s2n-tls-sys`, which is used by the `s2n-tls` crate to provide higher-level bindings.
See [s2n-tls-sys](https://github.com/aws/s2n-tls/blob/main/bindings/rust/s2n-tls-sys/README.md) for more information on `s2n-tls-sys` crate.

## Minimum Supported Rust Version (MSRV)

`s2n-tls` will maintain a rolling MSRV (minimum supported rust version) policy of at least 6 months. The current s2n-quic version is not guaranteed to build on Rust versions earlier than the MSRV.

The current MSRV is [1.63.0][msrv-url].

