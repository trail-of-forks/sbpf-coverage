# sbpf-coverage

SBPF virtual machine with support for generating coverage

This is a fork of [solana-sbpf v0.12.2](https://github.com/anza-xyz/sbpf/tree/v0.12.2) and is known to work with [Agave v3.0.6](https://github.com/anza-xyz/agave/tree/v3.0.6).

Prebuilt Agave binaries using this fork can be found under [Releases].

See [anchor-coverage] for full documentation.

## Description

This is a fork of Agave's [solana-sbpf](https://github.com/anza-xyz/sbpf)

- which is a fork of Solana Labs' [RBPF](https://github.com/solana-labs/rbpf)
- which in turn is a fork of [RBPF](https://github.com/qmonnet/rbpf) by Quentin Monnet.

## Usage

Install the Agave validator [from source] after adding the following to the `[patch.crate-io]` section near the end of its Cargo.toml:

```toml
solana-sbpf = { git = "https://github.com/trail-of-forks/sbpf-coverage" }
```

Then, set the environment variable `SBF_TRACE_DIR` to the path of a directory, and run the `solana-test-validator`. Three types of files will be written to that directory:

- `.pcs` - program counters executed
- `.insns` - instructions executed
- `.summary` - summary of the executable that was used

[anchor-coverage]: https://github.com/trailofbits/anchor-coverage
[from source]: https://docs.anza.xyz/cli/install#building-from-source
[Releases]: https://github.com/trail-of-forks/sbpf-coverage/releases
