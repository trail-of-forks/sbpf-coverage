# sbpf-coverage

SBPF virtual machine with support for generating coverage

This is a fork of solana-sbpf commit [58236a8](https://github.com/anza-xyz/sbpf/commit/58236a8ca3c3eeddae8b3c7f45a3246d8ee0fb8e) and is known to work with Agave commit [cd29142](https://github.com/anza-xyz/agave/commit/cd291424d3d71c1a3be0c2c919916dcaa272d162).

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

Then, set the environment variable `SBF_TRACE_DIR` to the path of a directory, and run the `solana-validator`. Three types of files will be written to that directory:

- `.pcs` - program counters executed
- `.insns` - instructions executed
- `.summary` - summary of the executable that was used

[anchor-coverage]: https://github.com/trailofbits/anchor-coverage
[from source]: https://docs.anza.xyz/cli/install#building-from-source
