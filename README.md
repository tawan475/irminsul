# auto-artifactarium

a library to parse network packets from a certain turn based anime game!

## use in your projects

not published to crates.io out of caution. add following to your Cargo.toml to use

```toml
[dependencies]
auto-artifactarium = { git = "https://github.com/tawan475/auto-artifactarium" }
```

this crate has no stable release channel, so consumers are expected to **pin an
explicit revision** rather than track the default branch:

```toml
[dependencies]
auto-artifactarium = { git = "https://github.com/tawan475/auto-artifactarium", rev = "<full commit sha>" }
```

that is what [irminsul](https://github.com/tawan475/irminsul) does; its
`update_rev.py` rewrites the pinned rev to the latest upstream `HEAD`, so always
re-run the build and test suite after bumping.

only the library target is built by default. the `auto-artifactarium` CLI (a
small helper that dumps avatar/item packets captured to a file) lives behind the
optional `cli` feature so that library consumers do not pull in `clap` and
`anyhow`:

```sh
cargo run --features cli -- avatars path/to/packet.bin
cargo run --features cli -- items path/to/packet.bin
```

for documentation, use `cargo doc`

## development

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -Dwarnings
cargo test --all-features
cargo build --all-features
```

the same four commands run in CI (`.github/workflows/rust.yml`) on every push
and pull request.

## forked from

- [konkers/auto-artifactarium](https://github.com/konkers/auto-artifactarium) (the `upstream` remote of this checkout)
- [hashblen/auto-artifactarium](https://github.com/hashblen/auto-artifactarium)
- [IceDynamix/reliquary](https://github.com/IceDynamix/reliquary)

## related

- [PJK136/auto-artifactarium](https://github.com/PJK136/auto-artifactarium)
- [PJK136/stardb-exporter](https://github.com/PJK136/stardb-exporter)
- [juliuskreutz/stardb-exporter](https://github.com/juliuskreutz/stardb-exporter)
- [IceDynamix/reliquary-archiver](https://github.com/IceDynamix/reliquary-archiver)
