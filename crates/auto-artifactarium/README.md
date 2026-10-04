# auto-artifactarium

a library to parse network packets from a certain turn based anime game!

## where it lives

this crate is part of the [irminsul](https://github.com/tawan475/irminsul)
repository: it is the `crates/auto-artifactarium` member of irminsul's cargo
workspace, and irminsul depends on it by path. it was developed in the
standalone `tawan475/auto-artifactarium` repository until it was merged here
with its full history.

## use in your projects

not published to crates.io out of caution. inside the irminsul workspace it is
a path dependency:

```toml
[dependencies]
auto-artifactarium = { path = "crates/auto-artifactarium" }
```

this crate has no stable release channel, so a project outside the workspace is
expected to **pin an explicit revision** of the irminsul repository (cargo finds
the package inside it by name) rather than track the default branch:

```toml
[dependencies]
auto-artifactarium = { git = "https://github.com/tawan475/irminsul", rev = "<full commit sha>" }
```

only the library target is built by default. the `auto-artifactarium` CLI (a
small helper that dumps avatar/item packets captured to a file) lives behind the
optional `cli` feature so that library consumers do not pull in `clap` and
`anyhow`:

```sh
cargo run -p auto-artifactarium --features cli -- avatars path/to/packet.bin
cargo run -p auto-artifactarium --features cli -- items path/to/packet.bin
```

for documentation, use `cargo doc -p auto-artifactarium`

## development

run from the root of the irminsul repository. the toolchain and the
`rustfmt.toml` are the workspace's:

```sh
cargo fmt --all --check
cargo clippy -p auto-artifactarium --all-targets --all-features -- -Dwarnings
cargo test -p auto-artifactarium --all-features
cargo build -p auto-artifactarium --all-features
RUSTDOCFLAGS=-Dwarnings cargo doc -p auto-artifactarium --no-deps --all-features
```

irminsul's `python check.py` runs these along with irminsul's own checks, and
CI runs them in the `library` job of irminsul's `.github/workflows/rust.yml` on
every push and pull request.

## forked from

- [konkers/auto-artifactarium](https://github.com/konkers/auto-artifactarium) (the `upstream` remote of this checkout)
- [hashblen/auto-artifactarium](https://github.com/hashblen/auto-artifactarium)
- [IceDynamix/reliquary](https://github.com/IceDynamix/reliquary)

## related

- [PJK136/auto-artifactarium](https://github.com/PJK136/auto-artifactarium)
- [PJK136/stardb-exporter](https://github.com/PJK136/stardb-exporter)
- [juliuskreutz/stardb-exporter](https://github.com/juliuskreutz/stardb-exporter)
- [IceDynamix/reliquary-archiver](https://github.com/IceDynamix/reliquary-archiver)
