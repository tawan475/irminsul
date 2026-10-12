# anime-game-data

Rust library for downloading and indexing game data from a certain anime game.

## where it lives

this crate is the `crates/anime-game-data` member of irminsul's cargo
workspace. irminsul's `build.rs` uses it to download Dimbreath's game data dump
and build the blob the binary embeds, and the binary uses it to look the data
up. irminsul depends on it by path.

## credits

written by Erik Gilling ([konkers](https://github.com/konkers)) as
[konkers/anime-game-data](https://github.com/konkers/anime-game-data), MIT
licensed (see [`LICENSE`](LICENSE), which stays as it was). it was vendored
here from revision `dfc03cdb5e27807a876b8d4dff17b3f67a320f5c` and has been
changed in this repository since; those changes are not upstream's.
