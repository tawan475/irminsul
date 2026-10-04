![Screenshot](docs/src/images/main-window.webp)

# Resources

- [Docs](https://tawan475.github.io/irminsul)
- [Discord](https://discord.gg/aQqdZPHEpP)

# Introduction

Irminsul is a utility to extract data from Genshin Impact and export it for use with [Genshin Optimizer](https://frzyc.github.io/genshin-optimizer/) and web sites, applications, and utilities that use the [GOOD](https://frzyc.github.io/genshin-optimizer/#/doc) data format.

Irminsul utilizes packet capture instead of the common optical character recognition (OCR) that other [scanners](https://frzyc.github.io/genshin-optimizer/#/scanner) use. This allows it to be much quicker in exchange for 1. needing to run with admin/root privaleges (for the packet capture) and 2. needing to be run when genshin starts to observe the handshake with the server.

## Dependencies

To use the `pcap` capture backend, make sure to install a Pcap library (Npcap/WinPcap on Windows, libpcap on Linux). The released Linux binary has libpcap linked into it, so this only applies there when building Irminsul yourself.

On Windows a build with `--features pcap` links `wpcap.dll` at load time, and Npcap (unless installed in WinPcap-compatible mode) puts it in `C:\Windows\System32\Npcap`, which is not on the DLL search path. Such a build then fails to start with "wpcap.dll was not found"; put that directory on `PATH` first (Git Bash: `PATH="/c/Windows/System32/Npcap:$PATH" ./irminsul.exe ...`).

## Repository layout

This repository is a Cargo workspace:

- the root package is Irminsul itself;
- [`crates/auto-artifactarium`](crates/auto-artifactarium) is the library that decrypts the game's traffic and parses its packets. It used to be a separate repository and was merged in with its history; Irminsul depends on it by path.

`python check.py` runs the same checks as CI for both.

## Releasing

Work happens on `develop`; `main` (the default branch) only holds what has
been released or is about to be. `main` is protected: changes reach it through
a pull request once CI is green. To publish, open a pull request from
`develop` into `main`, merge it, then run the **Create Release** workflow on
`main` (Actions → Create Release → Run workflow). There is nothing to type:
`next_version.py` takes the base version from `Cargo.toml` and appends the next
`-T-N` from the existing tags (`v0.2.2-T-2` → `v0.2.2-T-3`). To move to a new
base, change `package.version` in `Cargo.toml` (e.g. to `0.2.3`); the next
release is then `v0.2.3-T-1`. `Cargo.toml` keeps the bare base version on
purpose: local builds count as stable and are never offered a `-T-N` update.

## Command line options

Irminsul accepts a handful of command line options for advanced use cases:

- `--capture-backend <pktmon|pcap>`: chooses which capture backend to use. On Windows both `pktmon` (default) and `pcap` are available. On other platforms only `pcap` is available.
- `--no-admin`: skips the packet-capture privilege check, and the "permissions missing" dialog it would otherwise show, on Linux and macOS. Capture still needs root/`CAP_NET_RAW`/`/dev/bpf` access to work, so this only helps when you want the UI without capture. It has no effect on Windows: the embedded application manifest asks for elevation before `main()` runs, so Windows has already decided by the time the flag is parsed.
- `--replay-export <OUT_JSON> <RECORDING>`: decodes a recording without starting the app and writes its export to `OUT_JSON`; see below.

## Development: replaying a recording

Debug builds record every captured frame to `irminsul-data/log/latest.pcapng` under their working directory (the previous run's file is renamed to its timestamp at startup; six are kept). A recorded session can then be decoded again as often as needed -- to debug an export, check which items carry another UID (`gi_debug.uidCheck`), or look at character fields -- without logging in again:

```bash
cargo build                              # any build; no pcap feature needed
cp irminsul-data/log/latest.pcapng /somewhere/session.pcapng   # replay a copy
target/debug/irminsul --replay-export /somewhere/session.json /somewhere/session.pcapng
```

The recording must contain the login (start Irminsul before the game connects), exactly as for live capture: the session key is recovered from the recorded handshake. Classic pcap files (`-b pcap <template>`) and Wireshark pcapng files work too. Each login or reconnect in the recording is logged, with its recorded time; the state at the end is exported, where a later login's data replaces an earlier one's once it arrives, as in the app.

- **Output**: `OUT_JSON` is the full export, pretty-printed, including the `gi_*` extras and `gi_debug`, made with the default export settings and stamped with the time its data was captured. The log, ending in a summary and the export report, goes to stdout and to `OUT_JSON.log`; `RUST_LOG=debug` shows more.
- **Exit code**: 0 when an export was written; 1 when nothing could be decoded (no login in the recording, a key that was never recovered, no game traffic...), with the reason in the last error line, and no `OUT_JSON` is written.
- **Safe to run at any time**: a replay never uploads or verifies a tracker key, never saves an automation file or checks for updates, never reads or writes the app's settings (`app.ron`) or anything under its data directory, and does not take the single-instance lock, so it runs beside a live Irminsul. It needs no administrator rights; on Windows the executable's manifest still asks for elevation before any code runs, so on a machine with UAC set `__COMPAT_LAYER=RunAsInvoker` to start it unelevated.
- Release builds have no console window on Windows; read `OUT_JSON.log` there, or use a debug build.

## Features

In it's current state Irminsul supports:

- Incredibly fast capture of all Genshin Optimizer supported data
  - Artifacts including "unactivated" rolls and reporting of initial values for rolls
  - Weapons
  - Materials
  - Characters
- Simple, clean UI
- Export settings to filter which data gets exported
- Exports data either to the clipboard or saved to a file

Planned features include:

- Achievement export
- Wish history export
- Real time data updates while game is running

## Thanks

Irmunsil is built upon the work of many others.

- [PJK136](https://github.com/PJK136) whose work on a [fork of `stardb-exporter`](https://github.com/PJK136/stardb-exporter) provided the main inspiration for Irminsul's development.
- [juliuskreutz](https://github.com/juliuskreutz) whose [`stardb-exporter`](https://github.com/juliuskreutz/stardb-exporter) provided the foundation for PJK136's work as well as providing some examples for how to wrangle [`egui`](https://github.com/emilk/egui).
- [hashblen](https://github.com/hashblen) whose [`auto-artifactarioum`](https://github.com/hashblen/auto-artifactarium) is used to interpret the network packets from Genshin.
- [IceDynamix](https://github.com/IceDynamix/) whose work on Honkai Star Rail network scanning is at the root of many of the Genshin and HSR network scanning utilities.
- [emmachase](https://github.com/emmachase) who wrote the packet capture library [`pktmon`](https://github.com/emmachase/pktmon) which Irminsul uses to allow packet capture without having to install a npcap driver as well as their contributions to some of the above projects.
- [Genshin Optimizer](https://frzyc.github.io/genshin-optimizer/) without which there would be no point in exporting data.
- [Inventory Kamera](https://github.com/Andrewthe13th/Inventory_Kamera) which was my introduction into artifact and character scanning and whose discord provided a collaboration environment that spawned Irminsul.
