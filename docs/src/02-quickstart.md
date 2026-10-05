# Quickstart

## Download Irminsul

The latest Irminsul release can always be found on the [Irminsul GitHub Releases Page](https://github.com/tawan475/irminsul/releases). Grab the file for your platform, not either of the "Source code" archives:

| File | Platform | Capture backend |
| --- | --- | --- |
| `irminsul-windows.exe` | Windows x64 | `pktmon` (built into Windows, nothing to install) |
| `irminsul-windows-pcap.exe` | Windows x64 | `pcap`, requires the Npcap runtime |
| `irminsul-linux-x86_64.tar.gz` | Linux x86_64 | `pcap`, libpcap is statically linked in |
| `Irminsul-macos-arm64.app.tar.gz` | macOS (Apple Silicon) | `pcap` |

If you are on Windows and unsure which one to take, take `irminsul-windows.exe`: it needs no driver install.

## Install a Pcap library (only for the pcap backend)

- **Windows**: only needed for `irminsul-windows-pcap.exe`. Install Npcap (<https://npcap.com/#download>). The older WinPcap should work too, but we didn't test it. `irminsul-windows.exe` uses `pktmon` and needs nothing.
- **Linux**: nothing to install. The released binary has libpcap linked into it. You only need libpcap from your distro's package manager if you build Irminsul yourself.
- **macOS**: nothing to install; libpcap ships with the system.

## Unpack the download

**Windows**: the download is the executable itself, nothing to unpack.

**Linux**: extract the tarball, which contains a single `irminsul` binary.

```
tar -xzf irminsul-linux-x86_64.tar.gz
chmod +x irminsul
```

**macOS**: extract the tarball, which contains `Irminsul.app`. The app is not
notarized, so macOS quarantines it after download; clear that flag before
launching it:

```
tar -xzf Irminsul-macos-arm64.app.tar.gz
xattr -dr com.apple.quarantine Irminsul.app
```

## Launch Irminsul and grant it packet capture privileges

Irminsul needs to be running and capturing packets before you enter the door into the main game. The simplest way to accomplish this is to launch Irminsul before launching Genshin

Irminsul needs admin/root privileges to observe Genshin's network traffic and won't work without it.

On Windows, accept the admin prompt that appears when Irminsul starts.

On Linux, you can either grant the extracted binary permission to capture packets:

```
sudo setcap cap_net_raw=ep ./irminsul
```

or run it as root every time:

```
sudo ./irminsul
```

`setcap` grants the permission to that particular copy of the file, so it has to be re-run after every update. Irminsul tells you when this is needed and shows you the command to use.

On macOS, open `Irminsul.app`. Its launcher checks whether it can read `/dev/bpf0` and, if it can't, asks for an admin password once to run `chmod 644 /dev/bpf*`. macOS resets those permissions on reboot, so expect the prompt again after restarting.

## Start packet capture

Click on the play button in the "Packet Capture" section. This will start Irminsul capturing packets.

![Start Capture](images/start-capture.webp)

## Start Genshin and enter the door

Once packet capture is running, enter the door in Genshin

![Door](images/door.webp)

Once Irminsul detects the various data it needs, you'll green checkmarks appear in the "Packet Capture" section.

![Checkmarks](images/checkmark.webp)

## Export data

![Genshin Optimizer Export](images/export.webp)

Once the data has been captured, you can export:

- To the clipboard by clicking ont the clipboard with the arrow icon.
- To a file by clicking on the download icon.

Which data gets exported can be controlled by clicking on the settings icon.

## Upload to a Genshin Data Tracker

This fork can also push a capture straight to a Genshin Data Tracker account,
from the "Tracker" section of the main window. By default it talks to the hosted
tracker at <https://genshin-tracker.475.dev>:

1. In the tracker dashboard, generate an **Import Key** for the Genshin account you want to fill.
2. In Irminsul, click the gear icon in the "Tracker" section, paste the key, and click "Save & Close". Irminsul verifies the key and shows the account name, UID and server it belongs to.
3. With a capture completed, click the cloud upload icon to send the current data. Tick "Auto export to tracker" in the same section to upload every completed capture automatically.

The same modal has a **Tracker API base URL** field, so a self-hosted tracker
needs no rebuild -- point it at your backend's API base and click "Save &
Close". The default is `https://genshin-tracker.475.dev/api`; note the `/api`,
under which the tracker serves its API. The compile-time `TRACKER_API_URL`
replaces that default for a build and only supplies the value a fresh install
starts with; once you have edited or saved the field the stored URL wins,
including after an update to a build with a different baked-in default. The
exceptions are an empty field and the old default `http://localhost:49000`,
which Irminsul resets to the build's default when it starts (to keep using a
local backend on that port, enter it as `http://127.0.0.1:49000`). "Reset URL
to default" puts the build's own value back.

The key is stored with the rest of Irminsul's saved state on your machine and
is sent only to the tracker it belongs to.

## Start Irminsul when you sign in (Windows)

Tick "Start Irminsul on startup" in the "Automation" section. Irminsul then
registers a Task Scheduler task named `Irminsul` that starts this copy about 15
seconds after you sign in, with the administrator rights packet capture needs
and without a UAC prompt. Untick it to remove the task. (Older versions used the
ordinary startup list, which Windows never runs for a program that needs
administrator rights; a newer version moves that entry to the task when it
starts.)

If the task starts a different copy of Irminsul, or a file that is no longer
there, an amber warning icon appears next to the checkbox. Click it to see both
paths, and "Start this copy instead" to point the task at the copy you are
running.

## Command line options

Irminsul also supports a couple of command line flags when launching from a terminal:

- `--capture-backend <pktmon|pcap>` (or `-b`): on Windows you can choose between the `pktmon` backend (default) and the cross-platform `pcap` backend. On other platforms only `pcap` is available.
- `--no-admin`: on Linux and macOS, skip the packet-capture privilege check and the "permissions missing" dialog it would otherwise show; capture itself still needs root/`CAP_NET_RAW`/`/dev/bpf` access. On Windows the flag does nothing: the executable carries a manifest requesting administrator rights, so Windows shows the UAC prompt and decides elevation before Irminsul's own code runs.
- `--read-from-file` (or `-r`): replay a previously saved capture file instead of capturing live traffic. The file is passed as a positional argument, e.g. `irminsul -r capture.pcapng`. Replay needs no admin/root rights, but it only works with the `pcap` backend, so on Windows use `irminsul-windows-pcap.exe -b pcap -r capture.pcapng`. This is mostly useful for debugging.
- A positional file path *without* `--read-from-file` records the live capture (pcap backend only). It is a filename template rather than an output path: Irminsul captures on every eligible network interface at once and gives each one its own file named after the device, so `irminsul -b pcap session.pcap` produces one `session-<interface>.pcap` per interface and no plain `session.pcap`. The log names each file as it is opened.
