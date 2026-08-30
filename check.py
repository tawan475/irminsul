#!/usr/bin/env python3
import subprocess
import sys
import os
import platform
import shutil

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))

# A Windows console still defaults to a legacy codepage (gbk, cp1252, ...) that
# cannot encode the status emoji used below, and an UnicodeEncodeError on the
# very first print aborts the run before a single check has executed. Re-encode
# our own streams as UTF-8 so the script reports results instead of dying on its
# own banner; `errors="replace"` keeps it alive even where the font cannot draw
# the glyph.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError, ValueError):
        pass

# Feature sets checked per host OS. These mirror the matrix in
# .github/workflows/rust.yml so a green local run means the same configurations
# CI builds were checked -- including the default (pktmon) Windows build that
# actually ships.
FEATURE_SETS = {
    "Windows": ["", "pcap"],
    "Linux": ["pcap,static-libpcap"],
    "Darwin": ["pcap"],
}

def run_command(cmd, step_name, env=None):
    print(f"\n[{step_name}] Running: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True, env=env)
    except subprocess.CalledProcessError as e:
        print(f"\n❌ [{step_name}] Failed with exit code {e.returncode}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"\n❌ [{step_name}] Command not found: {cmd[0]}. Make sure it is installed.")
        sys.exit(1)
    print(f"✅ [{step_name}] Passed!")

def host_target():
    """The target triple rustc builds for by default on this machine."""
    try:
        out = subprocess.run(["rustc", "-vV"], check=True, capture_output=True, text=True).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("⚠️  Could not run 'rustc -vV'; treating no target as native.")
        return ""
    for line in out.splitlines():
        if line.startswith("host:"):
            return line.split(":", 1)[1].strip()
    return ""

def npcap_lib_dir():
    """Directory holding wpcap.lib from the Npcap SDK, or None if not found.

    The `pcap` feature is not enabled by default on Windows precisely because it
    needs that SDK, so a contributor without it should be told to skip that leg
    rather than watch the build die in the linker.
    """
    # Already on the linker's search path: use it as-is.
    for d in os.environ.get("LIB", "").split(os.pathsep):
        if d and os.path.isfile(os.path.join(d, "wpcap.lib")):
            return d

    roots = [os.environ[v] for v in ("NPCAP_SDK", "NPCAP_SDK_DIR") if os.environ.get(v)]
    # CI (and the docs) unzip the SDK into the repo root, which yields Lib/x64.
    roots.append(REPO_ROOT)
    roots.append(os.path.join("C:" + os.sep, "npcap-sdk"))
    roots.append(os.path.join(os.path.expanduser("~"), "npcap-sdk"))
    roots += [p for p in os.environ.get("PATH", "").split(os.pathsep) if "npcap" in p.lower()]

    for root in roots:
        # x64 first: Lib/ at the SDK root holds the 32 bit import libraries.
        for sub in (os.path.join("Lib", "x64"), "Lib", ""):
            candidate = os.path.join(root, sub)
            if os.path.isfile(os.path.join(candidate, "wpcap.lib")):
                return candidate
    return None

def env_with_lib(lib_dir):
    """A copy of the environment with `lib_dir` prepended to LIB, mirroring the
    `LIB:` env the CI workflows set for the pcap legs."""
    env = os.environ.copy()
    existing = env.get("LIB", "")
    env["LIB"] = lib_dir + os.pathsep + existing if existing else lib_dir
    return env

def feature_args(feature_set):
    return ["--features", feature_set] if feature_set else []

def feature_label(feature_set):
    return feature_set if feature_set else "default"

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Run local CI checks for Irminsul.")
    parser.add_argument("--all", action="store_true", help="Run 'cargo check' across Windows, macOS, and Linux targets (requires cross-compilation toolchains).")
    args = parser.parse_args()

    print("🚀 Starting local checks for Irminsul...")

    system = platform.system()
    feature_sets = FEATURE_SETS.get(system, [""])

    # 1. Cargo Fmt
    run_command(["cargo", "fmt", "--check"], "Format Check")

    if args.all:
        print("\n🌍 Running cross-platform checks (Windows, macOS, Linux)...")

        # Don't check the native target using cross-compilation logic.
        native_target = host_target()

        targets = [
            ("x86_64-pc-windows-gnu", ["--features", "pcap"], "x86_64-w64-mingw32-gcc", "sudo apt-get install mingw-w64"),
            ("x86_64-apple-darwin", ["--features", "pcap"], "x86_64-apple-darwin-cc", "osxcross toolchain"),
            ("x86_64-unknown-linux-gnu", ["--features", "pcap,static-libpcap"], "gcc" if native_target == "x86_64-unknown-linux-gnu" else "x86_64-linux-gnu-gcc", "gcc-x86-64-linux-gnu (or run within WSL)")
        ]

        for target, target_features, compiler, install_hint in targets:
            if target == native_target:
                continue # Handled by the standard run below

            print(f"\n📦 Preparing target {target}...")
            if not shutil.which(compiler):
                print(f"⚠️  Skipping {target}: Missing C compiler '{compiler}' needed for C-dependencies like the 'ring' crate.")
                print(f"   (Hint: Install {install_hint} to check this target locally)")
                continue

            run_command(["rustup", "target", "add", target], f"Add target {target}")
            cmd = ["cargo", "check", "--no-default-features", "--target", target] + target_features
            run_command(cmd, f"Check {target}")

        print("\n🎉 Cross-platform structural checks complete!")
        # Continue with normal local checks...

    for feature_set in feature_sets:
        label = feature_label(feature_set)
        env = None

        if system == "Windows" and "pcap" in feature_set:
            lib_dir = npcap_lib_dir()
            if lib_dir is None:
                print(f"\n⚠️  Skipping features '{label}': wpcap.lib not found.")
                print("   The pcap backend needs the Npcap SDK (https://npcap.com/#download).")
                print("   Unzip it into the repo root, point NPCAP_SDK at it, or add its")
                print("   Lib\\x64 directory to LIB. Everything else is still checked.")
                continue
            print(f"\n🔗 Using wpcap.lib from {lib_dir}")
            env = env_with_lib(lib_dir)

        print(f"\n🔧 Checking features: {label}")
        features = feature_args(feature_set)

        # 2. Cargo Clippy
        clippy_cmd = ["cargo", "clippy", "--no-default-features"] + features + ["--", "-Dwarnings"]
        run_command(clippy_cmd, f"Clippy Lints [{label}]", env=env)

        # 3. Cargo Test
        test_cmd = ["cargo", "test", "--no-default-features"] + features
        run_command(test_cmd, f"Unit Tests [{label}]", env=env)

        # 4. Cargo Build
        build_cmd = ["cargo", "build", "--no-default-features"] + features
        run_command(build_cmd, f"Build Verification [{label}]", env=env)

    print("\n🎉 All checks passed! You are ready to push.")

if __name__ == "__main__":
    main()
