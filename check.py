#!/usr/bin/env python3
import subprocess
import sys
import os
import platform
import shutil

def run_command(cmd, step_name):
    print(f"\n[{step_name}] Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"\n❌ [{step_name}] Failed with exit code {e.returncode}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"\n❌ [{step_name}] Command not found: {cmd[0]}. Make sure it is installed.")
        sys.exit(1)
    print(f"✅ [{step_name}] Passed!")

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Run local CI checks for Irminsul.")
    parser.add_argument("--all", action="store_true", help="Run 'cargo check' across Windows, macOS, and Linux targets (requires cross-compilation toolchains).")
    args = parser.parse_args()

    print("🚀 Starting local checks for Irminsul...")

    # Define base features depending on OS
    features = []
    if platform.system() == "Windows":
        features = ["--features", "pcap"]
    elif platform.system() == "Linux":
        features = ["--features", "pcap,static-libpcap"]
    elif platform.system() == "Darwin":
        features = ["--features", "pcap"]
        
    # 1. Cargo Fmt
    run_command(["cargo", "fmt", "--check"], "Format Check")

    if args.all:
        print("\n🌍 Running cross-platform checks (Windows, macOS, Linux)...")
        targets = [
            ("x86_64-pc-windows-gnu", ["--features", "pcap"], "x86_64-w64-mingw32-gcc", "sudo apt-get install mingw-w64"),
            ("x86_64-apple-darwin", ["--features", "pcap"], "x86_64-apple-darwin-cc", "osxcross toolchain"),
            ("x86_64-unknown-linux-gnu", ["--features", "pcap,static-libpcap"], "gcc", "build-essential")
        ]
        
        # Don't check the native target using cross-compilation logic
        native_target = ""
        if platform.system() == "Windows": native_target = "x86_64-pc-windows-gnu"
        elif platform.system() == "Linux": native_target = "x86_64-unknown-linux-gnu"
        elif platform.system() == "Darwin": native_target = "x86_64-apple-darwin"


        for target, target_features, compiler, install_hint in targets:
            if target == native_target:
                continue # Handled by the standard run below
            
            print(f"\n📦 Preparing target {target}...")
            if not shutil.which(compiler):
                print(f"⚠️  Skipping {target}: Missing C compiler '{compiler}' needed for C-dependencies like the 'ring' crate.")
                print(f"   (Hint: Install {install_hint} to check this target locally)")
                continue

            subprocess.run(["rustup", "target", "add", target], check=False)
            cmd = ["cargo", "check", "--no-default-features", "--target", target] + target_features
            run_command(cmd, f"Check {target}")
        
        print("\n🎉 Cross-platform structural checks complete!")
        # Continue with normal local checks...

    # 2. Cargo Clippy
    clippy_cmd = ["cargo", "clippy", "--no-default-features"] + features + ["--", "-Dwarnings"]
    run_command(clippy_cmd, "Clippy Lints")

    # 3. Cargo Test
    test_cmd = ["cargo", "test", "--no-default-features"] + features
    run_command(test_cmd, "Unit Tests")

    # 4. Cargo Build
    build_cmd = ["cargo", "build", "--no-default-features"] + features
    run_command(build_cmd, "Build Verification")

    print("\n🎉 All checks passed! You are ready to push.")

if __name__ == "__main__":
    main()
