#!/usr/bin/env python3
"""
Blaze Build Script - Creates standalone binaries for all platforms.
Uses PyInstaller to package Blaze into a single executable.

Usage:
  python build.py              Build for current platform
  python build.py --all        Build instructions for all platforms
"""

import os
import sys
import platform
import subprocess
import shutil


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DIST_DIR = os.path.join(SCRIPT_DIR, "dist")
BUILD_DIR = os.path.join(SCRIPT_DIR, "build")


def check_pyinstaller():
    try:
        import PyInstaller
        return True
    except ImportError:
        print("[!] PyInstaller not found. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
        return True


def get_platform_name():
    system = platform.system().lower()
    arch = platform.machine().lower()
    if "arm" in arch or "aarch64" in arch:
        arch = "arm64"
    elif "x86_64" in arch or "amd64" in arch:
        arch = "x64"
    return f"{system}-{arch}"


def build():
    check_pyinstaller()

    plat = get_platform_name()
    exe_name = f"blaze-{plat}"
    if platform.system() == "Windows":
        exe_name += ".exe"

    print(f"\n[*] Building Blaze for {plat}...")
    print(f"[*] Output: dist/{exe_name}\n")

    # Collect data files
    data_args = []
    wl_dir = os.path.join(SCRIPT_DIR, "wordlists")
    if os.path.exists(wl_dir):
        for wl in os.listdir(wl_dir):
            if wl.endswith(".txt"):
                src = os.path.join(wl_dir, wl)
                data_args.extend(["--add-data", f"{src}{os.pathsep}wordlists"])

    config_path = os.path.join(SCRIPT_DIR, "config.json")
    if os.path.exists(config_path):
        data_args.extend(["--add-data", f"{config_path}{os.pathsep}."])

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--name", exe_name,
        "--clean",
        "--noconfirm",
        # Hidden imports for optional features
        "--hidden-import", "aiohttp",
        "--hidden-import", "core",
        "--hidden-import", "core.engine",
        "--hidden-import", "core.waf_detector",
        "--hidden-import", "core.tech_detector",
        "--hidden-import", "core.wordlist_manager",
        "--hidden-import", "core.filters",
        "--hidden-import", "core.reporter",
        "--hidden-import", "core.response_differ",
        "--hidden-import", "core.smart_recursion",
        "--hidden-import", "core.smart_extensions",
        "--hidden-import", "core.js_extractor",
        "--hidden-import", "core.resume_manager",
        "--hidden-import", "core.pattern_generator",
        "--hidden-import", "core.vhost_scanner",
        "--hidden-import", "core.content_discovery",
        "--hidden-import", "core.headless",
        *data_args,
        os.path.join(SCRIPT_DIR, "blaze.py"),
    ]

    print(f"[*] Running: {' '.join(cmd[:8])}...")
    result = subprocess.run(cmd, cwd=SCRIPT_DIR)

    if result.returncode == 0:
        output = os.path.join(DIST_DIR, exe_name)
        if os.path.exists(output):
            size_mb = os.path.getsize(output) / (1024 * 1024)
            print(f"\n[+] Build successful!")
            print(f"[+] Binary: {output}")
            print(f"[+] Size: {size_mb:.1f} MB")
            print(f"\n[*] To install system-wide:")
            if platform.system() != "Windows":
                print(f"    sudo cp {output} /usr/local/bin/blaze")
                print(f"    sudo chmod +x /usr/local/bin/blaze")
            else:
                print(f"    copy {output} C:\\Windows\\blaze.exe")
    else:
        print(f"\n[!] Build failed with exit code {result.returncode}")
        sys.exit(1)

    # Cleanup build artifacts
    if os.path.exists(BUILD_DIR):
        shutil.rmtree(BUILD_DIR)
    spec_file = os.path.join(SCRIPT_DIR, f"{exe_name}.spec")
    if os.path.exists(spec_file):
        os.remove(spec_file)


if __name__ == "__main__":
    build()
