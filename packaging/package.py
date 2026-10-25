"""Packages a release build for one platform, as the release workflow (.github/workflows/release.yml) runs it.

    python packaging/package.py <version> <windows|linux|macos> <bin dir> <out dir>

<bin dir> holds the built cartwrite and cartwrite-cli executables (for macOS, universal binaries). Writes
Cartwrite-<version>-<platform>.zip (Windows) or .tar.gz (Linux, macOS) to <out dir> and prints its path.
"""
import os
import plistlib
import shutil
import stat
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

PLATFORMS = {
    "windows": {
        "name": "Windows (64-bit)",
        "suffix": "windows-x64",
        "contents": "cartwrite.exe      The desktop app. Double-click to run.\n"
        "cartwrite-cli.exe  The command-line version, for scripts.",
        "notes": "",
    },
    "linux": {
        "name": "Linux (64-bit)",
        "suffix": "linux-x64",
        "contents": "cartwrite      The desktop app. Run ./cartwrite.\n"
        "cartwrite-cli  The command-line version, for scripts.",
        "notes": "\nThe app needs an X11 or Wayland desktop. Its file dialogs use the XDG desktop\n"
        "portal (xdg-desktop-portal), which most desktops include.\n",
    },
    "macos": {
        "name": "macOS (Apple silicon and Intel)",
        "suffix": "macos-universal",
        "contents": "Cartwrite.app  The desktop app. Move it to Applications if you like.\n"
        "cartwrite-cli  The command-line version, for scripts.",
        "notes": "\nOn macOS, put prod.keys in ~/.switch/ (the app's own folder is inside\n"
        "Cartwrite.app).\n\n"
        "Cartwrite isn't signed by Apple, so macOS blocks it the first time. Right-click\n"
        "Cartwrite.app and choose Open, then Open again. Or run this once in Terminal:\n\n"
        "  xattr -dr com.apple.quarantine Cartwrite.app cartwrite-cli\n",
    },
}


def readme(version: str, p: dict) -> str:
    text = (ROOT / "packaging" / "README.txt").read_text(encoding="utf-8").replace("\r\n", "\n")
    # The first two lines are the title and its underline, sized to the title.
    title = f"Cartwrite {version} for {p['name']}"
    body = text.split("\n", 2)[2]
    text = title + "\n" + "=" * len(title) + "\n" + body
    return text.replace("@CONTENTS@", p["contents"]).replace("@NOTES@", p["notes"])


def mac_app(version: str, binary: Path, dest: Path) -> None:
    contents = dest / "Cartwrite.app" / "Contents"
    (contents / "MacOS").mkdir(parents=True)
    shutil.copy2(binary, contents / "MacOS" / "cartwrite")
    info = {
        "CFBundleName": "Cartwrite",
        "CFBundleDisplayName": "Cartwrite",
        "CFBundleIdentifier": "io.github.playingkarrde.cartwrite",
        "CFBundleExecutable": "cartwrite",
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": version,
        "CFBundleVersion": version,
        "LSMinimumSystemVersion": "11.0",
        "NSHighResolutionCapable": True,
    }
    with open(contents / "Info.plist", "wb") as f:
        plistlib.dump(info, f)
    # Ad-hoc signature: Apple silicon refuses to run unsigned code.
    subprocess.run(["codesign", "--force", "--deep", "--sign", "-", str(dest / "Cartwrite.app")], check=True)


def main() -> None:
    version, platform, bin_dir, out_dir = sys.argv[1], sys.argv[2], Path(sys.argv[3]), Path(sys.argv[4])
    p = PLATFORMS[platform]
    name = f"Cartwrite-{version}-{p['suffix']}"
    stage = out_dir / name
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)

    exe = ".exe" if platform == "windows" else ""
    if platform == "macos":
        mac_app(version, bin_dir / "cartwrite", stage)
    else:
        shutil.copy2(bin_dir / f"cartwrite{exe}", stage)
    shutil.copy2(bin_dir / f"cartwrite-cli{exe}", stage)
    if platform == "macos":
        subprocess.run(["codesign", "--force", "--sign", "-", str(stage / "cartwrite-cli")], check=True)
    shutil.copy2(ROOT / "LICENSE", stage / "LICENSE.txt")
    newline = "\r\n" if platform == "windows" else "\n"
    with open(stage / "README.txt", "w", encoding="utf-8", newline=newline) as f:
        f.write(readme(version, p))

    if platform == "windows":
        archive = out_dir / f"{name}.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
            for path in sorted(stage.rglob("*")):
                z.write(path, path.relative_to(out_dir).as_posix())
    else:
        archive = out_dir / f"{name}.tar.gz"

        def executable(info: tarfile.TarInfo) -> tarfile.TarInfo:
            # Keep the programs runnable whatever the build machine's umask.
            if info.isdir() or os.access(out_dir / info.name, os.X_OK) and not info.name.endswith(".txt"):
                info.mode |= stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
            return info

        with tarfile.open(archive, "w:gz") as t:
            t.add(stage, arcname=name, filter=executable)
    print(archive)


if __name__ == "__main__":
    main()
