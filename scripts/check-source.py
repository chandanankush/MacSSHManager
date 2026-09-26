#!/usr/bin/env python3
"""Validate publishable source, documentation links, icons, and optional app output."""

import argparse
import json
import plistlib
import re
import struct
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SECRET_PATTERNS = [
    re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    re.compile(rb"\bgh[oprsu]_[A-Za-z0-9]{30,}\b"),
    re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{30,}\b"),
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(rb"\bsk-[A-Za-z0-9_-]{32,}\b"),
]


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def source_files():
    output = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
    )
    for name in sorted(set(output.decode().split("\0")) - {""}):
        path = ROOT / name
        require(not path.is_symlink(), f"Unexpected source symlink: {name}")
        if path.is_file():
            yield path


def check_source():
    files = list(source_files())
    require(files, "No source files found")
    for path in files:
        name = path.relative_to(ROOT)
        require(
            path.suffix.lower() not in {".p12", ".pfx", ".key", ".pem", ".cer", ".pkg", ".dmg"}
            and not path.name.startswith(".env"),
            f"Signing material, credentials, or generated installer in source: {name}",
        )
        data = path.read_bytes()
        require(not any(pattern.search(data) for pattern in SECRET_PATTERNS), f"Possible credential in {name}")
    print(f"Source scan passed for {len(files)} files (common credential patterns only).")


def check_links():
    documents = [ROOT / name for name in ("README.md", "CONTRIBUTING.md", "SECURITY.md")]
    documents.extend((ROOT / "docs").glob("*.md"))
    for document in documents:
        text = document.read_text()
        for link in re.findall(r"\]\(([^\s)]+)(?:\s+\"[^\"]*\")?\)", text):
            if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", link) or link.startswith("#"):
                continue
            target, _, anchor = link.partition("#")
            destination = document.parent / target
            require(destination.exists(), f"Broken link in {document.name}: {link}")
            if anchor and destination.suffix == ".md":
                headings = re.findall(r"^#{1,6}\s+(.+)$", destination.read_text(), flags=re.M)
                slugs = {re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-") for heading in headings}
                require(anchor in slugs, f"Broken section link in {document.name}: {link}")
    for image in re.findall(r'<img\b[^>]*\bsrc="([^"]+)"', (ROOT / "README.md").read_text()):
        require((ROOT / image).is_file(), f"Missing README image: {image}")
    print("Documentation links and README image passed.")


def check_icons():
    catalog = ROOT / "Resources/Assets.xcassets/AppIcon.appiconset"
    entries = json.loads((catalog / "Contents.json").read_text())["images"]
    expected_slots = {(size, scale) for size in (16, 32, 128, 256, 512) for scale in (1, 2)}
    found_slots = set()
    for entry in entries:
        size, height = map(int, entry["size"].split("x"))
        scale = int(entry["scale"].removesuffix("x"))
        require(entry["idiom"] == "mac" and size == height, "Unexpected icon slot")
        found_slots.add((size, scale))
        data = (catalog / entry["filename"]).read_bytes()
        require(data[:8] == b"\x89PNG\r\n\x1a\n" and data[12:16] == b"IHDR", "Invalid icon PNG")
        width, height, depth, color = struct.unpack(">IIBB", data[16:26])
        require((width, height) == (size * scale, size * scale), f"Wrong dimensions: {entry['filename']}")
        require(depth == 8 and color == 6, f"Expected RGBA icon: {entry['filename']}")
    require(len(entries) == 10 and found_slots == expected_slots, "Incomplete macOS icon catalog")
    print("All ten macOS icon slots passed.")


def check_app(path):
    info = plistlib.loads((path / "Contents/Info.plist").read_bytes())
    for key in ("CFBundleName", "CFBundleDisplayName", "CFBundleExecutable"):
        require(info.get(key) == "Mac SSH Manager", f"Wrong built app {key}")
    require(info.get("CFBundleIconName") == "AppIcon", "Wrong built app icon name")
    resources = path / "Contents/Resources"
    for name in ("AppIcon.icns", "Assets.car"):
        require((resources / name).is_file() and (resources / name).stat().st_size > 0, f"Missing compiled {name}")
    print("Built app names and compiled icon passed.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, help="Also check a built Mac SSH Manager.app")
    arguments = parser.parse_args()
    check_source()
    check_links()
    check_icons()
    require("MIT License" in (ROOT / "LICENSE").read_text(), "Missing MIT license")
    if arguments.app:
        check_app(arguments.app.resolve())


if __name__ == "__main__":
    main()
