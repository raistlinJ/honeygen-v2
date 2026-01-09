#!/usr/bin/env python3
"""Download a small set of open-source service binaries into ./analysis.

This is meant for local testing only.

Notes:
- Downloads are fetched over HTTPS from official project sources.
- Most assets come from GitHub Releases (latest), resolved via the public API.
- No executables are run by this script.

Usage:
  python scripts/fetch_service_binaries.py

Optional:
  python scripts/fetch_service_binaries.py --dest analysis
  python scripts/fetch_service_binaries.py --force
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import stat
import tarfile
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class GitHubAssetRule:
    owner: str
    repo: str
    asset_name_regex: str
    # Path inside archive to extract. If None, download is expected to be the binary itself.
    extract_member_regex: str | None
    output_name: str


def _http_get_bytes(url: str, *, headers: dict[str, str] | None = None) -> bytes:
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read()


def _download_to_path(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    req = urllib.request.Request(url, headers={"User-Agent": "pyside-pin-instruction-logger/analysis-fetch"})
    with urllib.request.urlopen(req, timeout=600) as resp, tmp.open("wb") as f:
        while True:
            chunk = resp.read(1024 * 256)
            if not chunk:
                break
            f.write(chunk)
    tmp.replace(dest)


def _github_latest_release(owner: str, repo: str) -> dict:
    url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
    data = _http_get_bytes(url, headers={"Accept": "application/vnd.github+json"})
    return json.loads(data.decode("utf-8"))


def _pick_asset(release: dict, asset_name_regex: str) -> dict:
    rx = re.compile(asset_name_regex)
    assets = release.get("assets") or []
    for asset in assets:
        name = str(asset.get("name") or "")
        if rx.search(name):
            return asset
    names = [str(a.get("name") or "") for a in assets]
    raise RuntimeError(f"No asset matched /{asset_name_regex}/. Available: {names}")


def _extract_from_tar_bytes(data: bytes, member_regex: str) -> bytes:
    rx = re.compile(member_regex)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        members = tf.getmembers()
        for m in members:
            if not m.isfile():
                continue
            if rx.search(m.name):
                f = tf.extractfile(m)
                if f is None:
                    break
                return f.read()
        names = [m.name for m in members if m.isfile()]
        raise RuntimeError(f"No tar member matched /{member_regex}/. Available: {names[:50]}")


def _extract_from_zip_bytes(data: bytes, member_regex: str) -> bytes:
    rx = re.compile(member_regex)
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for name in zf.namelist():
            if rx.search(name):
                return zf.read(name)
        raise RuntimeError(f"No zip member matched /{member_regex}/. Available: {zf.namelist()[:50]}")


def _write_executable(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _download_github_rule(rule: GitHubAssetRule, dest_dir: Path, *, force: bool) -> tuple[Path, str]:
    out_path = dest_dir / rule.output_name
    if out_path.exists() and not force:
        return out_path, "(skipped; exists)"

    rel = _github_latest_release(rule.owner, rule.repo)
    asset = _pick_asset(rel, rule.asset_name_regex)
    url = str(asset.get("browser_download_url"))

    archive_bytes = _http_get_bytes(url, headers={"User-Agent": "pyside-pin-instruction-logger/analysis-fetch"})
    if rule.extract_member_regex is None:
        _write_executable(out_path, archive_bytes)
        return out_path, url

    # Try tar first, then zip.
    try:
        payload = _extract_from_tar_bytes(archive_bytes, rule.extract_member_regex)
    except tarfile.TarError:
        payload = _extract_from_zip_bytes(archive_bytes, rule.extract_member_regex)

    _write_executable(out_path, payload)
    return out_path, url


def _download_direct(url: str, dest_path: Path, *, force: bool) -> tuple[Path, str]:
    if dest_path.exists() and not force:
        return dest_path, "(skipped; exists)"
    _download_to_path(url, dest_path)
    mode = dest_path.stat().st_mode
    dest_path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return dest_path, url


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dest", default="analysis", help="Destination folder (default: analysis)")
    parser.add_argument("--force", action="store_true", help="Overwrite existing files")
    args = parser.parse_args(list(argv) if argv is not None else None)

    dest_dir = Path(args.dest)
    dest_dir.mkdir(parents=True, exist_ok=True)

    # 10 distinct services.
    rules: list[GitHubAssetRule] = [
        # Reverse proxy / edge router
        GitHubAssetRule(
            owner="traefik",
            repo="traefik",
            asset_name_regex=r"traefik_.*linux_amd64\.tar\.gz$",
            extract_member_regex=r"(^|/)traefik$",
            output_name="traefik",
        ),
        # Messaging
        GitHubAssetRule(
            owner="nats-io",
            repo="nats-server",
            asset_name_regex=r"nats-server-.*linux-amd64\.tar\.gz$",
            extract_member_regex=r"(^|/)nats-server$",
            output_name="nats-server",
        ),
        # Monitoring
        GitHubAssetRule(
            owner="prometheus",
            repo="prometheus",
            asset_name_regex=r"prometheus-.*\.linux-amd64\.tar\.gz$",
            extract_member_regex=r"(^|/)prometheus$",
            output_name="prometheus",
        ),
        GitHubAssetRule(
            owner="prometheus",
            repo="node_exporter",
            asset_name_regex=r"node_exporter-.*\.linux-amd64\.tar\.gz$",
            extract_member_regex=r"(^|/)node_exporter$",
            output_name="node_exporter",
        ),
        GitHubAssetRule(
            owner="prometheus",
            repo="alertmanager",
            asset_name_regex=r"alertmanager-.*\.linux-amd64\.tar\.gz$",
            extract_member_regex=r"(^|/)alertmanager$",
            output_name="alertmanager",
        ),
        # DNS
        GitHubAssetRule(
            owner="coredns",
            repo="coredns",
            asset_name_regex=r"coredns_.*_linux_amd64\.tgz$",
            extract_member_regex=r"(^|/)coredns$",
            output_name="coredns",
        ),
        # Git hosting
        GitHubAssetRule(
            owner="go-gitea",
            repo="gitea",
            asset_name_regex=r"gitea-.*-linux-amd64$",
            extract_member_regex=None,
            output_name="gitea",
        ),
        # File sync
        GitHubAssetRule(
            owner="syncthing",
            repo="syncthing",
            asset_name_regex=r"syncthing-linux-amd64-v.*\.tar\.gz$",
            extract_member_regex=r"(^|/)syncthing$",
            output_name="syncthing",
        ),
    ]

    direct_downloads: list[tuple[str, str]] = [
        # Web server
        ("https://caddyserver.com/api/download?os=linux&arch=amd64", "caddy"),
        # Object storage
        ("https://dl.min.io/server/minio/release/linux-amd64/minio", "minio"),
    ]

    results: list[tuple[str, Path, str]] = []

    for url, name in direct_downloads:
        path, src = _download_direct(url, dest_dir / name, force=args.force)
        results.append((name, path, src))

    for rule in rules:
        path, src = _download_github_rule(rule, dest_dir, force=args.force)
        results.append((rule.output_name, path, src))

    manifest = dest_dir / "THIRD_PARTY_BINARIES.txt"
    lines = [
        "These executables were downloaded for local testing.",
        "",
        "Name\tPath\tSource",
    ]
    for name, path, src in sorted(results, key=lambda t: t[0]):
        lines.append(f"{name}\t{path}\t{src}")
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"Wrote {len(results)} binaries into {dest_dir}/")
    print(f"Wrote manifest: {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
