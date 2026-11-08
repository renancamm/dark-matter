#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Download the latest GitHub release assets of every mod listing.

  fetch_releases.py <listings-dir> <downloads-dir>

Reads each <id>.toml listing, takes its [releases] table (`github = "owner/repo"`, optional
`tag_prefix`), and saves the newest non-draft release's .zip, .dll, .7z and .tar.gz assets to
<downloads-dir>/<id>/. Mods that already have a non-empty folder are skipped, so the script
can be re-run to resume. Unauthenticated GitHub API calls are limited to 60 per hour.

Downloaded files are untrusted. Nothing here extracts or runs them; see
`darkmatter-pipeline extract`.

Reference copy of `darkmatter-pipeline fetch-releases`, which replaces it (and downloads every
asset, not only the types above). Kept until the C# command has been run against GitHub and
compared; then delete this file.
"""
import argparse, json, os, re, sys, time, tomllib, urllib.request

ASSET_TYPES = (".zip", ".dll", ".7z", ".tar.gz")
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def get(url, raw=False, attempts=5):
    for i in range(attempts):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "dark-matter", "Accept": "application/vnd.github+json"})
            with urllib.request.urlopen(req, timeout=120) as r:
                data = r.read()
            return data if raw else json.loads(data)
        except Exception:
            if i == attempts - 1:
                raise
            time.sleep(2 * (i + 1))


def safe_name(s):
    """`s` if it is usable as a single path component, else None."""
    return s if isinstance(s, str) and SAFE_NAME.match(s) and s not in (".", "..") else None


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("listings", help="directory of <id>.toml listing files")
    ap.add_argument("out", help="download directory")
    a = ap.parse_args()

    for f in sorted(os.listdir(a.listings)):
        if not f.endswith(".toml"):
            continue
        try:
            with open(os.path.join(a.listings, f), "rb") as fh:
                listing = tomllib.load(fh)
        except tomllib.TOMLDecodeError as e:
            print(f"{f}: invalid TOML ({e})"); continue
        mid = safe_name(listing.get("id"))
        if not mid:
            print(f"{f}: missing or unsafe id {listing.get('id')!r}, skipped"); continue
        dest = os.path.join(a.out, mid)
        if os.path.isdir(dest) and os.listdir(dest):
            continue
        rel = listing.get("releases") or {}
        repo = rel.get("github")
        if not repo:
            print(f"{mid}: no GitHub release source"); continue
        try:
            releases = get(f"https://api.github.com/repos/{repo}/releases?per_page=30")
            prefix = rel.get("tag_prefix")
            releases = [r for r in releases if not r["draft"] and (not prefix or r["tag_name"].startswith(prefix))]
            if not releases:
                print(f"{mid}: no releases"); continue
            latest = releases[0]
            assets = [x for x in latest["assets"] if x["name"].lower().endswith(ASSET_TYPES)]
            os.makedirs(dest, exist_ok=True)
            saved = []
            for asset in assets:
                name = safe_name(asset["name"])
                if not name:
                    print(f"{mid}: unsafe asset name {asset['name']!r}, skipped"); continue
                data = get(asset["browser_download_url"], raw=True)
                with open(os.path.join(dest, name), "wb") as out:
                    out.write(data)
                saved.append(f"{name} ({len(data) // 1024} KiB)")
            print(f"{mid}: {latest['tag_name']} -> {', '.join(saved) or 'no matching assets'}")
        except Exception as e:
            print(f"{mid}: error: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
