#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the trusted-library allowlist from the content index, at run time.

Trust is rooted in the index's release ledger (KSAModding/content-index-releases):
one stamp per mod per version, each carrying the archive's authoritative SHA-256.
This tool, every run:

  1. reads the ledger's tree live (so new releases are picked up automatically),
  2. auto-detects trust anchors by `type` (default: mod-loader, e.g. StarMap),
  3. for every version stamp of each anchor: downloads the release archive,
     VERIFIES it against the stamp's download.sha256, unzips it, and records the
     SHA-256 of each managed DLL/EXE inside.

The result is a per-file allowlist the analyzer trusts by hash, covering the full
version history of every anchor, rooted in the index's own stamped hashes. An
archive whose bytes do not match its stamp is refused, never trusted.

With --library-dir, every trusted file is also written to DIR/<sha256>/<file name>.
Those files are the input of `darkmatter profile --library`, which profiles what each
trusted library member can do; the analyzer applies the profiles to calls into them,
and a trusted library without a profile for every version counts as not analyzed.

Archives are cached by their stamp hash, so each version downloads at most once.

Reference copy of `darkmatter-pipeline build-allowlist`, which replaces it (same arguments).
Kept until the C# command has been run against GitHub and compared; then delete this file.
"""
import argparse, hashlib, io, json, os, re, sys, time, urllib.request, zipfile

API = "https://api.github.com/repos/{repo}/git/trees/main?recursive=1"
RAW = "https://raw.githubusercontent.com/{repo}/main/{path}"

def get(url, raw=False):
    """GET with retries. Returns bytes when raw, else parsed JSON."""
    last = None
    for attempt in range(4):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ksa-allowlist", "Accept": "application/vnd.github+json"})
            with urllib.request.urlopen(req, timeout=180) as r:
                data = r.read()
            return data if raw else json.loads(data)
        except Exception as e:
            last = e; time.sleep(1.5 * (attempt + 1))
    raise last

def stamp_paths(repo, local_dir=None):
    """Every releases/<id>/<version>.json path, live from the ledger tree (or a
    local checkout fallback for offline/rate-limited runs)."""
    try:
        tree = get(API.format(repo=repo))["tree"]
        return [e["path"] for e in tree
                if e["type"] == "blob" and e["path"].startswith("releases/") and e["path"].endswith(".json")]
    except Exception as e:
        if local_dir:
            sys.stderr.write(f"live tree unavailable ({e}); using local checkout {local_dir}\n")
            out = []
            for root, _, files in os.walk(os.path.join(local_dir, "releases")):
                for f in files:
                    if f.endswith(".json"):
                        out.append(os.path.relpath(os.path.join(root, f), local_dir))
            return out
        raise

def read_stamp(repo, path, local_dir=None):
    if local_dir and os.path.exists(os.path.join(local_dir, path)):
        with open(os.path.join(local_dir, path), "rb") as f:
            return json.load(f)
    return get(RAW.format(repo=repo, path=path))

def fetch_verified(url, want, cache_dir):
    """Archive bytes whose SHA-256 equals `want`, from the cache or the network; None if the
    download fails or does not match. A cached copy that no longer matches is discarded."""
    cache = os.path.join(cache_dir, want + ".zip")
    if os.path.exists(cache):
        with open(cache, "rb") as f:
            blob = f.read()
        if hashlib.sha256(blob).hexdigest() == want:
            return blob
        os.remove(cache)
    blob = get(url, raw=True)
    if hashlib.sha256(blob).hexdigest() != want:
        return None
    tmp = cache + ".part"
    with open(tmp, "wb") as f:
        f.write(blob)
    os.replace(tmp, cache)
    return blob

def write_library_file(root, sha, entry, data):
    """Writes one trusted file as root/<sha>/<file name>. Only the entry's base name is used, so
    an archive entry cannot place a file outside its folder."""
    base = os.path.basename(entry.replace("\\", "/"))
    if not base or base in (".", "..") or "\0" in base:
        sys.stderr.write(f"  {entry}: unusable file name, not written to the library folder\n")
        return
    folder = os.path.join(root, sha)
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, base)
    tmp = path + ".part"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--releases-repo", default="KSAModding/content-index-releases")
    ap.add_argument("--anchor-types", default="mod-loader", help="comma list of listing types to trust")
    ap.add_argument("--anchor-ids", default="", help="extra ids to trust regardless of type")
    ap.add_argument("--only", default="", help="limit to these ids (comma list)")
    ap.add_argument("--cache-dir", default=os.path.join(os.environ.get("TMPDIR", "/tmp"), "ksa-archive-cache"))
    ap.add_argument("--local-fallback", default="", help="path to a content-index-releases checkout for offline runs")
    ap.add_argument("--library-dir", default="", help="also write each trusted file to DIR/<sha256>/<file name>, "
                    "the input of `darkmatter profile --library`")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    types = set(t.strip() for t in a.anchor_types.split(",") if t.strip())
    extra = set(i.strip() for i in a.anchor_ids.split(",") if i.strip())
    only = set(i.strip() for i in a.only.split(",") if i.strip())
    local = a.local_fallback or None
    os.makedirs(a.cache_dir, exist_ok=True)

    paths = stamp_paths(a.releases_repo, local)
    by_id = {}
    for p in paths:
        parts = p.split("/")
        if len(parts) == 3:
            by_id.setdefault(parts[1], []).append(p)

    # anchor detection: read one stamp per id for its `type`
    anchors = []
    for mid, ps in sorted(by_id.items()):
        if only and mid not in only:
            continue
        typ = read_stamp(a.releases_repo, ps[0], local).get("type", "")
        if typ in types or mid in extra:
            anchors.append((mid, typ, ps))

    allow = {}
    for mid, typ, ps in anchors:
        for p in sorted(ps):
            stamp = read_stamp(a.releases_repo, p, local)
            dl = stamp.get("download") or {}
            url, want = dl.get("url"), (dl.get("sha256") or "").lower()
            ver = stamp.get("version", "?")
            if not url or not want:
                sys.stderr.write(f"  {mid} {ver}: no download hash in stamp, skipped\n"); continue
            if not re.fullmatch(r"[0-9a-f]{64}", want):
                sys.stderr.write(f"  {mid} {ver}: malformed download.sha256 in stamp, skipped\n"); continue
            try:
                blob = fetch_verified(url, want, a.cache_dir)
            except Exception as e:
                sys.stderr.write(f"  {mid} {ver}: download failed ({e}), skipped\n"); continue
            if blob is None:                                  # bytes must match the stamp, or no trust
                sys.stderr.write(f"  {mid} {ver}: archive hash does not match stamp {want[:12]}, refused\n")
                continue
            n = 0
            try:
                z = zipfile.ZipFile(io.BytesIO(blob))
            except Exception as e:
                sys.stderr.write(f"  {mid} {ver}: not a readable zip ({e}), skipped\n"); continue
            for name in z.namelist():
                if name.lower().endswith((".dll", ".exe")):
                    data = z.read(name)
                    h = hashlib.sha256(data).hexdigest()
                    if a.library_dir:
                        write_library_file(a.library_dir, h, name, data)
                    allow[h] = {"name": os.path.basename(name.replace("\\", "/"))[:-4], "trust": "index-release-stamp",
                                "anchor": mid, "anchor_type": typ, "version": ver,
                                "archive_sha256": want, "source": a.releases_repo}
                    n += 1
            print(f"  {mid:16} {ver:8} verified archive -> {n} DLL/EXE hashes trusted")

    if not allow:
        sys.stderr.write("warning: no trusted hashes collected; the allowlist is empty\n")
    with open(a.out, "w") as f:
        json.dump({"note": "Per-file allowlist expanded from the content-index release ledger at run time. "
                           "Each DLL/EXE hash comes from an archive whose bytes were verified against the "
                           "stamp's download.sha256. Anchors auto-detected by type=" + a.anchor_types + ".",
                   "anchors": [m for m, _, _ in anchors], "libraries": allow},
                  f, indent=1)
    print(f"\n{len(anchors)} anchors -> {len(allow)} trusted file hashes -> {a.out}")
    if a.library_dir:
        print(f"trusted files written to {a.library_dir}; profile them with:\n"
              f"  dotnet out/darkmatter.dll profile --library --allowlist {a.out} --game-profile GAME-PROFILE "
              f"--out library-profiles.json {os.path.join(a.library_dir, '*', '*')}")

if __name__ == "__main__":
    main()
