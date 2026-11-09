# Legacy download scripts

The first version of the pipeline, kept only as a fallback. Use `darkmatter-pipeline scan` instead
(see [docs/usage.md](../../docs/usage.md)).

| Script | Replaced by |
|---|---|
| `fetch_releases.py` | the downloads of `darkmatter-pipeline scan` |
| `build_allowlist.py` | `darkmatter-pipeline build-allowlist` (same arguments) |

`scan` and `build-allowlist` have not yet downloaded from the live content index: .NET could not
open TLS connections in the environment they were written in, and a full index scan has so far run
on archives fetched by another client. Once both have run live, delete this folder.

Requires Python 3.11 or later (`fetch_releases.py` reads TOML with `tomllib`).
