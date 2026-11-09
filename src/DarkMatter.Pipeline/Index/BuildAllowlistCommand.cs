// SPDX-License-Identifier: MIT
using System.Globalization;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using DarkMatter.Pipeline.Extract;

namespace DarkMatter.Pipeline.Index;

/// <summary>
/// The trusted-library allowlist, built from the content index's snapshot: every release of each
/// trust anchor (by default the listings of type "mod-loader", e.g. StarMap and Oxidizer) that is
/// not yanked. Each archive is verified against its stamped SHA-256 (<see cref="ArchiveStore"/>);
/// the SHA-256 of every DLL and EXE inside it is then trusted. An archive that does not match its
/// stamp, or cannot be read completely, contributes nothing. With a library folder, every trusted
/// file is also written to <c>DIR/&lt;sha256&gt;/&lt;file name&gt;</c>, the input of
/// <c>darkmatter profile --library</c>.
/// </summary>
internal static class AllowlistBuilder {
    /// <summary>Which listings are trust anchors.</summary>
    internal sealed record Anchors(IReadOnlySet<string> Types, IReadOnlySet<string> ExtraIds, IReadOnlySet<string> Only) {
        public static readonly Anchors Default = new(new HashSet<string>(StringComparer.Ordinal) { "mod-loader" }, new HashSet<string>(), new HashSet<string>());

        public bool Includes(Listing l) =>
            (Only.Count == 0 || Only.Contains(l.Id)) && (Types.Contains(l.Type) || ExtraIds.Contains(l.Id));
    }

    /// <summary>The allowlist document (as <c>darkmatter analyze --allowlist</c> reads it) and how many anchor versions failed.</summary>
    internal sealed record Built(JsonObject Document, int TrustedFiles, int Failed);

    /// <summary>
    /// Every name an allowlist entry trusts its file under: <c>names</c>, and <c>name</c> for
    /// allowlists written before there was a list.
    /// </summary>
    public static IEnumerable<string> Names(JsonNode? entry) {
        var names = new SortedSet<string>(StringComparer.Ordinal);
        if (entry?["name"] is JsonValue n && n.TryGetValue<string>(out var one)) names.Add(one);
        foreach (var x in entry?["names"] as JsonArray ?? [])
            if (x is JsonValue v && v.TryGetValue<string>(out var name)) names.Add(name);
        return names;
    }

    public static async Task<Built> Build(Snapshot snapshot, ArchiveStore store, Anchors anchors, string? libraryDir, long maxBytes, TextWriter log) {
        var allow = new SortedDictionary<string, JsonObject>(StringComparer.Ordinal);
        // Every name a hash was published under: a later release that ships the same file under
        // another name must not take the first name off the trusted names.
        var names = new Dictionary<string, SortedSet<string>>(StringComparer.Ordinal);
        var ids = new List<string>();
        int failed = 0;
        var source = snapshot.Sources is JsonObject s && s["generated"] is JsonObject g && g["repository"] is JsonValue r && r.TryGetValue<string>(out var repo)
            ? repo
            : snapshot.Source;
        foreach (var listing in snapshot.Listings.Where(anchors.Includes)) {
            ids.Add(listing.Id);
            foreach (var release in listing.Releases.Where(x => !x.Yanked).Order(Snapshot.ReleaseOrder.Instance)) {
                var fetched = await store.Get(release, maxBytes);
                if (fetched.Path == null) {
                    failed++;
                    log.WriteLine($"  {listing.Id} {Text.Printable(release.Version)}: {fetched.Problem}; not trusted");
                    continue;
                }
                List<(string Sha, string Name, string Entry, byte[] Data)> found;
                try {
                    found = Read(fetched.Path, release.Sha256, maxBytes);
                } catch (Exception e) when (e is InvalidDataException or ArchiveException or IOException or NotSupportedException) {
                    // Nothing from an archive that cannot be read completely is trusted.
                    failed++;
                    log.WriteLine($"  {listing.Id} {Text.Printable(release.Version)}: not a readable zip ({e.Message}); not trusted");
                    continue;
                }
                foreach (var (sha, name, entry, data) in found) {
                    if (libraryDir != null) WriteLibraryFile(libraryDir, sha, entry, data, log);
                    if (!names.TryGetValue(sha, out var all)) names[sha] = all = new SortedSet<string>(StringComparer.Ordinal);
                    all.Add(name);
                    // The newest release (by semantic version) that ships the file describes it.
                    allow[sha] = new JsonObject {
                        ["name"] = name,
                        ["names"] = new JsonArray([.. all.Select(x => (JsonNode?)JsonValue.Create(x))]),
                        ["trust"] = "index-release-stamp",
                        ["anchor"] = listing.Id,
                        ["anchor_type"] = listing.Type,
                        ["version"] = release.Version,
                        ["archive_sha256"] = release.Sha256,
                        ["source"] = source,
                    };
                }
                log.WriteLine($"  {listing.Id,-16} {Text.Printable(release.Version),-8} verified archive -> {found.Count} DLL/EXE hashes trusted");
            }
        }
        var libraries = new JsonObject();
        foreach (var (sha, entry) in allow) libraries[sha] = entry;
        var doc = new JsonObject {
            ["note"] = "Per-file allowlist built from the content index's snapshot. Each DLL/EXE hash comes from an archive whose bytes "
                + "were verified against its release's stamped download.sha256. Anchors: listings of type "
                + string.Join(", ", anchors.Types.Order(StringComparer.Ordinal)) + (anchors.ExtraIds.Count > 0 ? " and " + string.Join(", ", anchors.ExtraIds.Order(StringComparer.Ordinal)) : "") + ".",
            ["snapshot"] = snapshot.Describe(),
            ["anchors"] = new JsonArray([.. ids.Select(i => (JsonNode?)JsonValue.Create(i))]),
            ["libraries"] = libraries,
        };
        return new Built(doc, allow.Count, failed);
    }

    /// <summary>
    /// The DLLs and EXEs of a verified archive, with their SHA-256. The archive is read into memory
    /// and hashed there again, so nothing can change it between the check and the use.
    /// </summary>
    static List<(string Sha, string Name, string Entry, byte[] Data)> Read(string path, string want, long maxBytes) {
        if (new FileInfo(path).Length > maxBytes) throw new InvalidDataException($"over the {maxBytes}-byte limit");
        var blob = File.ReadAllBytes(path);
        if (Convert.ToHexStringLower(SHA256.HashData(blob)) != want) throw new InvalidDataException("the archive changed after it was verified");
        var found = new List<(string, string, string, byte[])>();
        using var zip = new ZipArchive(new MemoryStream(blob, writable: false), ZipArchiveMode.Read, leaveOpen: false, Archives.Cp437);
        foreach (var e in zip.Entries) {
            if (!e.FullName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) && !e.FullName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) continue;
            var data = Archives.ReadEntry(e, maxBytes);
            var name = e.FullName.Replace('\\', '/').Split('/')[^1];
            found.Add((Convert.ToHexStringLower(SHA256.HashData(data)), name[..^4], e.FullName, data));
        }
        return found;
    }

    /// <summary>
    /// Writes one trusted file as ROOT/&lt;sha&gt;/&lt;file name&gt;. Only the entry's base name is used,
    /// so an archive entry cannot place a file outside its folder.
    /// </summary>
    static void WriteLibraryFile(string root, string sha, string entry, byte[] data, TextWriter log) {
        var name = entry.Replace('\\', '/').Split('/')[^1];
        if (name.Length == 0 || name is "." or ".." || name.Any(char.IsControl)) {
            log.WriteLine($"  {Text.Quote(entry)}: unusable file name, not written to the library folder");
            return;
        }
        var folder = Path.Join(root, sha);
        Directory.CreateDirectory(folder);
        var path = Path.Join(folder, name);
        if (File.Exists(path) && ArchiveStore.Hash(path) == sha) return;
        var tmp = path + ".part";
        File.WriteAllBytes(tmp, data);
        File.Move(tmp, path, overwrite: true);
    }
}

/// <summary>
/// <c>darkmatter-pipeline build-allowlist</c>: write the trusted-library allowlist built from the
/// content index's snapshot (<see cref="AllowlistBuilder"/>).
/// </summary>
internal static class BuildAllowlistCommand {
    static readonly string[] Valued = ["--snapshot", "--anchor-types", "--anchor-ids", "--only", "--cache-dir", "--library-dir", "--out", "--max-bytes", "--retries"];

    public static async Task<int> Run(IReadOnlyList<string> argv) {
        var o = Options.Parse(argv, Valued, []);
        if (o.Positional.Count > 0) throw new UsageException($"unexpected argument {o.Positional[0]}");
        var output = o.Get("--out") ?? throw new UsageException("build-allowlist needs --out FILE");
        var anchors = new AllowlistBuilder.Anchors(List(o.Get("--anchor-types") ?? "mod-loader"), List(o.Get("--anchor-ids")), List(o.Get("--only")));
        var cache = o.Get("--cache-dir") ?? Path.Join(Path.GetTempPath(), "ksa-archive-cache");
        var libraryDir = o.Get("--library-dir") is { Length: > 0 } d ? d : null;
        var maxBytes = o.Number("--max-bytes", 1L << 30, 1);
        using var http = new Http(attempts: (int)o.Number("--retries", 3, 0) + 1, pause: TimeSpan.FromSeconds(1.5), timeout: TimeSpan.FromSeconds(180));
        var snapshot = await SnapshotSource.Load(http, o.Get("--snapshot") ?? Snapshot.DefaultUrl, null, Console.Error);
        var built = await AllowlistBuilder.Build(snapshot, new ArchiveStore(cache, http), anchors, libraryDir, maxBytes, Console.Out);
        if (built.TrustedFiles == 0) Console.Error.WriteLine("warning: no trusted hashes collected; the allowlist is empty");
        Text.WriteJson(output, built.Document);
        Console.WriteLine($"\n{built.Document["anchors"]!.AsArray().Count} anchors -> {built.TrustedFiles} trusted file hashes -> {output}"
            + (built.Failed > 0 ? $" ({built.Failed} anchor versions could not be verified)" : ""));
        if (libraryDir != null)
            Console.WriteLine($"trusted files written to {libraryDir}; profile them with:\n"
                + $"  dotnet out/darkmatter.dll profile --library --allowlist {output} --game-profile GAME-PROFILE "
                + $"--out library-profiles.json {Path.Join(libraryDir, "*", "*")}");
        return built.Failed > 0 ? 1 : 0;
    }

    static HashSet<string> List(string? csv) =>
        (csv ?? "").Split(',').Select(x => x.Trim()).Where(x => x.Length > 0).ToHashSet(StringComparer.Ordinal);
}

/// <summary>Reads the snapshot from a file or an HTTPS URL.</summary>
internal static class SnapshotSource {
    /// <param name="http">For a URL.</param>
    /// <param name="source">A file path or an HTTPS URL.</param>
    /// <param name="copy">
    /// Where a downloaded snapshot is kept (also the fallback when the download fails or is not a
    /// usable snapshot); null for none. A download replaces it only once it has been read as a
    /// snapshot, so a bad download never replaces the last good copy.
    /// </param>
    /// <param name="log">Where the snapshot's problems are reported.</param>
    public static async Task<Snapshot> Load(Http http, string source, string? copy, TextWriter log) {
        if (!source.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) {
            if (!File.Exists(source)) throw new UsageException($"snapshot not found: {source}");
            return Report(Snapshot.Parse(await File.ReadAllBytesAsync(source), source), log);
        }
        var target = copy != null ? copy + ".download" : Path.Join(Path.GetTempPath(), $"darkmatter-snapshot-{Environment.ProcessId}.json");
        try {
            try {
                await http.Download(source, target, 256L << 20);
            } catch (Exception e) when (e is FetchException or RateLimitException or IOException or UnauthorizedAccessException) {
                return Stale(copy, $"cannot download the snapshot ({e.Message})", log);
            }
            Snapshot snapshot;
            try {
                snapshot = Snapshot.Parse(await File.ReadAllBytesAsync(target), source);
            } catch (Exception e) when (e is not OutOfMemoryException) {
                return Stale(copy, $"the downloaded snapshot cannot be read ({e.Message})", log);
            }
            if (copy != null) File.Move(target, copy, overwrite: true);
            return Report(snapshot, log);
        } finally {
            File.Delete(target);  // when it was not kept
        }
    }

    /// <summary>The copy kept by an earlier run, used when the snapshot cannot be downloaded; it says plainly that it may be out of date.</summary>
    static Snapshot Stale(string? copy, string problem, TextWriter log) {
        if (copy == null || !File.Exists(copy)) throw new FetchException($"cannot read the snapshot: {problem}");
        var saved = File.GetLastWriteTimeUtc(copy).ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);
        log.WriteLine($"warning: {problem}; using the copy an earlier run kept, {copy} (saved {saved} UTC). It may be out of date: "
            + "releases published or yanked since then are not seen, and a trust anchor release yanked since then is still trusted");
        return Report(Snapshot.Parse(File.ReadAllBytes(copy), copy).AsStale($"{problem}; the copy saved {saved} UTC was used, and may be out of date"), log);
    }

    static Snapshot Report(Snapshot s, TextWriter log) {
        foreach (var p in s.Problems) log.WriteLine($"snapshot: {p}");
        return s;
    }
}
