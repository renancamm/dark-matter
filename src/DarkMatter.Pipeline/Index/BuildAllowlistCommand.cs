// SPDX-License-Identifier: MIT
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using DarkMatter.Pipeline.Extract;

namespace DarkMatter.Pipeline.Index;

/// <summary>
/// <c>darkmatter-pipeline build-allowlist</c>: build the trusted-library allowlist from the
/// content index's release ledger (KSAModding/content-index-releases), at run time.
/// <list type="number">
/// <item>Reads the ledger's tree live (new releases are picked up automatically).</item>
/// <item>Detects trust anchors by listing type (default mod-loader, e.g. StarMap).</item>
/// <item>For every version stamp of each anchor: downloads the release archive, verifies it
/// against the stamp's download.sha256, and records the SHA-256 of each DLL and EXE inside.</item>
/// </list>
/// An archive whose bytes do not match its stamp is refused, never trusted. Archives are cached
/// by their stamp hash, so each version downloads at most once. With <c>--library-dir</c>, every
/// trusted file is also written to <c>DIR/&lt;sha256&gt;/&lt;file name&gt;</c>, the input of
/// <c>darkmatter profile --library</c>.
/// </summary>
internal static partial class BuildAllowlistCommand {
    static readonly string[] Valued = ["--releases-repo", "--anchor-types", "--anchor-ids", "--only", "--cache-dir", "--local-fallback", "--library-dir", "--out", "--max-bytes"];

    [GeneratedRegex("^[0-9a-f]{64}$")]
    private static partial Regex Sha256Hex();

    [GeneratedRegex("^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$")]
    private static partial Regex RepoName();

    sealed record Settings(string Repo, string? Local, string Cache, string? LibraryDir, long MaxBytes);

    public static async Task<int> Run(IReadOnlyList<string> argv) {
        var o = Options.Parse(argv, Valued, []);
        if (o.Positional.Count > 0) throw new UsageException($"unexpected argument {o.Positional[0]}");
        var output = o.Get("--out") ?? throw new UsageException("build-allowlist needs --out FILE");
        var repo = o.Get("--releases-repo") ?? "KSAModding/content-index-releases";
        if (!RepoName().IsMatch(repo)) throw new UsageException($"--releases-repo is not a GitHub owner/repository: {repo}");
        var anchorTypes = o.Get("--anchor-types") ?? "mod-loader";
        var types = List(anchorTypes);
        var extra = List(o.Get("--anchor-ids"));
        var only = List(o.Get("--only"));
        var s = new Settings(
            repo,
            o.Get("--local-fallback") is { Length: > 0 } l ? l : null,
            o.Get("--cache-dir") ?? Path.Join(Path.GetTempPath(), "ksa-archive-cache"),
            o.Get("--library-dir") is { Length: > 0 } d ? d : null,
            o.Number("--max-bytes", 1L << 30, 1));
        Directory.CreateDirectory(s.Cache);

        using var http = new Http(attempts: 4, pause: TimeSpan.FromSeconds(1.5), timeout: TimeSpan.FromSeconds(180));
        List<string> paths;
        try {
            paths = await StampPaths(http, s);
        } catch (Exception e) when (e is FetchException or RateLimitException or JsonException or InvalidDataException) {
            Console.Error.WriteLine($"error: cannot list the ledger: {e.Message}");
            return 1;
        }
        var byId = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var p in paths) {
            var parts = p.Split('/');
            if (parts.Length != 3) continue;
            if (!byId.TryGetValue(parts[1], out var list)) byId[parts[1]] = list = [];
            list.Add(p);
        }

        // Anchor detection: one stamp per id gives its listing type.
        var anchors = new List<(string Id, string Type, List<string> Paths)>();
        foreach (var (mid, ps) in byId.OrderBy(kv => kv.Key, StringComparer.Ordinal)) {
            if (only.Count > 0 && !only.Contains(mid)) continue;
            string type;
            try {
                using var stamp = await ReadStamp(http, s, ps[0]);
                type = Str(stamp.RootElement, "type") ?? "";
            } catch (Exception e) when (e is FetchException or RateLimitException or JsonException or InvalidDataException or IOException) {
                Console.Error.WriteLine($"  {mid}: cannot read stamp {ps[0]} ({e.Message}), not considered");
                continue;
            }
            if (types.Contains(type) || extra.Contains(mid)) anchors.Add((mid, type, ps));
        }

        var allow = new JsonObject();
        foreach (var (mid, type, ps) in anchors) {
            foreach (var p in ps.Order(StringComparer.Ordinal)) {
                try {
                    await Version(http, s, mid, type, p, allow);
                } catch (Exception e) when (e is FetchException or RateLimitException or JsonException or InvalidDataException or IOException) {
                    Console.Error.WriteLine($"  {mid} {p}: {e.Message}, skipped");
                }
            }
        }

        if (allow.Count == 0) Console.Error.WriteLine("warning: no trusted hashes collected; the allowlist is empty");
        Text.WriteJson(output, new JsonObject {
            ["note"] = "Per-file allowlist expanded from the content-index release ledger at run time. "
                + "Each DLL/EXE hash comes from an archive whose bytes were verified against the "
                + "stamp's download.sha256. Anchors auto-detected by type=" + anchorTypes + ".",
            ["anchors"] = new JsonArray([.. anchors.Select(a => (JsonNode?)JsonValue.Create(a.Id))]),
            ["libraries"] = allow,
        });
        Console.WriteLine($"\n{anchors.Count} anchors -> {allow.Count} trusted file hashes -> {output}");
        if (s.LibraryDir != null)
            Console.WriteLine($"trusted files written to {s.LibraryDir}; profile them with:\n"
                + $"  dotnet out/darkmatter.dll profile --library --allowlist {output} --game-profile GAME-PROFILE "
                + $"--out library-profiles.json {Path.Join(s.LibraryDir, "*", "*")}");
        return 0;
    }

    static HashSet<string> List(string? csv) =>
        (csv ?? "").Split(',').Select(x => x.Trim()).Where(x => x.Length > 0).ToHashSet(StringComparer.Ordinal);

    static string? Str(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    /// <summary>Every releases/&lt;id&gt;/&lt;version&gt;.json path: live from the ledger tree, or from a local checkout if that fails.</summary>
    static async Task<List<string>> StampPaths(Http http, Settings s) {
        try {
            using var doc = await http.GetJson($"https://api.github.com/repos/{s.Repo}/git/trees/main?recursive=1");
            var root = doc.RootElement;
            if (root.TryGetProperty("truncated", out var t) && t.ValueKind == JsonValueKind.True)
                Console.Error.WriteLine("warning: the ledger tree is truncated; versions missing from it are not trusted");
            return [.. root.GetProperty("tree").EnumerateArray()
                .Where(e => Str(e, "type") == "blob")
                .Select(e => Str(e, "path") ?? "")
                .Where(p => p.StartsWith("releases/", StringComparison.Ordinal) && p.EndsWith(".json", StringComparison.Ordinal))];
        } catch (Exception e) when (s.Local != null && e is FetchException or RateLimitException or JsonException or InvalidDataException or KeyNotFoundException) {
            Console.Error.WriteLine($"live tree unavailable ({e.Message}); using local checkout {s.Local}");
            var releases = Path.Join(s.Local, "releases");
            return [.. Directory.EnumerateFiles(releases, "*.json", SearchOption.AllDirectories)
                .Select(f => Path.GetRelativePath(s.Local, f).Replace(Path.DirectorySeparatorChar, '/'))];
        }
    }

    static async Task<JsonDocument> ReadStamp(Http http, Settings s, string path) {
        var parts = path.Split('/');
        if (parts.Any(p => p.Length == 0 || p is "." or ".." || p.Any(char.IsControl) || p.Contains('\\', StringComparison.Ordinal)))
            throw new InvalidDataException($"unusable stamp path {Text.Quote(path)}");
        if (s.Local != null && Path.Join([s.Local, .. parts]) is var local && File.Exists(local)) {
            using var f = File.OpenRead(local);
            return await JsonDocument.ParseAsync(f);
        }
        return await http.GetJson($"https://raw.githubusercontent.com/{s.Repo}/main/{string.Join('/', parts.Select(Uri.EscapeDataString))}");
    }

    /// <summary>Verifies one version's archive and adds the hashes of its DLLs and EXEs to <paramref name="allow"/>.</summary>
    static async Task Version(Http http, Settings s, string mid, string type, string path, JsonObject allow) {
        using var stamp = await ReadStamp(http, s, path);
        var root = stamp.RootElement;
        var download = root.ValueKind == JsonValueKind.Object && root.TryGetProperty("download", out var dl) ? dl : default;
        var url = Str(download, "url");
        var want = (Str(download, "sha256") ?? "").ToLowerInvariant();
        var version = root.ValueKind == JsonValueKind.Object && root.TryGetProperty("version", out var v) ? v : (JsonElement?)null;
        var ver = version is { ValueKind: JsonValueKind.String } sv ? sv.GetString()! : version?.GetRawText() ?? "?";
        if (string.IsNullOrEmpty(url) || want.Length == 0) {
            Console.Error.WriteLine($"  {mid} {ver}: no download hash in stamp, skipped");
            return;
        }
        if (!Sha256Hex().IsMatch(want)) {
            Console.Error.WriteLine($"  {mid} {ver}: malformed download.sha256 in stamp, skipped");
            return;
        }
        byte[]? blob;
        try {
            blob = await FetchVerified(http, url, want, s);
        } catch (Exception e) when (e is FetchException or RateLimitException or IOException) {
            Console.Error.WriteLine($"  {mid} {ver}: download failed ({e.Message}), skipped");
            return;
        }
        if (blob == null) {
            // The bytes must match the stamp, or nothing in them is trusted.
            Console.Error.WriteLine($"  {mid} {ver}: archive hash does not match stamp {want[..12]}, refused");
            return;
        }

        var found = new List<(string Sha, string Name, string Entry, byte[] Data)>();
        try {
            using var zip = new ZipArchive(new MemoryStream(blob, writable: false), ZipArchiveMode.Read, leaveOpen: false, Archives.Cp437);
            foreach (var e in zip.Entries) {
                if (!e.FullName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) && !e.FullName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) continue;
                var data = Archives.ReadEntry(e, s.MaxBytes);
                var name = e.FullName.Replace('\\', '/').Split('/')[^1];
                found.Add((Convert.ToHexStringLower(SHA256.HashData(data)), name[..^4], e.FullName, data));
            }
        } catch (Exception e) when (e is InvalidDataException or ArchiveException or IOException or NotSupportedException) {
            // Nothing from an archive that cannot be read completely is trusted.
            Console.Error.WriteLine($"  {mid} {ver}: not a readable zip ({e.Message}), skipped");
            return;
        }
        foreach (var (sha, name, entry, data) in found) {
            if (s.LibraryDir != null) WriteLibraryFile(s.LibraryDir, sha, entry, data);
            allow[sha] = new JsonObject {
                ["name"] = name,
                ["trust"] = "index-release-stamp",
                ["anchor"] = mid,
                ["anchor_type"] = type,
                ["version"] = version is { } ve ? JsonNode.Parse(ve.GetRawText()) : "?",
                ["archive_sha256"] = want,
                ["source"] = s.Repo,
            };
        }
        Console.WriteLine($"  {mid,-16} {ver,-8} verified archive -> {found.Count} DLL/EXE hashes trusted");
    }

    /// <summary>
    /// The archive whose SHA-256 is <paramref name="want"/>, from the cache or the network; null if
    /// the download does not match. A cached copy that no longer matches is discarded. The bytes
    /// are hashed and used from memory, so nothing can change them between check and use.
    /// </summary>
    static async Task<byte[]?> FetchVerified(Http http, string url, string want, Settings s) {
        var cache = Path.Join(s.Cache, want + ".zip");
        if (File.Exists(cache)) {
            if (new FileInfo(cache).Length <= s.MaxBytes) {
                var blob = await File.ReadAllBytesAsync(cache);
                if (Convert.ToHexStringLower(SHA256.HashData(blob)) == want) return blob;
            }
            File.Delete(cache);
        }
        var download = cache + ".download";
        var (_, sha) = await http.Download(url, download, s.MaxBytes);
        if (sha != want) {
            File.Delete(download);
            return null;
        }
        File.Move(download, cache, overwrite: true);
        var verified = await File.ReadAllBytesAsync(cache);
        return Convert.ToHexStringLower(SHA256.HashData(verified)) == want ? verified : null;
    }

    /// <summary>
    /// Writes one trusted file as ROOT/&lt;sha&gt;/&lt;file name&gt;. Only the entry's base name is used,
    /// so an archive entry cannot place a file outside its folder.
    /// </summary>
    static void WriteLibraryFile(string root, string sha, string entry, byte[] data) {
        var name = entry.Replace('\\', '/').Split('/')[^1];
        if (name.Length == 0 || name is "." or ".." || name.Any(char.IsControl)) {
            Console.Error.WriteLine($"  {Text.Quote(entry)}: unusable file name, not written to the library folder");
            return;
        }
        var folder = Path.Join(root, sha);
        Directory.CreateDirectory(folder);
        var path = Path.Join(folder, name);
        var tmp = path + ".part";
        File.WriteAllBytes(tmp, data);
        File.Move(tmp, path, overwrite: true);
    }
}
