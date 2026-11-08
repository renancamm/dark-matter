// SPDX-License-Identifier: MIT
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace DarkMatter.Pipeline.Index;

/// <summary>
/// <c>darkmatter-pipeline fetch-releases</c>: download the newest non-draft GitHub release of
/// every content-index listing. Every asset of the release is downloaded, whatever its type: an
/// asset the pipeline skipped could be the one a player installs, and extraction decides what each
/// file is. A mod's folder appears only when all its assets are complete (they are downloaded into
/// <c>DOWNLOADS/.partial/</c> first), so a mod whose folder exists and is not empty is skipped and
/// a stopped run can be resumed. Downloaded files are untrusted; nothing here extracts or runs them.
/// </summary>
internal static partial class FetchReleasesCommand {
    static readonly string[] Valued = ["--max-bytes"];
    static readonly string[] Flags = ["--list"];
    const string Staging = ".partial";

    // Listing ids and kept asset names: usable as one path component on every system.
    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]*$")]
    private static partial Regex SafeName();

    // GitHub "owner/repository".
    [GeneratedRegex("^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$")]
    private static partial Regex RepoName();

    /// <summary>What a listing says about its releases.</summary>
    sealed record Listing(string Id, string? Repo, string? TagPrefix);

    public static async Task<int> Run(IReadOnlyList<string> argv) {
        var o = Options.Parse(argv, Valued, Flags);
        bool list = o.Has(Flags);
        if (o.Positional.Count != (list ? 1 : 2) && !(list && o.Positional.Count == 2))
            throw new UsageException("fetch-releases needs a listings folder and a downloads folder");
        var listings = o.Positional[0];
        if (!Directory.Exists(listings)) throw new UsageException($"folder not found: {listings}");
        var maxBytes = o.Number("--max-bytes", 4L << 30, 1);

        int errors = 0;
        using var http = new Http(attempts: 5, pause: TimeSpan.FromSeconds(2), timeout: TimeSpan.FromSeconds(120));
        foreach (var path in Directory.GetFiles(listings).Where(p => Path.GetFileName(p).EndsWith(".toml", StringComparison.Ordinal)).Order(StringComparer.Ordinal)) {
            var file = Path.GetFileName(path);
            var listing = Read(path, file, ref errors);
            if (listing == null) continue;
            if (list) {
                Console.WriteLine($"{listing.Id}\t{listing.Repo ?? "-"}\t{(listing.TagPrefix is { } p ? Text.Quote(p) : "-")}");
                continue;
            }
            var downloads = o.Positional[1];
            var dest = Path.Join(downloads, listing.Id);
            if (Directory.Exists(dest) && Directory.EnumerateFileSystemEntries(dest).Any()) continue;
            if (listing.Repo == null) {
                Console.WriteLine($"{listing.Id}: no GitHub release source");
                continue;
            }
            var staging = Path.Join(downloads, Staging, listing.Id);
            try {
                if (await Fetch(http, listing, staging, dest, maxBytes) is { } line) Console.WriteLine(line);
            } catch (RateLimitException e) {
                Console.Error.WriteLine($"{listing.Id}: {e.Message}");
                return 1;
            } catch (Exception e) when (e is FetchException or IOException or UnauthorizedAccessException or JsonException or InvalidDataException) {
                Console.Error.WriteLine($"{listing.Id}: error: {e.Message}");
                errors++;
            } finally {
                if (Directory.Exists(staging)) Directory.Delete(staging, recursive: true);
            }
        }
        if (!list && o.Positional.Count == 2) {
            var stagingRoot = Path.Join(o.Positional[1], Staging);
            if (Directory.Exists(stagingRoot) && !Directory.EnumerateFileSystemEntries(stagingRoot).Any()) Directory.Delete(stagingRoot);
        }
        return errors > 0 ? 1 : 0;
    }

    /// <summary>The listing's id and release source, or null (with a message) if it has no usable id or is malformed.</summary>
    static Listing? Read(string path, string file, ref int errors) {
        TomlTable doc;
        try {
            doc = Toml.Parse(new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(File.ReadAllBytes(path)));
        } catch (Exception e) when (e is TomlException or DecoderFallbackException) {
            Console.WriteLine($"{file}: invalid TOML ({(e is TomlException ? e.Message : "not UTF-8")})");
            return null;
        }
        var id = doc.Items.GetValueOrDefault("id");
        if (id is not string mid || !SafeName().IsMatch(mid)) {
            Console.WriteLine($"{file}: missing or unsafe id {(id is string s ? Text.Quote(s) : id == null ? "(none)" : "(not a string)")}, skipped");
            return null;
        }
        // The keys this command needs must have the expected form: anything else is an error for
        // this listing, never a silent default.
        string? problem = null, repo = null, prefix = null;
        switch (doc.Items.GetValueOrDefault("releases")) {
            case null:
                break;
            case TomlTable releases:
                switch (releases.Items.GetValueOrDefault("github")) {
                    case null: break;
                    case string g when g.Length == 0: break;
                    case string g when RepoName().IsMatch(g): repo = g; break;
                    case string g: problem = $"releases.github is not a GitHub owner/repository: {Text.Quote(g)}"; break;
                    default: problem = "releases.github is not a string"; break;
                }
                switch (releases.Items.GetValueOrDefault("tag_prefix")) {
                    case null: break;
                    case string p: prefix = p.Length > 0 ? p : null; break;
                    default: problem = "releases.tag_prefix is not a string"; break;
                }
                break;
            default:
                problem = "releases is not a table";
                break;
        }
        if (problem != null) {
            Console.Error.WriteLine($"{mid}: error: {problem}");
            errors++;
            return null;
        }
        return new Listing(mid, repo, prefix);
    }

    /// <summary>Downloads the newest matching release's assets; returns the line to print.</summary>
    static async Task<string?> Fetch(Http http, Listing listing, string staging, string dest, long maxBytes) {
        using var doc = await http.GetJson($"https://api.github.com/repos/{listing.Repo}/releases?per_page=30");
        if (doc.RootElement.ValueKind != JsonValueKind.Array) throw new InvalidDataException("the releases API did not return a list");
        JsonElement? latest = null;
        string tag = "";
        foreach (var r in doc.RootElement.EnumerateArray()) {
            var t = Field(r, "tag_name", JsonValueKind.String).GetString()!;
            var draft = Field(r, "draft", JsonValueKind.True, JsonValueKind.False).GetBoolean();
            if (draft || (listing.TagPrefix != null && !t.StartsWith(listing.TagPrefix, StringComparison.Ordinal))) continue;
            latest = r;
            tag = t;
            break;
        }
        if (latest is not { } release) return $"{listing.Id}: no releases";
        var assets = Field(release, "assets", JsonValueKind.Array).EnumerateArray()
            .Select(a => (Name: Field(a, "name", JsonValueKind.String).GetString()!, Url: Field(a, "browser_download_url", JsonValueKind.String).GetString()!))
            .ToList();
        // No folder: a mod without assets is not "content only", it is not analyzed.
        if (assets.Count == 0) return $"{listing.Id}: {Text.Printable(tag)} has no assets";

        if (Directory.Exists(staging)) Directory.Delete(staging, recursive: true);
        Directory.CreateDirectory(staging);
        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var saved = new List<string>();
        foreach (var (name, url) in assets) {
            var local = LocalName(name, used);
            var (size, _) = await http.Download(url, Path.Join(staging, local), maxBytes);
            saved.Add($"{local} ({size / 1024} KiB)" + (local != name ? $" (asset {Text.Quote(name)})" : ""));
        }
        if (Directory.Exists(dest)) Directory.Delete(dest);  // empty: checked by the caller
        Directory.Move(staging, dest);
        return $"{listing.Id}: {Text.Printable(tag)} -> {string.Join(", ", saved)}";
    }

    static JsonElement Field(JsonElement e, string name, params JsonValueKind[] kinds) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && kinds.Contains(v.ValueKind)
            ? v
            : throw new InvalidDataException($"the releases API returned an entry without a valid {name}");

    /// <summary>
    /// A file name for an asset: its own name when that is a safe single path component, else the
    /// name with every other character replaced by '_' (never skipped: a skipped asset would be
    /// invisible to the check). Names that differ only in case get a number in front.
    /// </summary>
    static string LocalName(string name, HashSet<string> used) {
        var n = name;
        if (!SafeName().IsMatch(n) || n.Length > 200) {
            var b = new StringBuilder();
            foreach (var c in name) b.Append(char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-' ? c : '_');
            n = b.ToString();
            if (n.Length > 200) n = n[..100] + n[^100..];
            if (n.Length == 0 || !char.IsAsciiLetterOrDigit(n[0])) n = "asset-" + n;
        }
        var unique = n;
        for (int k = 2; !used.Add(unique); k++) unique = $"{k}-{n}";
        return unique;
    }
}
