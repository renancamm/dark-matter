// SPDX-License-Identifier: MIT
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace DarkMatter.Pipeline.Index;

/// <summary>
/// One stamped release of a listing, as the content index's snapshot gives it. Its identity is
/// (<see cref="Id"/>, <see cref="Version"/>, <see cref="Sha256"/>): the archive the index stamped,
/// which the client verifies before installing.
/// </summary>
internal sealed record Release(
    string Id,
    string Version,
    string Status,
    string? Date,
    string Url,
    IReadOnlyList<string> Mirrors,
    string Sha256,
    long? Size,
    bool Yanked,
    string? YankedReason,
    string? Loader,
    string? GameMin,
    string? GameMax) {
    /// <summary>The mods this release names as dependencies (required, recommended, suggested, conflicting).</summary>
    public IReadOnlyList<Dependency> Dependencies { get; init; } = [];
}

/// <summary>A dependency a release declares: the listing's id, the kind ("required", "recommends", "suggests", "conflict") and the lowest version, if given.</summary>
internal sealed record Dependency(string Id, string Kind, string? Min);

/// <summary>A listing: its id, type ("mod", "mod-loader"), display name, and its usable releases.</summary>
internal sealed record Listing(string Id, string Type, string Name, IReadOnlyList<Release> Releases);

/// <summary>A listing left out because its id cannot be used (it names folders, or another listing has it ignoring case): the id as given, and why.</summary>
internal sealed record RejectedListing(string Id, string Reason);

/// <summary>
/// The content index's snapshot (https://ksamodding.github.io/content-index-releases/v1/index.json),
/// which merges the authored listings, the stamped releases and the game release list. Only what
/// the scan needs is read. The snapshot is the index's own published document, but every field is
/// still checked before use: ids become folder names, hashes decide what is trusted, URLs are
/// fetched. A listing or release that fails a check is left out and reported in <see cref="Problems"/>;
/// a listing left out for its id is also in <see cref="Rejected"/>, which <c>scan index</c> reports as failed.
/// </summary>
internal sealed partial class Snapshot {
    public const string DefaultUrl = "https://ksamodding.github.io/content-index-releases/v1/index.json";

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")]
    private static partial Regex IdPattern();

    [GeneratedRegex("^[0-9a-fA-F]{64}$")]
    private static partial Regex Sha256Hex();

    /// <summary>Where the snapshot was read from (a URL or a file).</summary>
    public required string Source { get; init; }

    /// <summary>SHA-256 of the snapshot's bytes.</summary>
    public required string Sha256 { get; init; }

    /// <summary>The snapshot's <c>sources</c> (the commits of both halves of the index), as given.</summary>
    public required JsonNode? Sources { get; init; }

    public required IReadOnlyList<Listing> Listings { get; init; }

    public required IReadOnlyList<string> Problems { get; init; }

    /// <summary>Listings left out because their id is not usable as a folder name, or is an earlier listing's ignoring case.</summary>
    public required IReadOnlyList<RejectedListing> Rejected { get; init; }

    /// <summary>
    /// Why this is a copy an earlier run kept rather than the snapshot asked for (the download failed
    /// or could not be read), and when it was saved; null when it is the snapshot asked for. Such a
    /// copy may be out of date, and the run document says so.
    /// </summary>
    public string? Stale { get; private init; }

    /// <summary>This snapshot, marked as a kept copy used in place of the one asked for (<see cref="Stale"/>).</summary>
    public Snapshot AsStale(string why) => new() {
        Source = Source,
        Sha256 = Sha256,
        Sources = Sources,
        Listings = Listings,
        Problems = Problems,
        Rejected = Rejected,
        Stale = why,
    };

    /// <summary>A short description for reports: the generated half's commit, when the snapshot names it.</summary>
    public string Describe() =>
        Sources is JsonObject s && s["generated"] is JsonObject g && g["commit"] is JsonValue v && v.TryGetValue<string>(out var commit) && commit.Length > 0
            ? $"content-index-releases@{Text.Printable(commit[..Math.Min(12, commit.Length)])}"
            : Source;

    public static Snapshot Parse(byte[] bytes, string source) {
        using var doc = JsonDocument.Parse(bytes);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("listings", out var listings) || listings.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException($"{source}: not a content-index snapshot (no listings)");
        if (root.TryGetProperty("snapshot_version", out var sv) && !(sv.ValueKind == JsonValueKind.Number && sv.GetInt32() == 1))
            throw new InvalidDataException($"{source}: snapshot_version {sv.GetRawText()} is not supported (only 1)");
        var problems = new List<string>();
        var rejected = new List<RejectedListing>();
        var result = new List<Listing>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var l in listings.EnumerateArray()) {
            var id = Str(l, "id");
            // Ids name folders in the state directory (extracted/ID, results/ID): letters, digits and
            // ._-, and one folder name on every system (no device name, no trailing dot, not renamed).
            if (id == null || !IdPattern().IsMatch(id) || !Extract.EntryNames.IsFolderName(id)) {
                var why = $"listing id {Text.Quote(id ?? "(none)")} is not usable as a folder name; the listing is not scanned";
                problems.Add(why);
                rejected.Add(new RejectedListing(id ?? "(none)", why));
                continue;
            }
            // Ids name folders in the state directory: two that differ only in case would share one.
            // The later one fails (Rejected) rather than drop out of the run unseen.
            if (!seen.Add(id)) {
                var why = $"listing id {Text.Quote(id)} is already used by another listing (ignoring case); only the first is scanned, this one is not";
                problems.Add(why);
                rejected.Add(new RejectedListing(id, why));
                continue;
            }
            var authored = l.TryGetProperty("authored", out var a) ? a : default;
            var type = Str(authored, "type") ?? "";
            var name = Str(authored, "name") ?? id;
            var releases = new List<Release>();
            if (l.TryGetProperty("releases", out var rs) && rs.ValueKind == JsonValueKind.Array)
                foreach (var r in rs.EnumerateArray())
                    if (ReadRelease(id, r, out var why) is { } release) releases.Add(release);
                    else problems.Add($"{id}: a release is left out ({why})");
            result.Add(new Listing(id, type, name, releases));
        }
        return new Snapshot {
            Source = source,
            Sha256 = Convert.ToHexStringLower(SHA256.HashData(bytes)),
            Sources = root.TryGetProperty("sources", out var src) ? JsonNode.Parse(src.GetRawText()) : null,
            Listings = [.. result.OrderBy(x => x.Id, StringComparer.Ordinal)],
            Problems = problems,
            Rejected = rejected,
        };
    }

    static Release? ReadRelease(string listingId, JsonElement r, out string why) {
        why = "";
        var version = Str(r, "version");
        if (string.IsNullOrWhiteSpace(version) || version.Length > 100 || version.Any(char.IsControl)) {
            why = $"unusable version {Text.Quote(version ?? "(none)")}";
            return null;
        }
        if (Str(r, "id") is { } rid && rid != listingId) {
            why = $"{version} names listing {Text.Quote(rid)}";
            return null;
        }
        var download = r.TryGetProperty("download", out var d) ? d : default;
        var url = Str(download, "url");
        var sha = Str(download, "sha256");
        if (sha == null || !Sha256Hex().IsMatch(sha)) {
            why = $"{version} has no usable download.sha256";
            return null;
        }
        if (url == null || !IsHttps(url)) {
            why = $"{version} has no HTTPS download.url";
            return null;
        }
        var mirrors = download.ValueKind == JsonValueKind.Object && download.TryGetProperty("mirrors", out var m) && m.ValueKind == JsonValueKind.Array
            ? m.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!).Where(IsHttps).ToList()
            : [];
        long? size = download.ValueKind == JsonValueKind.Object && download.TryGetProperty("size", out var s) && s.ValueKind == JsonValueKind.Number && s.TryGetInt64(out var n) && n >= 0 ? n : null;
        var loader = r.TryGetProperty("loader", out var lo) ? Str(lo, "id") : null;
        // An entry without a usable id names no listing; one without a kind is taken as required (it then counts).
        List<Dependency> dependencies = r.TryGetProperty("dependencies", out var deps) && deps.ValueKind == JsonValueKind.Array
            ? [.. deps.EnumerateArray().Where(x => Str(x, "id") is { Length: > 0 and <= 100 }).Select(x => new Dependency(Str(x, "id")!, Str(x, "kind") ?? "required", Str(x, "min")))]
            : [];
        return new Release(listingId, version, Str(r, "release_status") ?? "stable", Str(r, "release_date"), url, mirrors, sha.ToLowerInvariant(), size,
            r.TryGetProperty("yanked", out var y) && y.ValueKind == JsonValueKind.True, Str(r, "yanked_reason"), loader, Str(r, "game_min"), Str(r, "game_max")) {
            Dependencies = dependencies,
        };
    }

    static bool IsHttps(string url) => Uri.TryCreate(url, UriKind.Absolute, out var u) && u.Scheme == Uri.UriSchemeHttps;

    static string? Str(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    /// <summary>
    /// The release to scan for a listing: the newest stable release that is not yanked, or, when the
    /// listing has no stable one, its newest release of any status that is not yanked. Newest is by
    /// semantic version (the snapshot's order is not always by version), then by release date.
    /// Null when every release is yanked or unusable.
    /// </summary>
    public static Release? Newest(Listing listing) {
        var usable = listing.Releases.Where(r => !r.Yanked).ToList();
        var stable = usable.Where(r => r.Status == "stable").ToList();
        return (stable.Count > 0 ? stable : usable).OrderDescending(ReleaseOrder.Instance).FirstOrDefault();
    }

    /// <summary>Orders releases by semantic version (unparseable versions first, by date), then by release date.</summary>
    internal sealed class ReleaseOrder : IComparer<Release> {
        public static readonly ReleaseOrder Instance = new();

        public int Compare(Release? x, Release? y) {
            if (x == null || y == null) return x == null ? (y == null ? 0 : -1) : 1;
            var (a, b) = (SemVer.TryParse(x.Version), SemVer.TryParse(y.Version));
            int c = (a, b) switch {
                (null, null) => 0,
                (null, _) => -1,
                (_, null) => 1,
                _ => a.CompareTo(b),
            };
            return c != 0 ? c : string.CompareOrdinal(x.Date, y.Date);
        }
    }
}

/// <summary>
/// A semantic version (https://semver.org) for ordering releases: up to four numeric parts (missing
/// ones count as 0), a pre-release after "-", build metadata after "+" (ignored), and an optional
/// leading "v" as tags often have.
/// </summary>
internal sealed class SemVer : IComparable<SemVer> {
    readonly long[] core;
    readonly string[] pre;

    SemVer(long[] core, string[] pre) {
        this.core = core;
        this.pre = pre;
    }

    public static SemVer? TryParse(string version) {
        var v = version.Trim();
        if (v.StartsWith('v') || v.StartsWith('V')) v = v[1..];
        int plus = v.IndexOf('+', StringComparison.Ordinal);
        if (plus >= 0) v = v[..plus];
        int dash = v.IndexOf('-', StringComparison.Ordinal);
        var main = dash >= 0 ? v[..dash] : v;
        var pre = dash >= 0 ? v[(dash + 1)..].Split('.') : [];
        var parts = main.Split('.');
        if (parts.Length is < 1 or > 4 || pre.Any(p => p.Length == 0)) return null;
        var core = new long[4];
        for (int i = 0; i < parts.Length; i++)
            if (!long.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out core[i])) return null;
        return new SemVer(core, pre);
    }

    public int CompareTo(SemVer? other) {
        if (other == null) return 1;
        for (int i = 0; i < 4; i++)
            if (core[i] != other.core[i]) return core[i].CompareTo(other.core[i]);
        // A pre-release sorts before the release it leads to.
        if (pre.Length == 0 || other.pre.Length == 0) return other.pre.Length.CompareTo(pre.Length);
        for (int i = 0; i < Math.Min(pre.Length, other.pre.Length); i++) {
            bool an = long.TryParse(pre[i], NumberStyles.None, CultureInfo.InvariantCulture, out var a);
            bool bn = long.TryParse(other.pre[i], NumberStyles.None, CultureInfo.InvariantCulture, out var b);
            int c = (an, bn) switch {
                (true, true) => a.CompareTo(b),
                (true, false) => -1,
                (false, true) => 1,
                _ => string.CompareOrdinal(pre[i], other.pre[i]),
            };
            if (c != 0) return c;
        }
        return pre.Length.CompareTo(other.pre.Length);
    }
}
