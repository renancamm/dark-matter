// SPDX-License-Identifier: MIT
using System.Text.Json.Nodes;

namespace DarkMatter.Pipeline.Scan;

/// <summary>A label or a Broad-access reason of a result: id, text and evidence.</summary>
internal sealed record FindingView(string Id, string Text, int Count, IReadOnlyList<string> Evidence);

/// <summary>A Broad-access group of a result, with its reasons.</summary>
internal sealed record GroupView(string Id, string Name, string Summary, IReadOnlyList<FindingView> Reasons);

/// <summary>
/// A required dependency noted in a result (see ScanCommand's Dependencies): the listing, the release that answered,
/// the tier of its own code (null when it has no result), and the dependency it comes through when it is not
/// required directly.
/// </summary>
internal sealed record DependencyView(string Id, string? Version, string? Tier, string TierName, string? Through, bool Scanned, string? Reason);

/// <summary>A code file of a result.</summary>
internal sealed record FileView(string Path, string? Sha256, string? Name, string? Classification);

/// <summary>
/// One mod's result as <c>darkmatter analyze --json</c> writes it (policy 13 and later: three tiers,
/// Broad-access reasons in groups), read for display and comparison. Results from policy 13 have no
/// label or reason ids and at most five pieces of evidence; their text stands in for the id. Results
/// from before policy 36 call the top tier "full-access" and its groups "fullAccess"; they read as
/// "broad-access" and "broadAccess", so a rename alone is not a difference.
/// </summary>
internal sealed record ResultView(
    string Tier,
    string TierName,
    string TierSummary,
    IReadOnlyList<FindingView> Labels,
    IReadOnlyList<GroupView> Groups,
    IReadOnlyList<string> Warnings,
    IReadOnlyList<string> Trusted,
    IReadOnlyList<FileView> Files) {
    /// <summary>The mod's required dependencies, and theirs: a note beside the result, not part of its tier.</summary>
    public IReadOnlyList<DependencyView> Dependencies { get; init; } = [];

    /// <summary>How many Broad-access reasons the mod's own code has: what stands between it and Limited access.</summary>
    public int ReasonCount => Groups.Sum(g => g.Reasons.Count);

    /// <summary>What goes beside the tier: for Broad access, the number of reasons; null when there is nothing to add.</summary>
    public string? TierNote => Tier == "broad-access" && ReasonCount > 0 ? $"{ReasonCount} reason{(ReasonCount == 1 ? "" : "s")}" : null;

    /// <summary>The dependencies as one line: "requires X 1.0 (Broad access), Y (not scanned)"; null without any.</summary>
    public string? Requires => Dependencies.Count == 0 ? null : "requires " + string.Join(", ", Dependencies.Select(d =>
        $"{d.Id}{(d.Version != null ? " " + d.Version : "")} ({d.TierName}{(d.Through != null ? ", through " + d.Through : "")})"));

    static readonly Dictionary<string, string> OldTiers = new(StringComparer.Ordinal) {
        ["content-only"] = "no-code",
        ["known-access"] = "limited-access",
        ["unverified"] = "broad-access",
        ["full-access"] = "broad-access",  // before policy 36
    };

    public static ResultView From(JsonNode? node) {
        var o = node as JsonObject ?? throw new InvalidDataException("a result is not an object");
        var tier = Str(o, "tier") ?? throw new InvalidDataException("a result has no tier");
        tier = OldTiers.GetValueOrDefault(tier, tier);
        var groups = new List<GroupView>();
        foreach (var g in Arr(o, o.ContainsKey("broadAccess") ? "broadAccess" : "fullAccess").OfType<JsonObject>()) {
            if (g["reasons"] is JsonArray reasons)
                groups.Add(new GroupView(Str(g, "group") ?? "broad-access", Str(g, "name") ?? Str(g, "group") ?? "Broad access", Str(g, "summary") ?? "",
                    [.. reasons.OfType<JsonObject>().Select(Finding)]));
            else
                // Before policy 13: a flat list of reasons.
                groups.Add(new GroupView("broad-access", "Broad access", "", [Finding(g)]));
        }
        var old = Arr(o, "unverified").OfType<JsonObject>().Select(Finding).ToList();
        if (old.Count > 0) groups.Add(new GroupView("unverified", "Unverified", "", old));
        return new ResultView(
            tier,
            Str(o, "tierName") ?? tier,
            Str(o, "tierSummary") ?? "",
            [.. Arr(o, "labels").OfType<JsonObject>().Select(Finding)],
            groups,
            [.. Arr(o, "warnings").Select(x => x?.ToString() ?? "")],
            [.. Arr(o, "trusted").Select(x => x?.ToString() ?? "")],
            [.. Arr(o, "files").OfType<JsonObject>().Select(f => new FileView(Str(f, "path") ?? "", Str(f, "sha256"), Str(f, "name"), Str(f, "classification")))]) {
            Dependencies = [.. Arr(o, "dependencies").OfType<JsonObject>().Select(d => new DependencyView(
                Str(d, "id") ?? "?", Str(d, "version"), Str(d, "tier"), Str(d, "tierName") ?? Str(d, "tier") ?? "Not scanned",
                Str(d, "through"), Str(d, "status") != "not scanned", Str(d, "reason")))],
        };
    }

    static FindingView Finding(JsonObject f) {
        var text = Str(f, "text") ?? throw new InvalidDataException("a label or reason has no text");
        List<string> evidence = [.. Arr(f, "evidence").Select(x => x?.ToString() ?? "")];
        int count = f["count"] is JsonValue c && c.TryGetValue<int>(out var n) ? n : evidence.Count;
        return new FindingView(Str(f, "id") ?? text, text, count, evidence);
    }

    public static string? Str(JsonObject? o, string name) =>
        o?[name] is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

    static JsonArray Arr(JsonObject o, string name) => o[name] as JsonArray ?? [];

    /// <summary>Every Broad-access reason, with its group.</summary>
    public IEnumerable<(GroupView Group, FindingView Reason)> Reasons => Groups.SelectMany(g => g.Reasons.Select(r => (g, r)));
}

/// <summary>What changed between two results of one listing (an earlier release or stamp, and now).</summary>
internal static class ResultDiff {
    /// <summary>
    /// The difference as a JSON object: the tiers when they differ, labels and reasons added and
    /// removed (by id, shown by text), and the reason groups when they differ. Null when the two
    /// have the same tier, labels, groups and reasons.
    /// </summary>
    public static JsonObject? Of(ResultView before, ResultView after) {
        var diff = new JsonObject();
        if (before.Tier != after.Tier) diff["tier"] = new JsonObject { ["from"] = before.Tier, ["to"] = after.Tier };
        Added(diff, "labels", before.Labels.Select(l => (l.Id, l.Text)), after.Labels.Select(l => (l.Id, l.Text)));
        var g1 = before.Groups.Select(g => g.Id).ToList();
        var g2 = after.Groups.Select(g => g.Id).ToList();
        if (!g1.SequenceEqual(g2)) diff["groups"] = new JsonObject { ["from"] = Strings(g1), ["to"] = Strings(g2) };
        Added(diff, "reasons", before.Reasons.Select(r => (r.Reason.Id, r.Reason.Text)), after.Reasons.Select(r => (r.Reason.Id, r.Reason.Text)));
        return diff.Count > 0 ? diff : null;
    }

    static void Added(JsonObject diff, string name, IEnumerable<(string Id, string Text)> before, IEnumerable<(string Id, string Text)> after) {
        var a = before.GroupBy(x => x.Id).ToDictionary(g => g.Key, g => g.First().Text, StringComparer.Ordinal);
        var b = after.GroupBy(x => x.Id).ToDictionary(g => g.Key, g => g.First().Text, StringComparer.Ordinal);
        var added = b.Where(kv => !a.ContainsKey(kv.Key)).Select(kv => kv.Value).ToList();
        var removed = a.Where(kv => !b.ContainsKey(kv.Key)).Select(kv => kv.Value).ToList();
        if (added.Count == 0 && removed.Count == 0) return;
        diff[name] = new JsonObject { ["added"] = Strings(added), ["removed"] = Strings(removed) };
    }

    static JsonArray Strings(IEnumerable<string> items) => new([.. items.Select(s => (JsonNode?)JsonValue.Create(s))]);

    /// <summary>A one-line description of a difference, for text output.</summary>
    public static string Describe(JsonObject diff) {
        var parts = new List<string>();
        if (diff["tier"] is JsonObject t) parts.Add($"tier {t["from"]} -> {t["to"]}");
        if (diff["groups"] is JsonObject g) parts.Add($"groups [{Join(g["from"])}] -> [{Join(g["to"])}]");
        foreach (var name in new[] { "labels", "reasons" })
            if (diff[name] is JsonObject x) {
                foreach (var s in (x["added"] as JsonArray ?? [])) parts.Add($"+ {s}");
                foreach (var s in (x["removed"] as JsonArray ?? [])) parts.Add($"- {s}");
            }
        return string.Join("; ", parts);
    }

    /// <summary>
    /// What a run's <c>change</c> says about the result, for text output: its difference, that the
    /// previous result could not be read (nothing compared), or that nothing differs.
    /// </summary>
    public static string OfChange(JsonObject change) =>
        change["difference"] is JsonObject d ? Describe(d)
        : ResultView.Str(change, "previous") == "unreadable" ? "the previous result could not be read, so nothing is compared"
        : "no difference in tier, labels or reasons";

    static string Join(JsonNode? a) => a is JsonArray arr ? string.Join(", ", arr.Select(x => x?.ToString())) : "";
}
