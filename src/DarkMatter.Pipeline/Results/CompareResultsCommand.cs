// SPDX-License-Identifier: MIT
using System.Text.Json;

namespace DarkMatter.Pipeline.Results;

/// <summary>
/// <c>darkmatter-pipeline compare-results</c>: tier, label and Full-access reason counts (by group) of
/// one results file (the <c>--json</c> output of <c>darkmatter analyze --manifest</c>), or of two, and
/// the mods whose tier or reason groups changed. A Full-access mod whose reasons move from one group
/// to another (deep game access only, then system access too) keeps its tier, so it is listed apart.
/// Results from before policy 13 have four tiers and two flat reason lists, <c>fullAccess</c> and
/// <c>unverified</c> (absent before policy 9): their tiers read as the new ones they became, and their
/// lists as groups named "full-access" and "unverified".
/// </summary>
internal static class CompareResultsCommand {
    static readonly string[] Tiers = ["no-code", "limited-access", "full-access"];

    // Tiers before policy 13.
    static readonly Dictionary<string, string> OldTiers = new(StringComparer.Ordinal) {
        ["content-only"] = "no-code",
        ["known-access"] = "limited-access",
        ["unverified"] = "full-access",
    };

    public static int Run(IReadOnlyList<string> argv) {
        var o = Options.Parse(argv, [], []);
        if (o.Positional.Count is < 1 or > 2) throw new UsageException("compare-results needs one or two results files");
        using var before = Load(o.Positional[0]);
        Show(o.Positional[0], before.RootElement);
        if (o.Positional.Count == 1) return 0;
        using var after = Load(o.Positional[1]);
        Show(o.Positional[1], after.RootElement);

        var m1 = Mods(before.RootElement);
        var m2 = Mods(after.RootElement);
        var names = m1.Keys.Union(m2.Keys).Order(StringComparer.Ordinal).ToList();
        string Why(string name) {
            List<string> old = m1.TryGetValue(name, out var a) ? [.. Reasons(a).Select(r => r.Text)] : [];
            List<string> now = m2.TryGetValue(name, out var b) ? [.. Reasons(b).Select(r => r.Text)] : [];
            var added = now.Where(r => !old.Contains(r)).ToList();
            var gone = old.Where(r => !now.Contains(r)).ToList();
            return (added.Count > 0 ? $"  (new: {string.Join("; ", added)})" : "") + (gone.Count > 0 ? $"  (gone: {string.Join("; ", gone)})" : "");
        }

        Console.WriteLine("## tier changes");
        int changed = 0;
        foreach (var name in names) {
            var t1 = m1.TryGetValue(name, out var a) ? Tier(a) : "(absent)";
            var t2 = m2.TryGetValue(name, out var b) ? Tier(b) : "(absent)";
            if (t1 == t2) continue;
            changed++;
            Console.WriteLine($"  {name}: {t1} -> {t2}{Why(name)}");
        }
        if (changed == 0) Console.WriteLine("  none");

        Console.WriteLine();
        Console.WriteLine("## reason group changes (Full access in both)");
        changed = 0;
        foreach (var name in names) {
            if (!m1.TryGetValue(name, out var a) || !m2.TryGetValue(name, out var b) || Tier(a) != "full-access" || Tier(b) != "full-access") continue;
            var g1 = string.Join(", ", Reasons(a).Select(r => r.Group).Distinct());
            var g2 = string.Join(", ", Reasons(b).Select(r => r.Group).Distinct());
            if (g1 == g2) continue;
            changed++;
            Console.WriteLine($"  {name}: [{g1}] -> [{g2}]{Why(name)}");
        }
        if (changed == 0) Console.WriteLine("  none");
        return 0;
    }

    static JsonDocument Load(string path) =>
        File.Exists(path) ? JsonDocument.Parse(File.ReadAllBytes(path)) : throw new UsageException($"file not found: {path}");

    static Dictionary<string, JsonElement> Mods(JsonElement root) {
        var mods = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (var m in root.GetProperty("mods").EnumerateObject()) mods[m.Name] = m.Value;
        return mods;
    }

    static string? Str(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    static string Tier(JsonElement mod) {
        var t = Str(mod, "tier") ?? throw new InvalidDataException("a mod has no tier");
        return OldTiers.GetValueOrDefault(t, t);
    }

    static IEnumerable<string> Texts(JsonElement items, string list) =>
        items.EnumerateArray().Select(i => Str(i, "text") ?? throw new InvalidDataException($"a {list} entry has no text"));

    static IEnumerable<string> Labels(JsonElement mod) =>
        mod.ValueKind == JsonValueKind.Object && mod.TryGetProperty("labels", out var items) ? Texts(items, "labels") : throw new InvalidDataException("a mod has no labels list");

    /// <summary>A mod's Full-access reasons with their group, in the order of the result.</summary>
    static IEnumerable<(string Group, string Text)> Reasons(JsonElement mod) {
        if (mod.ValueKind != JsonValueKind.Object || !mod.TryGetProperty("fullAccess", out var full))
            throw new InvalidDataException("a mod has no fullAccess list");
        foreach (var e in full.EnumerateArray()) {
            if (e.TryGetProperty("reasons", out var reasons)) {
                var group = Str(e, "group") ?? throw new InvalidDataException("a fullAccess group has no id");
                foreach (var t in Texts(reasons, "fullAccess")) yield return (group, t);
            } else {
                // Before policy 13: a flat list.
                yield return ("full-access", Str(e, "text") ?? throw new InvalidDataException("a fullAccess entry has no text"));
            }
        }
        if (mod.TryGetProperty("unverified", out var unverified))
            foreach (var t in Texts(unverified, "unverified")) yield return ("unverified", t);
    }

    /// <summary>Counts in descending order; equal counts in the order first seen.</summary>
    static List<(string Key, int Count)> Count(IEnumerable<string> items) {
        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        var order = new List<string>();
        foreach (var i in items) {
            if (counts.TryGetValue(i, out var n)) counts[i] = n + 1;
            else {
                counts[i] = 1;
                order.Add(i);
            }
        }
        return [.. order.Select(k => (k, counts[k])).OrderByDescending(kv => kv.Item2)];
    }

    static void Show(string title, JsonElement root) {
        var mods = Mods(root).Values.ToList();
        string version = "?", tool = "?";
        if (root.TryGetProperty("stamp", out var stamp) && stamp.ValueKind == JsonValueKind.Object) {
            if (stamp.TryGetProperty("policy", out var p) && p.ValueKind == JsonValueKind.Object && p.TryGetProperty("version", out var v))
                version = v.ValueKind == JsonValueKind.String ? v.GetString()! : v.GetRawText();
            tool = Str(stamp, "tool") ?? "?";
        }
        Console.WriteLine($"## {title}  ({mods.Count} mods, policy {version}, {tool})");
        var tiers = Count(mods.Select(Tier)).ToDictionary(kv => kv.Key, kv => kv.Count);
        foreach (var t in Tiers.Concat(tiers.Keys.Except(Tiers))) Console.WriteLine($"  {t,-14} {tiers.GetValueOrDefault(t)}");
        var labels = Count(mods.SelectMany(Labels));
        if (labels.Count > 0) {
            Console.WriteLine("  labels:");
            foreach (var (text, n) in labels) Console.WriteLine($"    {n,4}  {text}");
        }
        var reasons = mods.SelectMany(Reasons).ToList();
        // Mods per group: a mod counts once in each group it has a reason in.
        var groups = Count(mods.SelectMany(m => Reasons(m).Select(r => r.Group).Distinct()));
        foreach (var (group, n) in groups) {
            Console.WriteLine($"  {group} reasons ({n} mods):");
            foreach (var (text, k) in Count(reasons.Where(r => r.Group == group).Select(r => r.Text))) Console.WriteLine($"    {k,4}  {text}");
        }
        Console.WriteLine();
    }
}
