// SPDX-License-Identifier: MIT
using System.Text.Json;

namespace DarkMatter.Pipeline.Results;

/// <summary>
/// <c>darkmatter-pipeline compare-results</c>: tier, label and reason counts (Full access and
/// Unverified) of one results file (the <c>--json</c> output of <c>darkmatter analyze --manifest</c>),
/// or of two, and the mods whose tier changed. Results from before policy 9 have three tiers and no
/// <c>unverified</c> list; they read as having no Unverified reasons.
/// </summary>
internal static class CompareResultsCommand {
    static readonly string[] Tiers = ["content-only", "known-access", "unverified", "full-access"];

    public static int Run(IReadOnlyList<string> argv) {
        var o = Options.Parse(argv, [], []);
        if (o.Positional.Count is < 1 or > 2) throw new UsageException("compare-results needs one or two results files");
        using var before = Load(o.Positional[0]);
        Show(o.Positional[0], before.RootElement);
        if (o.Positional.Count == 1) return 0;
        using var after = Load(o.Positional[1]);
        Show(o.Positional[1], after.RootElement);

        Console.WriteLine("## tier changes");
        var m1 = Mods(before.RootElement);
        var m2 = Mods(after.RootElement);
        int changed = 0;
        foreach (var name in m1.Keys.Union(m2.Keys).Order(StringComparer.Ordinal)) {
            var t1 = m1.TryGetValue(name, out var a) ? Str(a, "tier") ?? "(absent)" : "(absent)";
            var t2 = m2.TryGetValue(name, out var b) ? Str(b, "tier") ?? "(absent)" : "(absent)";
            if (t1 == t2) continue;
            changed++;
            List<string> old = m1.ContainsKey(name) ? [.. Reasons(a)] : [];
            List<string> now = m2.ContainsKey(name) ? [.. Reasons(b)] : [];
            var added = now.Where(r => !old.Contains(r)).ToList();
            var gone = old.Where(r => !now.Contains(r)).ToList();
            var why = (added.Count > 0 ? $"  (new: {string.Join("; ", added)})" : "") + (gone.Count > 0 ? $"  (gone: {string.Join("; ", gone)})" : "");
            Console.WriteLine($"  {name}: {t1} -> {t2}{why}");
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

    static IEnumerable<string> Texts(JsonElement mod, string list, bool optional = false) =>
        mod.ValueKind == JsonValueKind.Object && mod.TryGetProperty(list, out var items)
            ? items.EnumerateArray().Select(i => Str(i, "text") ?? throw new InvalidDataException($"a {list} entry has no text"))
            : optional ? [] : throw new InvalidDataException($"a mod has no {list} list");

    static IEnumerable<string> FullReasons(JsonElement mod) => Texts(mod, "fullAccess");

    // Absent before policy 9.
    static IEnumerable<string> UnverifiedReasons(JsonElement mod) => Texts(mod, "unverified", optional: true);

    static IEnumerable<string> Reasons(JsonElement mod) => FullReasons(mod).Concat(UnverifiedReasons(mod));

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
        var tiers = Count(mods.Select(m => Str(m, "tier") ?? throw new InvalidDataException("a mod has no tier"))).ToDictionary(kv => kv.Key, kv => kv.Count);
        foreach (var t in Tiers) Console.WriteLine($"  {t,-14} {tiers.GetValueOrDefault(t)}");
        var labels = Count(mods.SelectMany(m => Texts(m, "labels")));
        if (labels.Count > 0) {
            Console.WriteLine("  labels:");
            foreach (var (text, n) in labels) Console.WriteLine($"    {n,4}  {text}");
        }
        foreach (var (heading, list) in new[] { ("full-access", (Func<JsonElement, IEnumerable<string>>)FullReasons), ("unverified", UnverifiedReasons) }) {
            var reasons = Count(mods.SelectMany(list));
            if (reasons.Count == 0) continue;
            Console.WriteLine($"  {heading} reasons:");
            foreach (var (text, n) in reasons) Console.WriteLine($"    {n,4}  {text}");
        }
        Console.WriteLine();
    }
}
