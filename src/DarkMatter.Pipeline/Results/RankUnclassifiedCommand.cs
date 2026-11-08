// SPDX-License-Identifier: MIT
using System.Text.Json;

namespace DarkMatter.Pipeline.Results;

/// <summary>
/// <c>darkmatter-pipeline rank-unclassified</c>: rank the framework members the policy does not
/// classify by how many mods use them. The input is the <c>--facts</c> output of
/// <c>darkmatter analyze</c>; with <c>--manifest</c> counts are mods, without it files. This is
/// the triage input for the policy's "safe" list.
/// </summary>
internal static class RankUnclassifiedCommand {
    static readonly string[] Valued = ["--manifest", "--top", "--by"];

    public static int Run(IReadOnlyList<string> argv) {
        var o = Options.Parse(argv, Valued, []);
        if (o.Positional.Count != 1) throw new UsageException("rank-unclassified needs one facts file");
        var top = o.Number("--top", 60, 0);
        var by = o.Get("--by") ?? "member";
        if (by is not ("member" or "type" or "namespace")) throw new UsageException("--by is member, type or namespace");

        using var facts = Load(o.Positional[0]);
        var owner = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        if (o.Get("--manifest") is { } mp) {
            using var manifest = Load(mp);
            foreach (var mod in manifest.RootElement.GetProperty("mods").EnumerateObject())
                foreach (var f in mod.Value.GetProperty("files").EnumerateArray()) {
                    var path = f.GetProperty("path").GetString() ?? throw new InvalidDataException("a manifest file has no path");
                    if (!owner.TryGetValue(path, out var mods)) owner[path] = mods = new(StringComparer.Ordinal);
                    mods.Add(mod.Name);
                }
        }

        var users = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        foreach (var f in facts.RootElement.GetProperty("files").EnumerateArray()) {
            if (!f.TryGetProperty("unclassifiedReferences", out var refs)) continue;
            var path = f.GetProperty("path").GetString() ?? throw new InvalidDataException("a facts file entry has no path");
            foreach (var r in refs.EnumerateArray()) {
                var key = Group(r.GetString() ?? throw new InvalidDataException("an unclassified reference is not text"), by);
                if (!users.TryGetValue(key, out var u)) users[key] = u = new(StringComparer.Ordinal);
                u.UnionWith(owner.TryGetValue(path, out var mods) ? mods : [path]);
            }
        }
        var ranked = users.OrderByDescending(kv => kv.Value.Count).ThenBy(kv => kv.Key, StringComparer.Ordinal).ToList();
        Console.WriteLine($"{ranked.Count} unclassified {by}s");
        foreach (var (key, us) in ranked.Take((int)Math.Min(top, int.MaxValue))) {
            var names = us.Order(StringComparer.Ordinal).ToList();
            Console.WriteLine($"{us.Count,4}  {key}  ({string.Join(", ", names.Take(4))}{(names.Count > 4 ? ", ..." : "")})");
        }
        return 0;
    }

    static JsonDocument Load(string path) =>
        File.Exists(path) ? JsonDocument.Parse(File.ReadAllBytes(path)) : throw new UsageException($"file not found: {path}");

    static string Group(string member, string by) {
        if (by == "member") return member;
        var type = member.Split("::", 2)[0];
        if (by == "type") return type;
        int dot = type.LastIndexOf('.');
        return dot >= 0 ? type[..dot] + "." : type;
    }
}
