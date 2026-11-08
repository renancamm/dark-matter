// SPDX-License-Identifier: MIT
using System.Text.Json;
using DarkMatter.Analysis;
using DarkMatter.Evaluation;

namespace DarkMatter.Cli;

/// <summary>One mod as listed in the manifest (or given on the command line).</summary>
internal sealed record ModListing(string Name, IReadOnlyList<(string Path, string? Sha256)> Files, IReadOnlyList<string> Unextracted, IReadOnlyList<string> Scripts);

/// <summary>
/// A game profile: the game-API map, the game's assemblies (null in a profile written before the
/// list existed) and the types they define (for reflection on a game type found by name).
/// </summary>
internal sealed record GameProfile(IReadOnlyDictionary<string, string[]> Methods, IReadOnlyList<string>? Assemblies, IReadOnlySet<string> Types);

/// <summary>Loads the allowlist, the game profile and the manifest.</summary>
internal static class Inputs {
    public static string Require(string path) => File.Exists(path) ? path : throw new UsageException($"file not found: {path}");

    static string Text(JsonElement e, string what) => e.GetString() ?? throw new InvalidDataException($"{what}: expected text");

    public static Allowlist LoadAllowlist(string path) {
        using var doc = JsonDocument.Parse(File.ReadAllText(Require(path)));
        var hashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var byName = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in doc.RootElement.GetProperty("libraries").EnumerateObject()) {
            var hash = e.Name.ToLowerInvariant();
            hashes.Add(hash);
            if (e.Value.TryGetProperty("name", out var n) && n.GetString() is { Length: > 0 } name) {
                names.Add(name);
                if (!byName.TryGetValue(name, out var list)) byName[name] = list = [];
                list.Add(hash);
            }
        }
        return new Allowlist(hashes, names, byName.ToDictionary(kv => kv.Key, kv => (IReadOnlyList<string>)kv.Value, StringComparer.OrdinalIgnoreCase));
    }

    /// <summary>Profile files written by `darkmatter profile`; one without the current format is refused.</summary>
    public const int ProfileFormat = 3;

    // A profile is derived with one policy's rules. With another policy its capabilities could be
    // missing ones the current rules would find, so it must be regenerated, not used.
    static void CheckProfile(JsonElement root, string path, Policy policy, string what) {
        if (!root.TryGetProperty("format", out var f) || f.ValueKind != JsonValueKind.Number || f.GetInt32() != ProfileFormat)
            throw new InvalidDataException($"{what} {path} was written by an older version of the tool (it may leave out capabilities that raise the tier); regenerate it with `darkmatter profile`");
        string? sha = root.TryGetProperty("stamp", out var st) && st.TryGetProperty("policy", out var p) && p.TryGetProperty("sha256", out var s) ? s.GetString() : null;
        if (sha != policy.Sha256)
            throw new InvalidDataException($"{what} {path} was made with a different policy (sha256 {sha ?? "missing"}, current {policy.Sha256}); regenerate it with `darkmatter profile`");
    }

    public static GameProfile LoadGameProfile(string path, Policy policy) {
        using var doc = JsonDocument.Parse(File.ReadAllText(Require(path)));
        CheckProfile(doc.RootElement, path, policy, "game profile");
        var known = policy.ProducibleCaps.ToHashSet();
        var map = new Dictionary<string, string[]>(StringComparer.Ordinal);
        foreach (var e in doc.RootElement.GetProperty("methods").EnumerateObject()) {
            var caps = e.Value.EnumerateArray().Select(x => Text(x, path)).ToArray();
            foreach (var c in caps)
                if (!known.Contains(c) || policy.FileKinds.ContainsKey(c) || policy.Informational.Contains(c))
                    throw new InvalidDataException($"game profile {path}: unexpected capability '{c}' for {e.Name}");
            map[e.Name] = caps;
        }
        // Older profiles have no assembly list; the policy's fallback patterns apply.
        IReadOnlyList<string>? assemblies = doc.RootElement.TryGetProperty("assemblies", out var a)
            ? [.. a.EnumerateArray().Select(x => Text(x, path))]
            : null;
        if (assemblies == null) Console.Error.WriteLine($"warning: game profile {path} has no assembly list; using the policy's game assembly patterns");
        var types = doc.RootElement.GetProperty("types").EnumerateArray().Select(x => Text(x, path)).ToHashSet(StringComparer.Ordinal);
        return new GameProfile(map, assemblies, types);
    }

    /// <summary>Library profiles by file SHA-256, from one or more files written by `darkmatter profile --library`.</summary>
    public static TrustedLibraries LoadLibraryProfiles(IEnumerable<string> paths, Policy policy, Allowlist allow) {
        var known = policy.ProducibleCaps.Concat(Policy.Findings).ToHashSet();
        var profiles = new Dictionary<string, LibraryProfile>(StringComparer.OrdinalIgnoreCase);
        var native = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var path in paths) {
            using var doc = JsonDocument.Parse(File.ReadAllText(Require(path)));
            CheckProfile(doc.RootElement, path, policy, "library profile");
            foreach (var lib in doc.RootElement.GetProperty("libraries").EnumerateObject()) {
                var v = lib.Value;
                var members = new Dictionary<string, Reach.Caps>(StringComparer.Ordinal);
                foreach (var m in v.GetProperty("members").EnumerateObject()) {
                    var caps = new Reach.Caps();
                    foreach (var c in m.Value.EnumerateObject()) {
                        if (!known.Contains(c.Name) || policy.FileKinds.ContainsKey(c.Name) || policy.Informational.Contains(c.Name))
                            throw new InvalidDataException($"library profile {path}: unexpected capability '{c.Name}' for {m.Name}");
                        caps[c.Name] = Text(c.Value, path);
                    }
                    members[m.Name] = caps;
                }
                var types = v.GetProperty("types").EnumerateObject()
                    .ToDictionary(t => t.Name, t => (IReadOnlyList<string>)[.. t.Value.EnumerateArray().Select(x => Text(x, path))], StringComparer.Ordinal);
                var forwarded = v.GetProperty("forwarded").EnumerateArray().Select(x => Text(x, path)).ToHashSet(StringComparer.Ordinal);
                profiles[lib.Name.ToLowerInvariant()] = new LibraryProfile(Text(v.GetProperty("name"), path), Text(v.GetProperty("assembly"), path), types, forwarded, members);
            }
            if (doc.RootElement.TryGetProperty("native", out var n))
                foreach (var e in n.EnumerateObject()) native.Add(e.Name.ToLowerInvariant());
        }
        var missing = allow.Hashes.Count(h => !profiles.ContainsKey(h) && !native.Contains(h));
        if (missing > 0)
            Console.Error.WriteLine($"warning: {missing} of {allow.Hashes.Count} trusted files have no library profile; calls into a library with an unprofiled version count as not analyzed");
        // A native file of the same name (an app host next to its managed assembly) is not a version a managed reference can load.
        var managed = allow.ByName.ToDictionary(kv => kv.Key, kv => (IReadOnlyList<string>)[.. kv.Value.Where(h => !native.Contains(h))], StringComparer.OrdinalIgnoreCase);
        return new TrustedLibraries(managed, profiles);
    }

    /// <summary>
    /// The manifest written by <c>darkmatter-pipeline extract</c> (its <c>ManifestMod</c> record;
    /// the two programs share no code, so the format is kept in step by hand).
    /// </summary>
    public static List<ModListing> LoadManifest(string path) {
        using var doc = JsonDocument.Parse(File.ReadAllText(Require(path)));
        var mods = new List<ModListing>();
        foreach (var mod in doc.RootElement.GetProperty("mods").EnumerateObject()) {
            var files = mod.Value.GetProperty("files").EnumerateArray()
                .Select(f => (Text(f.GetProperty("path"), path), (string?)Text(f.GetProperty("sha256"), path).ToLowerInvariant()))
                .ToList();
            var unextracted = mod.Value.TryGetProperty("unextracted", out var u)
                ? u.EnumerateArray().Select(x => Text(x, path)).ToList()
                : [];
            var scripts = mod.Value.TryGetProperty("scripts", out var sc)
                ? sc.EnumerateArray().Select(x => Text(x, path)).ToList()
                : [];
            mods.Add(new ModListing(mod.Name, files, unextracted, scripts));
        }
        return mods;
    }
}
