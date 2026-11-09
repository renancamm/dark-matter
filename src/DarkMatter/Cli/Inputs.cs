// SPDX-License-Identifier: MIT
using System.Text.Json;
using DarkMatter.Analysis;
using DarkMatter.Evaluation;

namespace DarkMatter.Cli;

/// <summary>
/// One mod as listed in the manifest (or given on the command line). <paramref name="Folder"/> is
/// the mod's extraction folder (the manifest's root plus the mod's name): paths under it are shown
/// relative to it in results, so a result names files as they are in the mod's archives, not where
/// one machine extracted them. Null for files given on the command line, which are shown as given.
/// </summary>
internal sealed record ModListing(string Name, IReadOnlyList<(string Path, string? Sha256)> Files, IReadOnlyList<string> Unextracted, IReadOnlyList<string> Scripts,
    string? Folder = null) {
    /// <summary><paramref name="path"/> as results show it.</summary>
    public string Shown(string path) {
        if (Folder == null) return path;
        var rel = System.IO.Path.GetRelativePath(Folder, path);
        return rel == ".." || rel.StartsWith(".." + System.IO.Path.DirectorySeparatorChar, StringComparison.Ordinal) || System.IO.Path.IsPathRooted(rel)
            ? path
            : rel.Replace(System.IO.Path.DirectorySeparatorChar, '/');
    }
}

/// <summary>
/// A game profile: the game-API map, the game's assemblies (null in a profile written before the
/// list existed), the types they define (for reflection on a game type found by name), the names of
/// every method and field they define by type, and each type's base type other than System.Object (a
/// reference to a member that neither a game type nor its base types define is code this build does
/// not have), the declared types of every member of every game type and the interfaces each type implements
/// (format 7, D2 and D3: a lookup by name on a game type types what it finds, and a game type known only up to
/// its derived types reaches theirs).
/// </summary>
internal sealed record GameProfile(IReadOnlyDictionary<string, string[]> Methods, IReadOnlyList<string>? Assemblies, IReadOnlySet<string> Types,
    IReadOnlyDictionary<string, IReadOnlySet<string>> Members, IReadOnlyDictionary<string, string> Bases, IReadOnlyDictionary<string, InlineArrayShape> InlineArrays,
    IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>> MemberTypes, IReadOnlyDictionary<string, IReadOnlyList<string>> Interfaces) {
    /// <summary>What the walker needs of the game's types (see <see cref="Analysis.GameTypes"/>).</summary>
    public GameTypes GameTypes { get; } = new(MemberTypes, Bases);
}

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
            // "name", and "names" for a file published under more than one name: every one is trusted.
            var entryNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (e.Value.TryGetProperty("name", out var n) && n.ValueKind == JsonValueKind.String && n.GetString() is { Length: > 0 } one) entryNames.Add(one);
            if (e.Value.TryGetProperty("names", out var ns) && ns.ValueKind == JsonValueKind.Array)
                foreach (var x in ns.EnumerateArray())
                    if (x.ValueKind == JsonValueKind.String && x.GetString() is { Length: > 0 } other) entryNames.Add(other);
            foreach (var name in entryNames) {
                names.Add(name);
                if (!byName.TryGetValue(name, out var list)) byName[name] = list = [];
                list.Add(hash);
            }
        }
        return new Allowlist(hashes, names, byName.ToDictionary(kv => kv.Key, kv => (IReadOnlyList<string>)kv.Value, StringComparer.OrdinalIgnoreCase));
    }

    /// <summary>Profile files written by `darkmatter profile`; one without the current format is refused.</summary>
    public const int ProfileFormat = 7;

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
                if (c != GameApiProfile.Unanalyzed && (!known.Contains(c) || policy.FileKinds.ContainsKey(c) || policy.Informational.Contains(c)))
                    throw new InvalidDataException($"game profile {path}: unexpected capability '{c}' for {e.Name}");
            map[e.Name] = caps;
        }
        // Older profiles have no assembly list; the policy's fallback patterns apply.
        IReadOnlyList<string>? assemblies = doc.RootElement.TryGetProperty("assemblies", out var a)
            ? [.. a.EnumerateArray().Select(x => Text(x, path))]
            : null;
        if (assemblies == null) Console.Error.WriteLine($"warning: game profile {path} has no assembly list; using the policy's game assembly patterns");
        var types = doc.RootElement.GetProperty("types").EnumerateArray().Select(x => Text(x, path)).ToHashSet(StringComparer.Ordinal);
        var members = doc.RootElement.GetProperty("members").EnumerateObject().ToDictionary(t => t.Name,
            t => (IReadOnlySet<string>)t.Value.EnumerateArray().Select(x => Text(x, path)).ToHashSet(StringComparer.Ordinal), StringComparer.Ordinal);
        var bases = doc.RootElement.GetProperty("bases").EnumerateObject().ToDictionary(t => t.Name, t => Text(t.Value, path), StringComparer.Ordinal);
        // The game's [InlineArray] types (format 6): a length that is not a positive number is an entry the check cannot use.
        var inlineArrays = new Dictionary<string, InlineArrayShape>(StringComparer.Ordinal);
        foreach (var t in doc.RootElement.GetProperty("inlineArrays").EnumerateObject()) {
            if (!t.Value.TryGetProperty("length", out var len) || len.ValueKind != JsonValueKind.Number || !len.TryGetInt32(out var count) || count < 1)
                throw new InvalidDataException($"game profile {path}: inline array {t.Name} has no valid length");
            inlineArrays[t.Name] = new(count, Text(t.Value.GetProperty("element"), path));
        }
        // The declared types of the game's members (format 7, D2): a key or value of another form is an entry the
        // check cannot use, so the profile is refused rather than read as typing less (or more) than it says.
        var memberTypes = new Dictionary<string, IReadOnlyDictionary<string, string>>(StringComparer.Ordinal);
        foreach (var t in doc.RootElement.GetProperty("memberTypes").EnumerateObject()) {
            var of = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var m in t.Value.EnumerateObject()) {
                var value = Text(m.Value, path);
                if (MemberTypes.ParseKey(m.Name) == null || (value != MemberTypes.Unknown && MemberTypes.Decode(value) == null))
                    throw new InvalidDataException($"game profile {path}: member type entry {t.Name} {m.Name} is not valid");
                of[m.Name] = value;
            }
            memberTypes[t.Name] = of;
        }
        var interfaces = doc.RootElement.GetProperty("interfaces").EnumerateObject()
            .ToDictionary(t => t.Name, t => (IReadOnlyList<string>)[.. t.Value.EnumerateArray().Select(x => Text(x, path))], StringComparer.Ordinal);
        if (doc.RootElement.TryGetProperty("skipped", out var sk) && sk.ValueKind == JsonValueKind.Array && sk.GetArrayLength() is > 0 and var n)
            Console.Error.WriteLine($"warning: game profile {path} lists {n} game file{(n == 1 ? "" : "s")} it could not read; calls into {(n == 1 ? "it" : "them")} count as not analyzed");
        return new GameProfile(map, assemblies, types, members, bases, inlineArrays, memberTypes, interfaces);
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
        // Paths are shown relative to each mod's folder (GetRelativePath resolves relative ones against the current folder).
        string? root = doc.RootElement.TryGetProperty("root", out var r) && r.ValueKind == JsonValueKind.String ? Path.GetFullPath(Text(r, path)) : null;
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
            var folder = root != null && mod.Name.Length > 0 && mod.Name is not ("." or "..") && mod.Name.IndexOfAny(['/', '\\']) < 0 ? Path.Join(root, mod.Name) : null;
            mods.Add(new ModListing(mod.Name, files, unextracted, scripts, folder));
        }
        return mods;
    }
}
