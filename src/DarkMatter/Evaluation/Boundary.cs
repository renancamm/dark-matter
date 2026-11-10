// SPDX-License-Identifier: MIT
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;

namespace DarkMatter.Evaluation;

/// <summary>What a member referenced in a game assembly runs (see <see cref="Boundary.GameTarget"/>).</summary>
internal enum GameRef { Defined, Inherited, Framework, Missing }

/// <summary>
/// Another build of the game than the one the mod is checked against: its name (for evidence), what it
/// defines (a <see cref="Boundary"/> made from its game profile) and its game-API map. A mod built for
/// another game version references members the current build lacks; they are looked up here.
/// </summary>
internal sealed record OtherGame(string Name, Boundary Boundary, IReadOnlyDictionary<string, string[]> Api);

/// <summary>Where the code of a referenced assembly comes from.</summary>
internal enum AssemblyKind {
    /// <summary>One of the mod's own files: analyzed with the mod.</summary>
    Mod,
    /// <summary>A library on the allowlist (by name; a shipped copy is checked by hash).</summary>
    Trusted,
    /// <summary>One of the game's assemblies.</summary>
    Game,
    /// <summary>The .NET shared framework: every member used must be classified by the policy.</summary>
    Framework,
    /// <summary>Anything else: code the check did not look at.</summary>
    Unanalyzed,
}

/// <summary>
/// Decides what a referenced assembly is, by name, in this order: a trusted library, the game, the
/// framework, a file of the mod. Anything else was not analyzed. The mod comes last because the
/// loader resolves those names before a mod's own files (the runtime's and the game's assemblies
/// are already loaded, the loader's own copies of trusted libraries win): a mod file named like one
/// of them is not what a reference to that name runs (the Evaluator reports such a file).
/// </summary>
/// <param name="Trusted">Assembly names on the allowlist.</param>
/// <param name="Game">The game's assemblies from the game profile, or null to use <paramref name="GamePatterns"/>.</param>
/// <param name="GamePatterns">The policy's fallback game assembly patterns ("Brutal.*").</param>
/// <param name="Framework">Assembly names of the .NET shared framework.</param>
/// <param name="GameMembers">Every game type, with the names of the methods and fields it defines, from the
/// game profile; null without one.</param>
/// <param name="GameBases">Each game type's base type other than System.Object, from the game profile.</param>
/// <param name="GameInterfaces">The interfaces each game type implements, from the game profile (format 7, D3).</param>
internal sealed record Boundary(IReadOnlySet<string> Trusted, IReadOnlySet<string>? Game, IReadOnlyList<string> GamePatterns, IReadOnlySet<string> Framework,
    IReadOnlyDictionary<string, IReadOnlySet<string>>? GameMembers = null, IReadOnlyDictionary<string, string>? GameBases = null,
    IReadOnlyDictionary<string, IReadOnlyList<string>>? GameInterfaces = null) {
    readonly Lazy<(HashSet<string> Names, Dictionary<string, string> Files)> frameworkTypes = new(SharedFrameworkTypes);
    readonly Dictionary<(string, string, bool), string?> frameworkDeclaring = [];

    /// <summary>Whether a type of that name is defined or forwarded by an assembly of the shared framework.</summary>
    public bool IsFrameworkType(string type) => frameworkTypes.Value.Names.Contains(type);

    /// <summary>The shared framework's types directly nested in <paramref name="type"/> ("Namespace.Outer/Inner").</summary>
    public IEnumerable<string> FrameworkNestedTypes(string type) =>
        frameworkTypes.Value.Names.Where(t => t.Length > type.Length + 1 && t.StartsWith(type + "/", StringComparison.Ordinal) && t.IndexOf('/', type.Length + 1) < 0);

    /// <summary>Whether the game profile says the game type <paramref name="type"/> defines a method or field named <paramref name="name"/>.</summary>
    public bool GameDefines(string type, string name) => GameMembers != null && GameMembers.TryGetValue(type, out var names) && names.Contains(name);

    /// <summary>The names of the methods and fields the game type <paramref name="type"/> defines (empty without a game profile).</summary>
    public IReadOnlySet<string> GameMembersOf(string type) => GameMembers != null && GameMembers.TryGetValue(type, out var names) ? names : EmptyNames;

    static readonly IReadOnlySet<string> EmptyNames = new HashSet<string>();

    /// <summary>The names of the methods and fields of the game type <paramref name="type"/> and of every type nested in it (empty without a game profile).</summary>
    public IEnumerable<string> GameMembersWithNested(string type) => GameMembers == null ? []
        : GameMembers.Where(kv => kv.Key == type || kv.Key.StartsWith(type + "/", StringComparison.Ordinal)).SelectMany(kv => kv.Value);

    Dictionary<string, List<string>>? gameNestedWithBase;
    Dictionary<string, List<string>>? gameSubtypes;

    /// <summary>
    /// The game types that derive from <paramref name="type"/>, directly or through other types, by base type or
    /// by interface (D3, D9), in name order; empty without a game profile. A type's own name is not included.
    /// </summary>
    public IReadOnlyList<string> GameDerived(string type) {
        if (GameMembers == null) return [];
        Dictionary<string, List<string>> subtypes;
        lock (frameworkDeclaring) {
            if (gameSubtypes == null) {
                gameSubtypes = new(StringComparer.Ordinal);
                void Edge(string super, string sub) {
                    if (!gameSubtypes.TryGetValue(super, out var list)) gameSubtypes[super] = list = [];
                    list.Add(sub);
                }
                foreach (var (t, b) in GameBases ?? new Dictionary<string, string>()) Edge(b, t);
                foreach (var (t, interfaces) in GameInterfaces ?? new Dictionary<string, IReadOnlyList<string>>())
                    foreach (var i in interfaces) Edge(i, t);
            }
            subtypes = gameSubtypes;
        }
        var found = new SortedSet<string>(StringComparer.Ordinal);
        var todo = new Stack<string>([type]);
        while (todo.Count > 0)
            if (subtypes.TryGetValue(todo.Pop(), out var direct))
                foreach (var d in direct)
                    if (d != type && GameMembers.ContainsKey(d) && found.Add(d)) todo.Push(d);
        return [.. found];
    }

    /// <summary>
    /// The game types nested in <paramref name="type"/> at any depth that have a base type other than
    /// System.Object (in the game profile), outermost first; empty without a game profile.
    /// </summary>
    public IReadOnlyList<string> GameNestedWithBase(string type) {
        if (GameBases == null) return [];
        lock (frameworkDeclaring) {
            if (gameNestedWithBase == null) {
                gameNestedWithBase = new(StringComparer.Ordinal);
                foreach (var t in GameBases.Keys.Order(StringComparer.Ordinal))
                    for (int i = t.IndexOf('/'); i > 0; i = t.IndexOf('/', i + 1)) {
                        if (!gameNestedWithBase.TryGetValue(t[..i], out var list)) gameNestedWithBase[t[..i]] = list = [];
                        list.Add(t);
                    }
            }
            return gameNestedWithBase.TryGetValue(type, out var nested) ? nested : [];
        }
    }

    /// <summary>
    /// The base type chain of a game type, as the game profile has it: the type, then its base types
    /// while they are game types, then (<paramref name="beyond"/>) the first base type that is not a game
    /// type: System.Object when the last game type has none listed (an interface's is System.Object too:
    /// only its members could be named through it), or null when the chain cannot be followed (no profile, a
    /// type the game does not define, a cycle).
    /// </summary>
    public List<string> GameChain(string type, out string? beyond) {
        var chain = new List<string>();
        beyond = null;
        if (GameMembers == null || !GameMembers.ContainsKey(type)) return chain;
        var t = type;
        while (chain.Count < 64 && !chain.Contains(t)) {  // a cycle is not a real hierarchy
            chain.Add(t);
            if (GameBases == null || !GameBases.TryGetValue(t, out var b)) { beyond = "System.Object"; return chain; }
            if (!GameMembers.ContainsKey(b)) { beyond = b; return chain; }
            t = b;
        }
        return chain;
    }

    /// <summary>
    /// What a member referenced in a game assembly ("Namespace.Type::Member") runs, as the runtime looks a
    /// member reference up: on its type, then on each base type in turn. <see cref="GameRef.Defined"/>: the
    /// type defines it (or there is no game profile to say otherwise). <see cref="GameRef.Inherited"/>: a game
    /// base type does (<paramref name="target"/>, whose game-API map entry is what the call runs).
    /// <see cref="GameRef.Framework"/>: a framework base type does (<paramref name="target"/>, which the
    /// policy classifies as a direct reference to it). <see cref="GameRef.Missing"/>: none of them does (a type
    /// this build lacks or forwards elsewhere, a member removed or renamed in this build). The game-API map has
    /// no entry for it, which would read as "reaches nothing": what it runs was not analyzed. By name: two
    /// overloads are one member, as in the map.
    /// </summary>
    public GameRef GameTarget(string member, out string target) {
        target = member;
        int sep = member.IndexOf("::", StringComparison.Ordinal);
        if (GameMembers == null || sep < 0) return GameRef.Defined;
        string type = member[..sep], name = member[(sep + 2)..];
        var chain = GameChain(type, out var beyond);
        for (int i = 0; i < chain.Count; i++)
            if (GameDefines(chain[i], name)) {
                target = chain[i] + "::" + name;
                return i == 0 ? GameRef.Defined : GameRef.Inherited;
            }
        if (beyond != null && IsFrameworkType(beyond) && FrameworkDeclaring(beyond, name) is { } declaring) {
            target = declaring + "::" + name;
            return GameRef.Framework;
        }
        return GameRef.Missing;
    }

    /// <summary>
    /// The framework type that defines a method or field named <paramref name="name"/> for
    /// <paramref name="type"/>: the type itself or its nearest base type that does (read from the framework's
    /// metadata, never loaded), comparing names ignoring case with <paramref name="ignoreCase"/>; null when
    /// none does. A type whose file cannot be read, or that no readable file defines, is taken to define it
    /// (fail closed: the name is then classified on that type by the policy's rules).
    /// </summary>
    public string? FrameworkDeclaring(string type, string name, bool ignoreCase = false) {
        lock (frameworkDeclaring) {
            if (frameworkDeclaring.TryGetValue((type, name, ignoreCase), out var cached)) return cached;
            string? found = null;
            for (var (t, depth) = ((string?)type, 0); t != null && depth < 32; depth++) {
                // A type no readable framework file defines (its file could not be read when the types were
                // listed, H12) is taken to define it too.
                if (!frameworkTypes.Value.Files.TryGetValue(t, out var file)) { found = t; break; }
                var b = FrameworkMember(file, t, name, ignoreCase, out bool defines, out bool unread);
                // A file that cannot be read may define it: taken to (H10b review; before, it read as no member, and a
                // lookup's name inherited from that type reached nothing). Every caller then classifies t::name.
                if (defines || unread) { found = t; break; }
                t = b;
            }
            return frameworkDeclaring[(type, name, ignoreCase)] = found;
        }
    }

    // Whether the framework type defines a method or field of that name, and its base type's name (null for none);
    // unread: the file cannot be read.
    static string? FrameworkMember(string file, string type, string name, bool ignoreCase, out bool defines, out bool unread) {
        defines = false;
        unread = false;
        try {
            using var fs = File.OpenRead(file);
            using var pe = new PEReader(fs);
            var md = pe.GetMetadataReader();
            foreach (var th in md.TypeDefinitions) {
                if (Analysis.Il.TypeName(md, th) != type) continue;
                var t = md.GetTypeDefinition(th);
                defines = t.GetMethods().Any(h => md.StringComparer.Equals(md.GetMethodDefinition(h).Name, name, ignoreCase))
                    || t.GetFields().Any(h => md.StringComparer.Equals(md.GetFieldDefinition(h).Name, name, ignoreCase));
                return t.BaseType.IsNil ? null : Analysis.Il.TypeName(md, t.BaseType);
            }
        } catch (Exception e) when (e is IOException or UnauthorizedAccessException or BadImageFormatException or InvalidOperationException) {
            // Silence on purpose: the caller counts the member as declared here (see FrameworkDeclaring).
            unread = true;
        }
        return null;
    }

    /// <summary>
    /// Whether <paramref name="name"/> is named like a game assembly (the policy's game patterns) but the game
    /// build the profile describes has no assembly of that name (H9): with no game profile every such name is
    /// the game, so this is false.
    /// </summary>
    public bool MissingGameAssembly(string name) => Game != null && name.Length > 0 && !Game.Contains(name) && Policy.MatchesName(GamePatterns, name);

    public AssemblyKind Resolve(string name, IReadOnlySet<string> modAssemblies) {
        // "" is a reference whose assembly could not be determined.
        if (name.Length == 0) return AssemblyKind.Unanalyzed;
        if (Trusted.Contains(name)) return AssemblyKind.Trusted;
        if (Game != null ? Game.Contains(name) : Policy.MatchesName(GamePatterns, name)) return AssemblyKind.Game;
        if (Framework.Contains(name)) return AssemblyKind.Framework;
        if (modAssemblies.Contains(name)) return AssemblyKind.Mod;
        return AssemblyKind.Unanalyzed;
    }

    /// <summary>
    /// Names of the assemblies in the .NET shared framework the tool runs on
    /// (Microsoft.NETCore.App, the same set the game ships as its runtime). The files are only
    /// listed, never loaded. If the folder cannot be listed the set is empty, so every framework
    /// call counts as not analyzed (not fully checked) instead of being trusted.
    /// </summary>
    // Names of the types the shared framework's assemblies define or forward ("Namespace.Outer/Inner"),
    // read from their metadata (never loaded). A file that cannot be read adds none: a type found by
    // name only there counts as code that was not analyzed.
    // Also the file that defines each one (for FrameworkDeclaring).
    static (HashSet<string>, Dictionary<string, string>) SharedFrameworkTypes() {
        var types = new HashSet<string>(StringComparer.Ordinal);
        var defined = new Dictionary<string, string>(StringComparer.Ordinal);
        IEnumerable<string> files;
        try { files = Directory.EnumerateFiles(RuntimeEnvironment.GetRuntimeDirectory(), "*.dll").ToList(); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return (types, defined); }
        foreach (var path in files) {
            try {
                using var fs = File.OpenRead(path);
                using var pe = new PEReader(fs);
                if (!pe.HasMetadata) continue;
                var md = pe.GetMetadataReader();
                foreach (var th in md.TypeDefinitions) {
                    var name = Analysis.Il.TypeName(md, th);
                    types.Add(name);
                    defined.TryAdd(name, path);
                }
                foreach (var eh in md.ExportedTypes) {
                    var e = md.GetExportedType(eh);
                    if (e.Implementation.Kind != HandleKind.ExportedType)
                        types.Add(md.GetString(e.Namespace) is { Length: > 0 } ns ? ns + "." + md.GetString(e.Name) : md.GetString(e.Name));
                }
            } catch (Exception e) when (e is IOException or UnauthorizedAccessException or BadImageFormatException or InvalidOperationException) {
                // Silence on purpose: this file's types are not known, which fails closed (see above).
            }
        }
        return (types, defined);
    }

    public static IReadOnlySet<string> SharedFramework() {
        try {
            return Directory.EnumerateFiles(RuntimeEnvironment.GetRuntimeDirectory(), "*.dll")
                .Select(Path.GetFileNameWithoutExtension).OfType<string>()
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
        } catch (Exception e) when (e is IOException or UnauthorizedAccessException) {
            Console.Error.WriteLine($"warning: the .NET shared framework could not be listed ({e.Message}); framework calls count as not analyzed");
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }
    }
}
