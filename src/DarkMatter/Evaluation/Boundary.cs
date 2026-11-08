// SPDX-License-Identifier: MIT
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;

namespace DarkMatter.Evaluation;

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
internal sealed record Boundary(IReadOnlySet<string> Trusted, IReadOnlySet<string>? Game, IReadOnlyList<string> GamePatterns, IReadOnlySet<string> Framework) {
    readonly Lazy<HashSet<string>> frameworkTypes = new(SharedFrameworkTypes);

    /// <summary>Whether a type of that name is defined or forwarded by an assembly of the shared framework.</summary>
    public bool IsFrameworkType(string type) => frameworkTypes.Value.Contains(type);

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
    /// call counts as not analyzed (Unverified) instead of being trusted.
    /// </summary>
    // Names of the types the shared framework's assemblies define or forward ("Namespace.Outer/Inner"),
    // read from their metadata (never loaded). A file that cannot be read adds none: a type found by
    // name only there counts as code that was not analyzed.
    static HashSet<string> SharedFrameworkTypes() {
        var types = new HashSet<string>(StringComparer.Ordinal);
        IEnumerable<string> files;
        try { files = Directory.EnumerateFiles(RuntimeEnvironment.GetRuntimeDirectory(), "*.dll").ToList(); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return types; }
        foreach (var path in files) {
            try {
                using var fs = File.OpenRead(path);
                using var pe = new PEReader(fs);
                if (!pe.HasMetadata) continue;
                var md = pe.GetMetadataReader();
                foreach (var th in md.TypeDefinitions) types.Add(Analysis.Il.TypeName(md, th));
                foreach (var eh in md.ExportedTypes) {
                    var e = md.GetExportedType(eh);
                    if (e.Implementation.Kind != HandleKind.ExportedType)
                        types.Add(md.GetString(e.Namespace) is { Length: > 0 } ns ? ns + "." + md.GetString(e.Name) : md.GetString(e.Name));
                }
            } catch (Exception e) when (e is IOException or UnauthorizedAccessException or BadImageFormatException or InvalidOperationException) {
                // Silence on purpose: this file's types are not known, which fails closed (see above).
            }
        }
        return types;
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
