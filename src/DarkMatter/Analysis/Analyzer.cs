// SPDX-License-Identifier: MIT
using System.Reflection.PortableExecutable;

namespace DarkMatter.Analysis;

/// <summary>
/// Trusted-library allowlist: SHA-256 hashes, the names they carry (for impersonation checks),
/// and the hashes of every trusted version of each name.
/// </summary>
internal sealed record Allowlist(IReadOnlySet<string> Hashes, IReadOnlySet<string> Names, IReadOnlyDictionary<string, IReadOnlyList<string>> ByName) {
    public static Allowlist Empty { get; } = new(new HashSet<string>(), new HashSet<string>(), new Dictionary<string, IReadOnlyList<string>>());
}

/// <summary>
/// Reads one file's metadata and IL, without loading or running it, and records everything
/// the policy needs in a single pass per method.
/// </summary>
/// <param name="policy">The policy whose rules classify members.</param>
/// <param name="allow">Trusted-library allowlist.</param>
/// <param name="gameApi">The game-API map.</param>
/// <param name="framework">Assembly names of the .NET shared framework (see <c>Evaluation.Boundary.SharedFramework</c>):
/// only members that live there get the framework semantics the walker models by name.</param>
/// <param name="game">The game's assembly names (from the game profile), or null for the policy's game
/// assembly patterns: only members that live there get the game semantics the policy gives by name
/// (path sources such as the saves folder).</param>
/// <param name="gameInlineArrays">The game's [InlineArray] types, from the game profile (none without one).</param>
/// <param name="gameTypes">The declared types of the game's members and its base types, from the game profile (D2); null without one.</param>
/// <param name="explain">Also note what produced each value the walkers do not follow (see <see cref="Slot.Why"/>), for the facts output.</param>
internal sealed class Analyzer(Policy policy, Allowlist allow, IReadOnlyDictionary<string, string[]> gameApi, IReadOnlySet<string> framework,
    IReadOnlySet<string>? game, IReadOnlyDictionary<string, InlineArrayShape>? gameInlineArrays = null, GameTypes? gameTypes = null, bool explain = false) {
    /// <summary>The bytes of a file, or null (with why) if it cannot be read.</summary>
    public static byte[]? Read(string path, out string? error) {
        error = null;
        try {
            return File.ReadAllBytes(path);
        } catch (Exception e) when (e is IOException or UnauthorizedAccessException) {
            error = e.Message;
            return null;
        }
    }

    public AssemblyFacts Analyze(string path) => Analyze(path, Read(path, out var error), error);

    /// <summary>
    /// Analyzes the bytes read from <paramref name="path"/> (null if they could not be read): the
    /// hash and the analysis come from the same bytes, so the file cannot change in between.
    /// </summary>
    public AssemblyFacts Analyze(string path, byte[]? bytes, string? error) {
        var sha = bytes != null ? Il.Sha256(bytes) : null;
        var facts = new AssemblyFacts { Path = path, Sha256 = sha, Name = System.IO.Path.GetFileNameWithoutExtension(path) };
        if (bytes == null) { facts.Error = "file could not be read" + (error != null ? $" ({error})" : ""); return facts; }
        // An ELF or Mach-O program or library is native code, like a PE without .NET metadata: one
        // reason ("Ships a native program or library"), not a file the check cannot read.
        if (IsNativeImage(bytes)) { facts.Classification = FileClass.Native; return facts; }
        try {
            using var pe = new PEReader(System.Collections.Immutable.ImmutableArray.Create(bytes));
            if (!pe.HasMetadata) { facts.Classification = FileClass.Native; return facts; }
            new AssemblyWalker(policy, allow, gameApi, framework, game, pe, facts, gameInlineArrays, gameTypes, explain).Run();
        } catch (Exception e) {
            // Deliberately broad: malformed metadata can fail in many ways, and any of them is a
            // finding (Broad access) for this file, never a crash that loses the whole run.
            facts.Classification = FileClass.Error;
            facts.Error = e.GetType().Name + ": " + e.Message;
            facts.Methods.Clear();
        }
        return facts;
    }

    /// <summary>
    /// Whether the bytes begin like an ELF or Mach-O image (thin, either byte order, or universal).
    /// Both are native code whatever they hold; a .NET assembly is always a PE file.
    /// </summary>
    public static bool IsNativeImage(ReadOnlySpan<byte> b) {
        if (b.Length < 8) return false;
        uint magic = (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);
        if (magic == 0x7F454C46) return true;  // ELF
        if (magic is 0xFEEDFACE or 0xFEEDFACF or 0xCEFAEDFE or 0xCFFAEDFE) return true;  // Mach-O, 32 or 64 bit, either byte order
        // A universal (fat) Mach-O, 32 or 64 bit, either byte order (as extraction's CodeMagic). Java
        // class files share the magic: not .NET assemblies either, and counted the same.
        return magic is 0xCAFEBABE or 0xCAFEBABF or 0xBEBAFECA or 0xBFBAFECA;
    }
}
