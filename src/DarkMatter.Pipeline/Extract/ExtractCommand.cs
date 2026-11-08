// SPDX-License-Identifier: MIT
using System.Security.Cryptography;

namespace DarkMatter.Pipeline.Extract;

/// <summary>One code file in the manifest.</summary>
internal sealed record ManifestFile(string Path, string Sha256);

/// <summary>
/// One mod in the manifest. The analyzer reads it (<c>Cli/Inputs.cs</c> <c>LoadManifest</c>); the
/// records are duplicated there on purpose, so the analyzer does not reference this project.
/// </summary>
internal sealed record ManifestMod(List<ManifestFile> Files, List<string> Unextracted, List<string> Scripts);

/// <summary>
/// <c>darkmatter-pipeline extract</c>: extract downloaded mod archives and write the manifest.
/// Downloads and archives are untrusted; see <see cref="Archives"/> and <see cref="ModTree"/>.
/// </summary>
internal static class ExtractCommand {
    static readonly string[] Valued = ["--manifest", "--max-depth", "--max-bytes", "--max-files"];

    const string NestedSuffix = ".extracted";
    static readonly string[] CodeExtensions = [".dll", ".exe", ".so", ".dylib"];
    static readonly string[] ScriptExtensions = [".bat", ".cmd", ".ps1", ".psm1", ".sh", ".command", ".vbs", ".wsf", ".lnk", ".msi"];

    // PE, ELF, Mach-O (both byte orders, 32 and 64 bit) and fat (universal) binaries: a renamed
    // binary is still a code file.
    static readonly byte[][] CodeMagic = [
        "MZ"u8.ToArray(),
        [0x7F, (byte)'E', (byte)'L', (byte)'F'],
        [0xFE, 0xED, 0xFA, 0xCE], [0xFE, 0xED, 0xFA, 0xCF], [0xCE, 0xFA, 0xED, 0xFE], [0xCF, 0xFA, 0xED, 0xFE],
        [0xCA, 0xFE, 0xBA, 0xBE], [0xBE, 0xBA, 0xFE, 0xCA], [0xCA, 0xFE, 0xBA, 0xBF], [0xBF, 0xBA, 0xFE, 0xCA],
    ];

    public static int Run(IReadOnlyList<string> argv) {
        var o = Options.Parse(argv, Valued, []);
        if (o.Positional.Count != 2) throw new UsageException("extract needs a downloads folder and an extraction folder");
        var manifest = o.Get("--manifest") ?? throw new UsageException("extract needs --manifest FILE");
        var maxDepth = (int)Math.Min(o.Number("--max-depth", 3, 0), 64);
        var maxBytes = o.Number("--max-bytes", 2L << 30, 1);
        var maxFiles = o.Number("--max-files", 100_000, 1);
        var (downloads, extracted) = (o.Positional[0], o.Positional[1]);
        if (!Directory.Exists(downloads)) throw new UsageException($"folder not found: {downloads}");
        // Each mod's extraction folder is deleted and recreated: it must not be the downloads.
        var (d, x) = (FullFolder(downloads), FullFolder(extracted));
        if (d.StartsWith(x, StringComparison.OrdinalIgnoreCase) || x.StartsWith(d, StringComparison.OrdinalIgnoreCase))
            throw new UsageException("the downloads and extraction folders must be separate (neither inside the other)");
        Directory.CreateDirectory(extracted);

        var mods = new Dictionary<string, ManifestMod>(StringComparer.Ordinal);
        foreach (var source in Directory.GetDirectories(downloads).Order(StringComparer.Ordinal)) {
            var mid = Path.GetFileName(source);
            // fetch-releases stages downloads in ".partial"; listing ids never start with a dot.
            if (mid.StartsWith('.')) {
                Console.Error.WriteLine($"  skipped folder {Text.Quote(mid)}: not a mod (name starts with a dot)");
                continue;
            }
            var mod = ExtractMod(source, mid, Path.Join(extracted, mid), maxDepth, maxBytes, maxFiles);
            mods[mid] = mod;
            Console.WriteLine($"{Text.Printable(mid)}: {mod.Files.Count} code file(s)"
                + (mod.Unextracted.Count > 0 ? $", {mod.Unextracted.Count} unextracted" : "")
                + (mod.Scripts.Count > 0 ? $", {mod.Scripts.Count} script(s)" : ""));
        }
        Text.WriteJson(manifest, new { root = extracted, mods });
        return 0;
    }

    static string FullFolder(string path) => Path.TrimEndingDirectorySeparator(Path.GetFullPath(path)) + Path.DirectorySeparatorChar;

    static ManifestMod ExtractMod(string source, string mid, string dest, int maxDepth, long maxBytes, long maxFiles) {
        if (Directory.Exists(dest) || File.Exists(dest)) {
            var info = new DirectoryInfo(dest);
            if (info.LinkTarget != null || !info.Exists) throw new UsageException($"{dest} exists and is not a folder; remove it first");
            Directory.Delete(dest, recursive: true);
        }
        Directory.CreateDirectory(dest);
        var tree = new ModTree(dest, maxBytes, maxFiles);
        var unextracted = new List<string>();
        void Warn(string message) => Console.Error.WriteLine($"  {Text.Printable(mid)}: {message}");

        foreach (var path in Directory.EnumerateFileSystemEntries(source).Order(StringComparer.Ordinal)) {
            var asset = Path.GetFileName(path);
            try {
                if (ExtractAsset(path, asset, tree, Warn) is { } problem) unextracted.Add(problem);
            } catch (Exception e) {
                // Whatever went wrong with a hostile file, the result is the same: not extracted.
                unextracted.Add(asset);
                Warn($"failed to extract {Text.Quote(asset)}: {e.Message}");
            }
        }
        try {
            unextracted.AddRange(ExpandNested(tree, maxDepth, Warn));
        } catch (Exception e) {
            unextracted.Add("(nested archives)");
            Warn($"failed to expand nested archives: {e.Message}");
        }

        var files = new List<ManifestFile>();
        var scripts = new List<string>();
        foreach (var p in Walk(dest)) {
            var name = Path.GetFileName(p);
            if (ScriptExtensions.Any(e => name.EndsWith(e, StringComparison.OrdinalIgnoreCase))) scripts.Add(NormPath(p));
            else if (IsCode(p, name)) files.Add(new ManifestFile(NormPath(p), Sha256(p)));
        }
        return new ManifestMod(files, unextracted, scripts);
    }

    /// <summary>
    /// Extracts one downloaded asset into the mod's folder: an archive into a folder named after
    /// it, any other file copied as it is (code, scripts and content are told apart afterwards,
    /// as for files inside an archive). Returns the manifest's "unextracted" entry if it was not
    /// extracted completely.
    /// </summary>
    static string? ExtractAsset(string path, string asset, ModTree tree, Action<string> warn) {
        var info = new FileInfo(path);
        if (!info.Exists || info.LinkTarget != null) {
            warn($"cannot extract {Text.Quote(asset)}: not a regular file");
            return asset;
        }
        var (kind, what) = CodeExtensions.Any(e => asset.EndsWith(e, StringComparison.OrdinalIgnoreCase))
            ? (ArchiveKind.None, "")  // a code file is copied; if it is also an archive, the nested pass opens it
            : Archives.Detect(path);
        if (kind == ArchiveKind.None) {
            if (!tree.Claim([asset], directory: false)) {
                warn($"cannot copy {Text.Quote(asset)}: another file has the same name (ignoring case)");
                return asset;
            }
            using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            tree.Write([asset], input);
            return null;
        }
        if (kind == ArchiveKind.Unsupported) {
            warn($"cannot extract {Text.Quote(asset)}: {what} archives are not supported");
            return asset;
        }
        var folder = FolderFor(asset, tree);
        if (folder == null) {
            warn($"cannot extract {Text.Quote(asset)}: no free folder name for it");
            return asset;
        }
        int skipped = Archives.Extract(path, kind, tree, [folder], warn);
        return skipped > 0 ? $"{asset} ({skipped} entries not extracted)" : null;
    }

    /// <summary>
    /// The folder an asset is extracted into: its name without the archive extension (as before),
    /// or, if that is not a usable name or is taken (a zip and a tar.gz of the same release), its
    /// full name plus ".extracted".
    /// </summary>
    static string? FolderFor(string asset, ModTree tree) {
        var stem = asset.EndsWith(".tar.gz", StringComparison.OrdinalIgnoreCase) ? asset[..^7] : StripExtension(asset);
        foreach (var name in new[] { stem, asset + NestedSuffix })
            if (EntryNames.Check(name, directory: true, out var parts) == null && parts.Length == 1 && parts[0] == name
                && tree.Claim([name], directory: true, fresh: true))
                return name;
        return null;
    }

    /// <summary>The name without its last extension; a name whose only dots lead it has none (".zip" stays ".zip").</summary>
    static string StripExtension(string name) {
        int dot = name.LastIndexOf('.');
        return dot > 0 && name[..dot].Any(c => c != '.') ? name[..dot] : name;
    }

    /// <summary>
    /// Extracts archives found among the mod's files next to themselves (into "NAME.extracted"),
    /// level by level, up to <paramref name="maxDepth"/> levels. Returns the ones it could not
    /// extract completely, by path relative to the mod's folder.
    /// </summary>
    static List<string> ExpandNested(ModTree tree, int maxDepth, Action<string> warn) {
        var unextracted = new List<string>();
        var done = new HashSet<string>(StringComparer.Ordinal);
        for (int depth = 1; depth <= maxDepth + 1; depth++) {
            var found = Walk(tree.Root).Where(done.Add).Select(p => (Path: p, Archive: Archives.Detect(p))).Where(f => f.Archive.Kind != ArchiveKind.None).ToList();
            if (found.Count == 0) break;
            foreach (var (p, (kind, what)) in found) {
                var rel = Path.GetRelativePath(tree.Root, p);
                if (depth > maxDepth) {
                    unextracted.Add(rel);
                    warn($"nested archive {Text.Quote(rel)} is deeper than {maxDepth} levels");
                    continue;
                }
                if (kind == ArchiveKind.Unsupported) {
                    unextracted.Add(rel);
                    warn($"cannot extract nested archive {Text.Quote(rel)}: {what} archives are not supported");
                    continue;
                }
                var into = tree.PartsOf(p);
                into[^1] += NestedSuffix;
                if (!tree.Claim(into, directory: true, fresh: true)) {
                    unextracted.Add(rel);
                    warn($"cannot extract nested archive {Text.Quote(rel)}: {Text.Quote(into[^1])} already exists");
                    continue;
                }
                try {
                    int skipped = Archives.Extract(p, kind, tree, into, warn);
                    if (skipped > 0) unextracted.Add($"{rel} ({skipped} entries not extracted)");
                } catch (Exception e) {
                    unextracted.Add(rel);
                    warn($"cannot extract nested archive {Text.Quote(rel)}: {e.Message}");
                }
            }
        }
        return unextracted;
    }

    /// <summary>Every file under <paramref name="folder"/>: each folder's files in name order, then its subfolders in name order.</summary>
    static IEnumerable<string> Walk(string folder) {
        foreach (var f in Directory.GetFiles(folder).Order(StringComparer.Ordinal)) yield return f;
        foreach (var d in Directory.GetDirectories(folder).Order(StringComparer.Ordinal)) {
            // The tree holds only what ModTree wrote, which is never a link; skip one anyway.
            if (new DirectoryInfo(d).LinkTarget != null) continue;
            foreach (var f in Walk(d)) yield return f;
        }
    }

    static bool IsCode(string path, string name) {
        if (CodeExtensions.Any(e => name.EndsWith(e, StringComparison.OrdinalIgnoreCase))) return true;
        var head = new byte[4];
        int n;
        try {
            using var f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            n = f.ReadAtLeast(head, head.Length, throwOnEndOfStream: false);
        } catch (Exception e) when (e is IOException or UnauthorizedAccessException) {
            // Listed anyway: the analyzer reports a file it cannot read as Full access.
            return true;
        }
        return CodeMagic.Any(m => n >= m.Length && head.AsSpan(0, m.Length).SequenceEqual(m));
    }

    static string Sha256(string path) {
        using var f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexStringLower(SHA256.HashData(f));
    }

    /// <summary>
    /// <paramref name="path"/> with empty and "." components removed and ".." resolved by name,
    /// as the manifest has always written paths (Python's os.path.normpath): relative stays relative.
    /// </summary>
    static string NormPath(string path) {
        var root = Path.GetPathRoot(path) ?? "";
        var parts = new List<string>();
        foreach (var c in path[root.Length..].Split('/', Path.DirectorySeparatorChar)) {
            if (c is "" or ".") continue;
            if (c == ".." && parts.Count > 0 && parts[^1] != "..") parts.RemoveAt(parts.Count - 1);
            else if (c != ".." || root.Length == 0) parts.Add(c);
        }
        var s = root + string.Join(Path.DirectorySeparatorChar, parts);
        return s.Length == 0 ? "." : s;
    }
}
