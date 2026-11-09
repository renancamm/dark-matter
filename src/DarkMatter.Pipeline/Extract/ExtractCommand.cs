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
        var maxDepth = (int)Math.Min(o.Number("--max-depth", Limits.Default.MaxDepth, 0), 64);
        var maxBytes = o.Number("--max-bytes", Limits.Default.MaxBytes, 1);
        var maxFiles = o.Number("--max-files", Limits.Default.MaxFiles, 1);
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
            var assets = Directory.EnumerateFileSystemEntries(source).Order(StringComparer.Ordinal).Select(p => (p, Path.GetFileName(p))).ToList();
            var mod = ExtractAssets(assets, mid, Path.Join(extracted, mid), new Limits(maxDepth, maxBytes, maxFiles));
            mods[mid] = mod;
            Console.WriteLine($"{Text.Printable(mid)}: {mod.Files.Count} code file(s)"
                + (mod.Unextracted.Count > 0 ? $", {mod.Unextracted.Count} unextracted" : "")
                + (mod.Scripts.Count > 0 ? $", {mod.Scripts.Count} script(s)" : ""));
        }
        Text.WriteJson(manifest, new { root = extracted, mods });
        return 0;
    }

    static string FullFolder(string path) => Path.TrimEndingDirectorySeparator(Path.GetFullPath(path)) + Path.DirectorySeparatorChar;

    /// <summary>
    /// Extraction limits per mod: nesting depth, bytes written, files written. A mod over a limit
    /// counts as not extracted (Full access), so <c>scan</c> puts the limits in its scan key and stamp.
    /// The byte limit bounds the disk one mod can fill (extracted trees are kept); the counted bytes,
    /// the file count and the depth are what stop archive bombs.
    /// </summary>
    internal sealed record Limits(int MaxDepth, long MaxBytes, long MaxFiles) {
        public static readonly Limits Default = new(3, 4L << 30, 100_000);
    }

    /// <summary>A fresh, empty extraction folder for one mod (an existing one is deleted first).</summary>
    static ModTree FreshTree(string dest, Limits limits) {
        if (Directory.Exists(dest) || File.Exists(dest)) {
            var info = new DirectoryInfo(dest);
            if (info.LinkTarget != null || !info.Exists) throw new UsageException($"{dest} exists and is not a folder; remove it first");
            Directory.Delete(dest, recursive: true);
        }
        Directory.CreateDirectory(dest);
        return new ModTree(dest, limits.MaxBytes, limits.MaxFiles);
    }

    /// <summary>
    /// Whether an extraction error came from the file system (a full disk, a permission, a file in
    /// use) rather than from what the archive holds: such an error may not happen again. Errors the
    /// archive's contents cause are <see cref="ArchiveException"/>, <see cref="InvalidDataException"/>
    /// and the like; a truncated archive is <see cref="EndOfStreamException"/>.
    /// </summary>
    internal static bool IsEnvironmentError(Exception e) =>
        e is UnauthorizedAccessException || (e is IOException && e is not EndOfStreamException);

    /// <summary>
    /// Extracts one mod's downloaded assets (<paramref name="assets"/>: a file and the name it is
    /// extracted under) into <paramref name="dest"/>, and returns its manifest entry. If
    /// <paramref name="environmentErrors"/> is given, it gets the file-system errors
    /// (<see cref="IsEnvironmentError"/>) that made something count as not extracted.
    /// </summary>
    internal static ManifestMod ExtractAssets(IReadOnlyList<(string Path, string Name)> assets, string mid, string dest, Limits limits, List<string>? environmentErrors = null) {
        var tree = FreshTree(dest, limits);
        var unextracted = new List<string>();
        void Warn(string message) => Console.Error.WriteLine($"  {Text.Printable(mid)}: {message}");

        foreach (var (path, asset) in assets) {
            try {
                if (ExtractAsset(path, asset, tree, Warn) is { } problem) unextracted.Add(problem);
            } catch (Exception e) {
                // Whatever went wrong with a hostile file, the result is the same: not extracted.
                unextracted.Add(asset);
                Warn($"failed to extract {Text.Quote(asset)}: {e.Message}");
                Note(environmentErrors, e, asset);
            }
        }
        return Finish(tree, dest, unextracted, limits, Warn, environmentErrors);
    }

    static void Note(List<string>? environmentErrors, Exception e, string what) {
        if (environmentErrors != null && IsEnvironmentError(e)) environmentErrors.Add($"{Text.Printable(what)}: {e.Message}");
    }

    /// <summary>
    /// Copies a folder (a mod as it is installed, or a build output) into <paramref name="dest"/> with
    /// the same rules as an archive: every name is checked, links and other non-regular files are not
    /// copied and make the folder count as not extracted, and archives in it are expanded.
    /// </summary>
    internal static ManifestMod CopyFolder(string source, string mid, string dest, Limits limits, List<string>? environmentErrors = null) {
        var tree = FreshTree(dest, limits);
        var unextracted = new List<string>();
        void Warn(string message) => Console.Error.WriteLine($"  {Text.Printable(mid)}: {message}");
        var root = Path.GetFullPath(source);
        void Copy(string folder) {
            foreach (var entry in Directory.EnumerateFileSystemEntries(folder).Order(StringComparer.Ordinal)) {
                var rel = Path.GetRelativePath(root, entry);
                var info = new FileInfo(entry);
                if (info.LinkTarget != null) {
                    unextracted.Add(rel);
                    Warn($"{Text.Quote(rel)} is a link; not copied");
                    continue;
                }
                if (Directory.Exists(entry)) {
                    Copy(entry);
                    continue;
                }
                var why = EntryNames.Check(rel, directory: false, out var parts, out var renamed) ?? (info.Exists ? null : "not a regular file");
                if (why != null) {
                    unextracted.Add(rel);
                    Warn($"cannot copy {Text.Quote(rel)}: {why}");
                    continue;
                }
                tree.ShowRenames(renamed, Warn);
                try {
                    if (!tree.Claim(parts, directory: false)) {
                        unextracted.Add(rel);
                        Warn($"cannot copy {Text.Quote(rel)}: another file has the same name (ignoring case)");
                        continue;
                    }
                    using var input = new FileStream(entry, FileMode.Open, FileAccess.Read, FileShare.Read);
                    tree.Write(parts, input);
                } catch (Exception e) {
                    unextracted.Add(rel);
                    Warn($"cannot copy {Text.Quote(rel)}: {e.Message}");
                    Note(environmentErrors, e, rel);
                }
            }
        }
        Copy(root);
        return Finish(tree, dest, unextracted, limits, Warn, environmentErrors);
    }

    static ManifestMod Finish(ModTree tree, string dest, List<string> unextracted, Limits limits, Action<string> warn, List<string>? environmentErrors) {
        int maxDepth = limits.MaxDepth;
        try {
            unextracted.AddRange(ExpandNested(tree, maxDepth, warn, environmentErrors));
        } catch (Exception e) {
            unextracted.Add("(nested archives)");
            warn($"failed to expand nested archives: {e.Message}");
            Note(environmentErrors, e, "(nested archives)");
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
            // The asset's name is checked like an entry's (a download, or a local file, may be named anything).
            var why = EntryNames.Check(asset, directory: false, out var parts, out var renamed) ?? (parts.Length == 1 ? null : "not a single file name");
            if (why != null) {
                warn($"cannot copy {Text.Quote(asset)}: {why}");
                return asset;
            }
            tree.ShowRenames(renamed, warn);
            if (!tree.Claim(parts, directory: false)) {
                warn($"cannot copy {Text.Quote(asset)}: another file has the same name (ignoring case)");
                return asset;
            }
            using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            tree.Write(parts, input);
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
    static List<string> ExpandNested(ModTree tree, int maxDepth, Action<string> warn, List<string>? environmentErrors) {
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
                    Note(environmentErrors, e, rel);
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
