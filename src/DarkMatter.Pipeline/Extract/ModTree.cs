// SPDX-License-Identifier: MIT
namespace DarkMatter.Pipeline.Extract;

/// <summary>An archive that cannot be extracted faithfully: unreadable, inconsistent or over a limit.</summary>
internal sealed class ArchiveException(string message) : Exception(message);

/// <summary>
/// One mod's extraction folder. Everything in it is written through this class, into a folder it
/// created empty, so it never contains a link or a file it did not write. Each path is claimed
/// before it is written: a path that is already used, ignoring case and Unicode normalization, or
/// whose parent is a file, is refused. Bytes and files written count against the mod's limits,
/// shared by all its archives, nested ones included.
/// </summary>
internal sealed class ModTree {
    readonly string fullRoot;
    readonly Dictionary<string, bool> claimed = new(StringComparer.Ordinal);  // collision key -> is a directory
    readonly HashSet<string> renamesShown = new(StringComparer.Ordinal);
    long bytesLeft;
    long filesLeft;

    public ModTree(string root, long maxBytes, long maxFiles) {
        Root = root;
        fullRoot = Path.GetFullPath(root);
        MaxBytes = maxBytes;
        bytesLeft = maxBytes;
        filesLeft = maxFiles;
    }

    /// <summary>The size limit for everything extracted for the mod.</summary>
    public long MaxBytes { get; }

    /// <summary>The mod's folder, as the manifest names it.</summary>
    public string Root { get; }

    /// <summary>The path of <paramref name="parts"/> (components relative to the mod's folder).</summary>
    public string PathOf(IEnumerable<string> parts) => Path.Join([Root, .. parts]);

    /// <summary>Components of <paramref name="path"/>, a path inside the mod's folder.</summary>
    public string[] PartsOf(string path) => Path.GetRelativePath(Root, path).Split(Path.DirectorySeparatorChar);

    /// <summary>
    /// Claims <paramref name="parts"/> for a new file, or with <paramref name="directory"/> a
    /// folder. With <paramref name="fresh"/> a folder must not exist yet; otherwise claiming an
    /// existing folder again is allowed (two entries in the same folder).
    /// </summary>
    public bool Claim(IReadOnlyList<string> parts, bool directory, bool fresh = false) {
        var keys = new string[parts.Count];
        for (int i = 0; i < parts.Count; i++) keys[i] = (i == 0 ? "" : keys[i - 1] + "/") + EntryNames.Key(parts[i]);
        for (int i = 0; i < keys.Length - 1; i++)
            if (claimed.TryGetValue(keys[i], out var isDir) && !isDir) return false;
        if (claimed.TryGetValue(keys[^1], out var lastIsDir) && (fresh || !directory || !lastIsDir)) return false;
        for (int i = 0; i < keys.Length - 1; i++) claimed[keys[i]] = true;
        claimed[keys[^1]] = directory;
        return true;
    }

    /// <summary>
    /// Warns that entries named <paramref name="renamed"/> (<see cref="EntryNames.Renamed"/>) are
    /// written under another name, once per name for the mod.
    /// </summary>
    public void ShowRenames(IEnumerable<string> renamed, Action<string> warn) {
        foreach (var r in renamed)
            if (renamesShown.Add(EntryNames.Key(r)))
                warn($"wrote {Text.Quote(r)} as {Text.Quote(EntryNames.RenamePrefix + r)} (here and wherever else the name occurs) so that "
                    + "version-control tools, editors and coding agents run in the extracted folder do not act on it");
    }

    /// <summary>
    /// Writes <paramref name="source"/> to the claimed file <paramref name="parts"/>. The size
    /// limit counts bytes actually written, never a size the archive declares. With
    /// <paramref name="declared"/>, the data must be exactly that long; with
    /// <paramref name="crc"/>, it must match that CRC-32. A file that fails is removed.
    /// </summary>
    public void Write(IReadOnlyList<string> parts, Stream source, long declared = -1, uint? crc = null) {
        if (bytesLeft < 0) throw new ArchiveException("extracted size limit exceeded");
        if (--filesLeft < 0) throw new ArchiveException("extracted file count limit exceeded");
        var path = PathOf(parts);
        var full = Path.GetFullPath(path);
        if (!full.StartsWith(fullRoot + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            throw new ArchiveException($"entry resolves outside the extraction folder: {Text.Quote(string.Join('/', parts))}");
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        var check = crc != null ? new Crc32() : null;
        long total = 0;
        // CreateNew: never replaces a file and never follows a link (O_CREAT | O_EXCL).
        var output = new FileStream(full, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        try {
            using (output) {
                var buffer = new byte[1 << 16];
                int n;
                while ((n = source.Read(buffer)) > 0) {
                    total += n;
                    if (declared >= 0 && total > declared) throw new ArchiveException("entry is longer than its declared size");
                    bytesLeft -= n;
                    if (bytesLeft < 0) throw new ArchiveException("extracted size limit exceeded");
                    check?.Append(buffer.AsSpan(0, n));
                    output.Write(buffer, 0, n);
                }
            }
            if (declared >= 0 && total != declared) throw new ArchiveException("entry is shorter than its declared size");
            if (check != null && check.Value != crc) throw new ArchiveException("entry fails its CRC check");
        } catch {
            // A partial or corrupt file is not what the archive holds: leave nothing behind.
            File.Delete(full);
            throw;
        }
    }
}
