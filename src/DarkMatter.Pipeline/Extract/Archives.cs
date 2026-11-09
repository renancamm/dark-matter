// SPDX-License-Identifier: MIT
using System.Formats.Tar;
using System.IO.Compression;
using System.Text;

namespace DarkMatter.Pipeline.Extract;

/// <summary>What a file is as an archive.</summary>
internal enum ArchiveKind { None, Zip, Tar, GzipTar, Unsupported }

/// <summary>
/// Recognizes archives and extracts zip, tar and gzip-compressed tar into a <see cref="ModTree"/>.
/// Archives are untrusted: entries are checked by <see cref="EntryNames"/> and claimed in the
/// tree before they are written (version-control, editor and agent-config names renamed first,
/// see <see cref="EntryNames"/>); links, devices and other non-regular entries are never
/// written. Every entry that is not written (apart from folders and archive metadata) is counted,
/// and the caller records an archive with such entries as not extracted: what a player's
/// extraction tool makes of them is not what the check looked at.
/// </summary>
internal static class Archives {
    // Leading bytes of archive and compression formats. Only zip, tar and gzip are extracted; the
    // others are recognized so that they count as not extracted instead of as ordinary content.
    static readonly (byte[] Magic, int Offset, ArchiveKind Kind, string What)[] Magics = [
        ("PK\u0003\u0004"u8.ToArray(), 0, ArchiveKind.Zip, "zip"),
        ("PK\u0005\u0006"u8.ToArray(), 0, ArchiveKind.Zip, "zip"),
        ("PK\u0007\u0008"u8.ToArray(), 0, ArchiveKind.Zip, "zip"),
        ([0x1F, 0x8B], 0, ArchiveKind.GzipTar, "gzip"),
        ("ustar"u8.ToArray(), 257, ArchiveKind.Tar, "tar"),
        ([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], 0, ArchiveKind.Unsupported, "7z"),
        ("Rar!\u001A\u0007"u8.ToArray(), 0, ArchiveKind.Unsupported, "RAR"),
        ([0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00], 0, ArchiveKind.Unsupported, "xz"),
        ([0x28, 0xB5, 0x2F, 0xFD], 0, ArchiveKind.Unsupported, "zstd"),
        ([0x04, 0x22, 0x4D, 0x18], 0, ArchiveKind.Unsupported, "LZ4"),
        ("MSCF"u8.ToArray(), 0, ArchiveKind.Unsupported, "cabinet"),
    ];

    static readonly (string Extension, ArchiveKind Kind, string What)[] Extensions = [
        (".zip", ArchiveKind.Zip, "zip"),
        (".tar.gz", ArchiveKind.GzipTar, "gzip"),
        (".tgz", ArchiveKind.GzipTar, "gzip"),
        (".gz", ArchiveKind.GzipTar, "gzip"),
        (".tar", ArchiveKind.Tar, "tar"),
        (".7z", ArchiveKind.Unsupported, "7z"),
        (".rar", ArchiveKind.Unsupported, "RAR"),
        (".xz", ArchiveKind.Unsupported, "xz"),
        (".txz", ArchiveKind.Unsupported, "xz"),
        (".bz2", ArchiveKind.Unsupported, "bzip2"),
        (".tbz2", ArchiveKind.Unsupported, "bzip2"),
        (".zst", ArchiveKind.Unsupported, "zstd"),
        (".lz4", ArchiveKind.Unsupported, "LZ4"),
        (".cab", ArchiveKind.Unsupported, "cabinet"),
    ];

    /// <summary>
    /// Whether <paramref name="path"/> is an archive, by its leading bytes first and its name
    /// second, so that a renamed archive is still found. An unreadable file is not an archive here;
    /// it fails when it is hashed or copied.
    /// </summary>
    public static (ArchiveKind Kind, string What) Detect(string path) {
        var head = new byte[262];
        int n;
        try {
            using var f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            n = f.ReadAtLeast(head, head.Length, throwOnEndOfStream: false);
        } catch (Exception e) when (e is IOException or UnauthorizedAccessException) {
            return (ArchiveKind.None, "");
        }
        var data = head.AsSpan(0, n);
        // bzip2: "BZh" and a block size digit.
        if (n >= 4 && data[0] == (byte)'B' && data[1] == (byte)'Z' && data[2] == (byte)'h' && data[3] is >= (byte)'1' and <= (byte)'9')
            return (ArchiveKind.Unsupported, "bzip2");
        foreach (var (magic, offset, kind, what) in Magics)
            if (n >= offset + magic.Length && data.Slice(offset, magic.Length).SequenceEqual(magic)) return (kind, what);
        foreach (var (ext, kind, what) in Extensions)
            if (path.EndsWith(ext, StringComparison.OrdinalIgnoreCase)) return (kind, what);
        return (ArchiveKind.None, "");
    }

    /// <summary>
    /// Extracts archive <paramref name="path"/> into the claimed folder <paramref name="into"/> of
    /// <paramref name="tree"/>. Returns how many entries were not written. Throws when the archive
    /// cannot be read or a limit is exceeded; files already written stay.
    /// </summary>
    public static int Extract(string path, ArchiveKind kind, ModTree tree, string[] into, Action<string> warn) => kind switch {
        ArchiveKind.Zip => ExtractZip(path, tree, into, warn),
        ArchiveKind.Tar or ArchiveKind.GzipTar => ExtractTar(path, kind == ArchiveKind.GzipTar, tree, into, warn),
        _ => throw new ArchiveException("unsupported archive format"),
    };

    // Names of entries without the UTF-8 flag are code page 437, as the zip format specifies and
    // as Python's zipfile and Windows' built-in extraction read them.
    public static readonly Encoding Cp437 = CodePage437();

    static Encoding CodePage437() {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        return Encoding.GetEncoding(437);
    }

    // Unix file types in the high 16 bits of a zip entry's external attributes.
    const uint TypeMask = 0xF000, TypeRegular = 0x8000, TypeDirectory = 0x4000;

    static int ExtractZip(string path, ModTree tree, string[] into, Action<string> warn) {
        using var file = File.OpenRead(path);
        // Names are read from the central directory; a tool that reads local headers sees the names
        // there, so an entry whose two names differ is refused.
        var mismatched = ZipHeaders.NameMismatches(file);
        file.Position = 0;
        using var zip = new ZipArchive(file, ZipArchiveMode.Read, leaveOpen: true, Cp437);
        if (mismatched.Count != zip.Entries.Count) throw new ArchiveException("zip central directory read two ways gives different entries");
        int skipped = 0;
        int index = -1;
        foreach (var e in zip.Entries) {
            if (mismatched[++index]) {
                warn($"skipped entry {Text.Quote(e.FullName)}: its local header names a different file");
                skipped++;
                continue;
            }
            var type = ((uint)e.ExternalAttributes >> 16) & TypeMask;
            // Many tools store permission bits without a file type, or no Unix attributes at all:
            // no type is a regular file. Any type other than regular or directory (link, device,
            // pipe) is refused: on Windows a link entry extracts as a file holding its data.
            bool directory = e.FullName.EndsWith('/') || (type == TypeDirectory && e.Length == 0);
            if (type != 0 && type != TypeRegular && !directory) {
                warn($"skipped non-regular entry {Text.Quote(e.FullName)}");
                skipped++;
                continue;
            }
            if (!Accept(e.FullName, directory, tree, into, warn, out var parts)) {
                skipped++;
                continue;
            }
            if (directory) continue;
            using var data = e.Open();
            tree.Write(parts, data, e.Length, e.Crc32);
        }
        return skipped;
    }

    static int ExtractTar(string path, bool gzip, ModTree tree, string[] into, Action<string> warn) {
        using var file = File.OpenRead(path);
        using var unpacked = gzip ? new GZipStream(file, CompressionMode.Decompress, leaveOpen: true) : null;
        // The data of skipped entries is decompressed too: bound the whole stream, not only what is
        // written, so a huge declared link or device entry cannot keep the extraction busy.
        using var limited = new LimitedStream(unpacked ?? (Stream)file, tree.MaxBytes > long.MaxValue / 2 ? long.MaxValue : 2 * tree.MaxBytes);
        using var reader = new TarReader(limited, leaveOpen: true);
        int skipped = 0;
        while (reader.GetNextEntry() is { } e) {
            switch (e.EntryType) {
                case TarEntryType.GlobalExtendedAttributes:
                    continue;  // pax metadata for the entries that follow, not a file
                case TarEntryType.Directory:
                    if (!Accept(e.Name, true, tree, into, warn, out _)) skipped++;
                    continue;
                case TarEntryType.RegularFile or TarEntryType.V7RegularFile or TarEntryType.ContiguousFile:
                    break;
                default:
                    warn($"skipped non-regular entry {Text.Quote(e.Name)} ({e.EntryType})");
                    skipped++;
                    continue;
            }
            if (!Accept(e.Name, false, tree, into, warn, out var parts)) {
                skipped++;
                continue;
            }
            tree.Write(parts, e.DataStream ?? Stream.Null, e.Length);
        }
        return skipped;
    }

    /// <summary>
    /// The data of a zip entry, in memory: at most <paramref name="maxBytes"/>, exactly its declared
    /// size, matching its CRC-32 (for build-allowlist, which hashes trusted files).
    /// </summary>
    public static byte[] ReadEntry(ZipArchiveEntry e, long maxBytes) {
        if (e.Length > maxBytes || e.Length > Array.MaxLength) throw new ArchiveException($"{Text.Quote(e.FullName)} is larger than the limit");
        var data = new byte[e.Length];
        using var s = e.Open();
        s.ReadExactly(data);
        if (s.ReadByte() != -1) throw new ArchiveException($"{Text.Quote(e.FullName)} is longer than its declared size");
        var crc = new Crc32();
        crc.Append(data);
        if (crc.Value != e.Crc32) throw new ArchiveException($"{Text.Quote(e.FullName)} fails its CRC check");
        return data;
    }

    /// <summary>Checks an entry name and claims its path; false (with a warning) if it is refused.</summary>
    static bool Accept(string name, bool directory, ModTree tree, string[] into, Action<string> warn, out string[] parts) {
        if (EntryNames.Check(name, directory, out var rel, out var renamed) is { } why) {
            warn($"skipped unsafe entry {Text.Quote(name)}: {why}");
            parts = [];
            return false;
        }
        tree.ShowRenames(renamed, warn);
        parts = [.. into, .. rel];
        if (rel.Length > 0 && !tree.Claim(parts, directory)) {
            warn($"skipped entry {Text.Quote(name)}: another entry or file has the same path (ignoring case)");
            return false;
        }
        return true;
    }

    /// <summary>A read-only stream that fails once more than a set number of bytes were read from it.</summary>
    sealed class LimitedStream(Stream inner, long limit) : Stream {
        long read;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => read; set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer) {
            int n = inner.Read(buffer);
            read += n;
            if (read > limit) throw new ArchiveException("extracted size limit exceeded");
            return n;
        }

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    }
}
