// SPDX-License-Identifier: MIT
using System.Buffers.Binary;
using System.Text.RegularExpressions;

namespace DarkMatter.Analysis;

/// <summary>
/// Recognizes manifest resources that carry code or an archive, from their leading bytes and
/// their names. The resource is never unpacked or loaded: a program, library or archive inside a
/// mod's assembly is code the check did not read, whatever the mod does with it later (load it
/// from memory, or write it next to its own DLL for the loader to pick up on the next launch).
/// </summary>
internal static partial class EmbeddedResources {
    // Costura.Fody stores bundled assemblies as "costura.<name>.dll.compressed" (deflate, which
    // has no magic number) or "costura.<name>.dll"; other bundlers use plain file names.
    [GeneratedRegex(@"^costura(32|64)?\.|\.(dll|exe|so|dylib)(\.(compressed|deflate|gz|zip|lz4|zst|br|bin))?$", RegexOptions.IgnoreCase)]
    private static partial Regex BinaryName();

    // (magic, offset, what). Leading bytes of executable and archive formats.
    static readonly (byte[] Magic, int Offset, string What)[] Magics = [
        ("MZ"u8.ToArray(), 0, "a Windows program or library"),
        ([0x7F, (byte)'E', (byte)'L', (byte)'F'], 0, "a Linux program or library (ELF)"),
        ([0xFE, 0xED, 0xFA, 0xCE], 0, "a macOS program or library (Mach-O)"),
        ([0xFE, 0xED, 0xFA, 0xCF], 0, "a macOS program or library (Mach-O)"),
        ([0xCE, 0xFA, 0xED, 0xFE], 0, "a macOS program or library (Mach-O)"),
        ([0xCF, 0xFA, 0xED, 0xFE], 0, "a macOS program or library (Mach-O)"),
        ([0xCA, 0xFE, 0xBA, 0xBE], 0, "a macOS universal binary (or Java class)"),
        ([0xBE, 0xBA, 0xFE, 0xCA], 0, "a macOS universal binary"),
        ([0xCA, 0xFE, 0xBA, 0xBF], 0, "a macOS universal binary"),
        ([0xBF, 0xBA, 0xFE, 0xCA], 0, "a macOS universal binary"),
        ("PK\u0003\u0004"u8.ToArray(), 0, "a zip archive"),
        ("PK\u0005\u0006"u8.ToArray(), 0, "a zip archive"),
        ("PK\u0007\u0008"u8.ToArray(), 0, "a zip archive"),
        ([0x1F, 0x8B], 0, "a gzip stream"),
        ([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], 0, "a 7z archive"),
        ("Rar!\u001A\u0007"u8.ToArray(), 0, "a RAR archive"),
        ([0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00], 0, "an xz stream"),
        ([0x28, 0xB5, 0x2F, 0xFD], 0, "a zstd stream"),
        ([0x04, 0x22, 0x4D, 0x18], 0, "an LZ4 stream"),
        ("MSCF"u8.ToArray(), 0, "a cabinet archive"),
        ("ustar"u8.ToArray(), 257, "a tar archive"),
    ];

    /// <summary>Whether a resource name looks like a bundled binary (Costura.Fody, "x.dll", "x.so.gz").</summary>
    public static bool NamedLikeBinary(string name) => BinaryName().IsMatch(name);

    /// <summary>
    /// What the resource's bytes are, or null if they look like none of the formats above. A
    /// Windows program or library is also found anywhere inside the resource (a .resources set or
    /// any other container that stores it uncompressed), checked by its PE header so that random
    /// data does not match. A .NET single-file bundle is an app host program, so its leading bytes
    /// already match. Compressed or encrypted payloads have no recognizable bytes (see
    /// docs/known-gaps.md).
    /// </summary>
    public static string? Kind(ReadOnlySpan<byte> data) {
        // ELF also opens with "\x7FELF"; bzip2 with "BZh" and a block size digit.
        if (data.Length >= 4 && data[0] == (byte)'B' && data[1] == (byte)'Z' && data[2] == (byte)'h' && data[3] is >= (byte)'1' and <= (byte)'9')
            return "a bzip2 stream";
        foreach (var (magic, offset, what) in Magics)
            if (data.Length >= offset + magic.Length && data.Slice(offset, magic.Length).SequenceEqual(magic)) return what;
        return PeAt(data) is int at ? $"a Windows program or library at offset {at}" : null;
    }

    // Offset of the first "MZ" whose e_lfanew field points at a "PE\0\0" signature, or null.
    static int? PeAt(ReadOnlySpan<byte> data) {
        for (int i = data.IndexOf("MZ"u8); i >= 0;) {
            if (i + 0x40 <= data.Length) {
                long pe = i + (long)BinaryPrimitives.ReadUInt32LittleEndian(data[(i + 0x3C)..]);
                if (pe + 4 <= data.Length && data.Slice((int)pe, 4).SequenceEqual("PE\0\0"u8)) return i;
            }
            int next = data[(i + 1)..].IndexOf("MZ"u8);
            i = next < 0 ? -1 : i + 1 + next;
        }
        return null;
    }
}
