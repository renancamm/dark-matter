// SPDX-License-Identifier: MIT
using System.Buffers.Binary;

namespace DarkMatter.Pipeline.Extract;

/// <summary>
/// Compares the name each zip entry has in the central directory (what ZipArchive, and so this
/// extraction, uses) with the name in its local header (what a tool that reads the archive from the
/// front uses). An archive whose two names differ unpacks to different files depending on the tool.
/// </summary>
internal static class ZipHeaders {
    const uint EndOfCentralDirectory = 0x06054b50, Zip64End = 0x06064b50, Zip64Locator = 0x07064b50;
    const uint CentralHeader = 0x02014b50, LocalHeader = 0x04034b50;

    /// <summary>
    /// For each central-directory entry, in order, whether its local header names it differently
    /// (or cannot be read). Throws <see cref="ArchiveException"/> if the central directory itself
    /// cannot be read.
    /// </summary>
    public static List<bool> NameMismatches(Stream zip) {
        long length = zip.Length;
        // The end-of-central-directory record: 22 bytes and a comment of up to 65535 bytes.
        int tail = (int)Math.Min(length, 22 + 65535);
        var end = Read(zip, length - tail, tail);
        int at = -1;
        for (int i = tail - 22; i >= 0; i--)
            if (BinaryPrimitives.ReadUInt32LittleEndian(end.AsSpan(i)) == EndOfCentralDirectory) { at = i; break; }
        if (at < 0) throw new ArchiveException("zip end of central directory not found");
        long entries = BinaryPrimitives.ReadUInt16LittleEndian(end.AsSpan(at + 10));
        long size = BinaryPrimitives.ReadUInt32LittleEndian(end.AsSpan(at + 12));
        long offset = BinaryPrimitives.ReadUInt32LittleEndian(end.AsSpan(at + 16));
        if (entries == 0xFFFF || size == 0xFFFFFFFF || offset == 0xFFFFFFFF) {
            // Zip64: the locator just before the record points at the zip64 end record.
            long endAt = length - tail + at;
            if (endAt < 20) throw new ArchiveException("zip64 locator missing");
            var locator = Read(zip, endAt - 20, 20);
            if (BinaryPrimitives.ReadUInt32LittleEndian(locator) != Zip64Locator) throw new ArchiveException("zip64 locator missing");
            var record = Read(zip, (long)BinaryPrimitives.ReadUInt64LittleEndian(locator.AsSpan(8)), 56);
            if (BinaryPrimitives.ReadUInt32LittleEndian(record) != Zip64End) throw new ArchiveException("zip64 end of central directory missing");
            entries = (long)BinaryPrimitives.ReadUInt64LittleEndian(record.AsSpan(32));
            size = (long)BinaryPrimitives.ReadUInt64LittleEndian(record.AsSpan(40));
            offset = (long)BinaryPrimitives.ReadUInt64LittleEndian(record.AsSpan(48));
        }
        if (offset < 0 || size < 0 || offset + size > length || size > int.MaxValue) throw new ArchiveException("zip central directory out of range");
        var directory = Read(zip, offset, (int)size);
        var result = new List<bool>();
        int pos = 0;
        for (long n = 0; n < entries; n++) {
            if (pos + 46 > directory.Length || BinaryPrimitives.ReadUInt32LittleEndian(directory.AsSpan(pos)) != CentralHeader)
                throw new ArchiveException("zip central directory entry malformed");
            int nameLength = BinaryPrimitives.ReadUInt16LittleEndian(directory.AsSpan(pos + 28));
            int extraLength = BinaryPrimitives.ReadUInt16LittleEndian(directory.AsSpan(pos + 30));
            int commentLength = BinaryPrimitives.ReadUInt16LittleEndian(directory.AsSpan(pos + 32));
            if (pos + 46 + nameLength + extraLength + commentLength > directory.Length) throw new ArchiveException("zip central directory entry malformed");
            var name = directory.AsSpan(pos + 46, nameLength);
            long local = BinaryPrimitives.ReadUInt32LittleEndian(directory.AsSpan(pos + 42));
            if (local == 0xFFFFFFFF) local = Zip64Offset(directory.AsSpan(pos), directory.AsSpan(pos + 46 + nameLength, extraLength));
            result.Add(!LocalNameIs(zip, local, name));
            pos += 46 + nameLength + extraLength + commentLength;
        }
        return result;
    }

    // The local header offset from an entry's zip64 extra field (id 1), whose values are present
    // only for the fields that are 0xFFFFFFFF in the entry: uncompressed size, compressed size, offset.
    static long Zip64Offset(ReadOnlySpan<byte> entry, ReadOnlySpan<byte> extra) {
        while (extra.Length >= 4) {
            int id = BinaryPrimitives.ReadUInt16LittleEndian(extra), n = BinaryPrimitives.ReadUInt16LittleEndian(extra[2..]);
            if (n > extra.Length - 4) break;
            if (id == 1) {
                var values = extra.Slice(4, n);
                int skip = (BinaryPrimitives.ReadUInt32LittleEndian(entry[24..]) == 0xFFFFFFFF ? 8 : 0) + (BinaryPrimitives.ReadUInt32LittleEndian(entry[20..]) == 0xFFFFFFFF ? 8 : 0);
                return values.Length >= skip + 8 ? (long)BinaryPrimitives.ReadUInt64LittleEndian(values[skip..]) : -1;
            }
            extra = extra[(4 + n)..];
        }
        return -1;  // not found: the local header cannot be read, which counts as a mismatch
    }

    static bool LocalNameIs(Stream zip, long at, ReadOnlySpan<byte> name) {
        if (at < 0 || at + 30 > zip.Length) return false;
        var header = Read(zip, at, 30);
        if (BinaryPrimitives.ReadUInt32LittleEndian(header) != LocalHeader) return false;
        int nameLength = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(26));
        if (nameLength != name.Length || at + 30 + nameLength > zip.Length) return false;
        return Read(zip, at + 30, nameLength).AsSpan().SequenceEqual(name);
    }

    static byte[] Read(Stream s, long at, int count) {
        if (at < 0 || count < 0 || at + count > s.Length) throw new ArchiveException("zip structure out of range");
        var data = new byte[count];
        s.Position = at;
        s.ReadExactly(data);
        return data;
    }
}
