// SPDX-License-Identifier: MIT
namespace DarkMatter.Pipeline.Extract;

/// <summary>CRC-32 (IEEE 802.3, as zip uses it). System.IO.Hashing is a package, not part of the runtime.</summary>
internal sealed class Crc32 {
    static readonly uint[] Table = MakeTable();
    uint state = 0xFFFFFFFF;

    public uint Value => ~state;

    public void Append(ReadOnlySpan<byte> data) {
        var s = state;
        foreach (var b in data) s = Table[(s ^ b) & 0xFF] ^ (s >> 8);
        state = s;
    }

    static uint[] MakeTable() {
        var t = new uint[256];
        for (uint i = 0; i < 256; i++) {
            var c = i;
            for (int k = 0; k < 8; k++) c = (c & 1) != 0 ? 0xEDB88320 ^ (c >> 1) : c >> 1;
            t[i] = c;
        }
        return t;
    }
}
