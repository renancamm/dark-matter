// SPDX-License-Identifier: MIT
// Writes a copy of an assembly whose first method body starts with an undefined opcode (0xC0),
// to check that undecodable IL is reported instead of skipped.
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;

if (args.Length != 2) {
    Console.Error.WriteLine("usage: corrupt <input.dll> <output.dll>");
    return 2;
}
var bytes = File.ReadAllBytes(args[0]);
using (var pe = new PEReader(new MemoryStream(bytes))) {
    var md = pe.GetMetadataReader();
    foreach (var mh in md.MethodDefinitions) {
        int rva = md.GetMethodDefinition(mh).RelativeVirtualAddress;
        if (rva == 0) continue;
        int section = pe.PEHeaders.GetContainingSectionIndex(rva);
        if (section < 0) continue;
        var s = pe.PEHeaders.SectionHeaders[section];
        int header = rva - s.VirtualAddress + s.PointerToRawData;
        int il = (bytes[header] & 3) == 2 ? header + 1 : header + 4 * (bytes[header + 1] >> 4);  // tiny or fat header
        bytes[il] = 0xC0;
        Console.WriteLine($"corrupted method at RVA 0x{rva:X}, file offset 0x{il:X}");
        File.WriteAllBytes(args[1], bytes);
        return 0;
    }
}
Console.Error.WriteLine("no method body found");
return 1;
