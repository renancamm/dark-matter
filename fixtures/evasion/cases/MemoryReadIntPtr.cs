// SPDX-License-Identifier: MIT
// H8 negative: Marshal.ReadInt32(IntPtr) reads memory at an address the mod chooses. Full access,
// "Reads or writes memory directly", next to the no-memory Marshal members that are safe since H8.
using System;
using System.Runtime.InteropServices;

public static class MemoryReadIntPtr {
    public static int Peek(IntPtr p) => Marshal.ReadInt32(p);
}
