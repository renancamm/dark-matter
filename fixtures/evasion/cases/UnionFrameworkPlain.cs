// SPDX-License-Identifier: MIT
// C3 (policy 34): explicit-layout unions over framework value types the check now lays out from the shared
// framework's own metadata: an enum (DayOfWeek over int), a struct of plain fields (DateTimeOffset over
// long and int, Rune over int), and a struct nesting them. All plain data: Limited access, nothing labelled
// (before: "Reads or writes memory directly", the framework types' contents were unknown).
using System;
using System.Runtime.InteropServices;
using System.Text;

[StructLayout(LayoutKind.Explicit)]
public struct DayUnion {
    [FieldOffset(0)] public DayOfWeek Day;
    [FieldOffset(0)] public int Raw;
}

[StructLayout(LayoutKind.Explicit)]
public struct DateUnion {
    [FieldOffset(0)] public DateTimeOffset When;
    [FieldOffset(0)] public long Ticks;
    [FieldOffset(8)] public short Offset;
}

[StructLayout(LayoutKind.Explicit)]
public struct RuneUnion {
    [FieldOffset(0)] public Rune Rune;
    [FieldOffset(0)] public int Value;
    [FieldOffset(4)] public ConsoleColor Colour;
    [FieldOffset(4)] public int ColourValue;
}

public static class UnionFrameworkPlain {
    public static int Day(DayUnion u) => u.Raw;
    public static long Date(DateUnion u) => u.Ticks;
    public static int Rune(RuneUnion u) => u.Value + u.ColourValue;
}
