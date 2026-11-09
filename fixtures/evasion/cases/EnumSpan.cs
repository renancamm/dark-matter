// SPDX-License-Identifier: MIT
// C1 (policy 34): spans of enum elements over stackalloc buffers. The compiler sizes an enum's stackalloc
// from its underlying type (a constant byte count, or count * 4 with mul.ovf.un), which the check now reads
// from the enum's one instance field. Limited access, nothing labelled (before: "Reads or writes memory
// directly", the enum had no size in the check's table).
using System;

public enum Hue { Red, Green, Blue }
public enum Wide : long { A, B }
public enum Tiny : byte { X, Y }

public static class EnumSpan {
    public static int Constant() { Span<Hue> s = stackalloc Hue[8]; s[1] = Hue.Blue; return (int)s[1]; }
    public static int Variable(int n) { Span<Hue> s = stackalloc Hue[n]; s[0] = Hue.Green; return (int)s[0]; }
    public static long Long(int n) { Span<Wide> s = stackalloc Wide[n]; return (long)s[0]; }
    public static int Byte(int n) { Span<Tiny> s = stackalloc Tiny[n]; return (int)s[0]; }
    public static int Framework(int n) { Span<DayOfWeek> s = stackalloc DayOfWeek[n]; s[0] = DayOfWeek.Monday; return (int)s[0]; }
}
