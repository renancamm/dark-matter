// SPDX-License-Identifier: MIT
// Probe case: an interpolation handler with a format provider whose custom formatter replaces every
// value it formats, here the mod's folder. Expected: "Changes files outside the game" (G1a review A13).
using System;
using System.IO;
using System.Runtime.CompilerServices;

sealed class ReplacingFormatter : IFormatProvider, ICustomFormatter {
    public object GetFormat(Type t) => t == typeof(ICustomFormatter) ? this : null;
    public string Format(string format, object arg, IFormatProvider provider) => "/tmp";
}

public static class InterpolationProvider {
    static string Own => Path.GetDirectoryName(typeof(InterpolationProvider).Assembly.Location);

    public static void Save() {
        var h = new DefaultInterpolatedStringHandler(1, 1, new ReplacingFormatter());
        h.AppendFormatted(Own);
        h.AppendLiteral("/dark-matter-fixture.txt");
        File.WriteAllText(h.ToStringAndClear(), "x");
    }
}
