// SPDX-License-Identifier: MIT
// Probe case: the interpolation handler is passed by reference to a method that clears it and
// appends the user's folder. Expected: "Changes files outside the game" (G1a review A16).
using System;
using System.IO;
using System.Runtime.CompilerServices;

public static class InterpolationByRef {
    static string Own => Path.GetDirectoryName(typeof(InterpolationByRef).Assembly.Location);

    static void Redirect(ref DefaultInterpolatedStringHandler h) {
        h.ToStringAndClear();
        h.AppendFormatted(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
    }

    public static void Save() {
        var h = new DefaultInterpolatedStringHandler(0, 1);
        h.AppendFormatted(Own);
        Redirect(ref h);
        h.AppendLiteral("/dark-matter-fixture.txt");
        File.WriteAllText(h.ToStringAndClear(), "x");
    }
}
