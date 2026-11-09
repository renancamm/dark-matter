// SPDX-License-Identifier: MIT
// Probe case: the interpolation handler is cleared and appended to through a by-reference local.
// Expected: "Changes files outside the game" (G1a review A16).
using System;
using System.IO;
using System.Runtime.CompilerServices;

public static class InterpolationRefLocal {
    static string Own => Path.GetDirectoryName(typeof(InterpolationRefLocal).Assembly.Location);

    public static void Save(bool first) {
        var a = new DefaultInterpolatedStringHandler(0, 1);
        var b = new DefaultInterpolatedStringHandler(0, 1);
        a.AppendFormatted(Own);
        ref var r = ref (first ? ref a : ref b);
        r.ToStringAndClear();
        r.AppendFormatted(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
        a.AppendLiteral("/dark-matter-fixture.txt");
        File.WriteAllText(a.ToStringAndClear(), "x");
    }
}
