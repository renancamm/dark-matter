// SPDX-License-Identifier: MIT
// Probe case: an interpolation handler reused after ToStringAndClear, which empties it. The second
// text begins with a rooted path, not after the mod's folder. Expected: "Changes files outside the
// game" (G1a review A12).
using System.IO;
using System.Runtime.CompilerServices;

public static class InterpolationCleared {
    static string Own => Path.GetDirectoryName(typeof(InterpolationCleared).Assembly.Location);

    public static void Save() {
        var h = new DefaultInterpolatedStringHandler(0, 1);
        h.AppendFormatted(Own);
        h.ToStringAndClear();
        h.AppendLiteral("/tmp/dark-matter-fixture.txt");
        File.WriteAllText(h.ToStringAndClear(), "x");
    }
}
