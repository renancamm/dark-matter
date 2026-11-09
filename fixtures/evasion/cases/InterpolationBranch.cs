// SPDX-License-Identifier: MIT
// Probe case: the mod's folder is appended only on one branch; on the other the text begins with a
// rooted path. Expected: "Changes files outside the game" (found while fixing G1a review A12).
using System.IO;
using System.Runtime.CompilerServices;

public static class InterpolationBranch {
    static string Own => Path.GetDirectoryName(typeof(InterpolationBranch).Assembly.Location);

    public static void Save(bool inOwnFolder) {
        var h = new DefaultInterpolatedStringHandler(0, 1);
        if (inOwnFolder) h.AppendFormatted(Own);
        h.AppendLiteral("/tmp/dark-matter-fixture.txt");
        File.WriteAllText(h.ToStringAndClear(), "x");
    }
}
