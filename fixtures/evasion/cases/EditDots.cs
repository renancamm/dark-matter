// SPDX-License-Identifier: MIT
// Probe case: string edits that make ".." out of text without it (a replacement, a cut, a name
// without its extension). Expected: "Changes files outside the game" (found while fixing G1a review A15).
using System.IO;

public static class EditDots {
    static string Own => Path.GetDirectoryName(typeof(EditDots).Assembly.Location);

    public static void Replaced() => File.WriteAllText((Own + "/x./x./a.txt").Replace("x", "."), "x");

    public static void Cut() => File.WriteAllText(Path.Combine(Own, "..b".Substring(0, 2), "b.txt"), "x");

    public static void NameOnly() => File.WriteAllText(Path.Combine(Own, Path.GetFileNameWithoutExtension("...c"), "c.txt"), "x");
}
