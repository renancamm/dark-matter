// SPDX-License-Identifier: MIT
// A path that begins with the mod's own folder, followed by a part the check cannot trace (a public
// method's parameter: any caller can pass "../.." or a rooted path), joined three ways.
// Expected: Limited access, "Changes files outside the game" only, for each method.
using System.IO;

public static class OwnFolderUntracedPart {
    static string Own => Path.GetDirectoryName(typeof(OwnFolderUntracedPart).Assembly.Location)!;

    public static void Combined(string name) => File.WriteAllText(Path.Combine(Own, name), "x");

    public static void Concatenated(string name) => File.WriteAllText(Own + "/" + name, "x");

    public static void Interpolated(string name) => File.WriteAllText($"{Own}/{name}.txt", "x");
}
