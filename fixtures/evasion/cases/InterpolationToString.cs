// SPDX-License-Identifier: MIT
// Probe case: a value of the mod's own type formatted after the mod's folder; its ToString leaves the
// folder (".."). Expected: "Changes files outside the game" (G1a review A14).
using System.IO;

public struct UpFolders {
    public override string ToString() => "/../../..";
}

public static class InterpolationToString {
    static string Own => Path.GetDirectoryName(typeof(InterpolationToString).Assembly.Location);

    public static void Save() => File.WriteAllText($"{Own}{new UpFolders()}/dark-matter-fixture.txt", "x");
}
