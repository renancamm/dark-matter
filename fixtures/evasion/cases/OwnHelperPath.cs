// SPDX-License-Identifier: MIT
// Control: a path parameter of an internal helper that only the mod calls, with a path in its own
// folder. Nothing outside the mod can call it. Expected: Limited access, "Changes files in its own or
// the game's folders" only. (A Harmony patch method, game-interaction/PatchPathArgument, is untraced.)
using System.IO;

internal static class SettingsFile {
    internal static void Save(string path) => File.WriteAllText(path, "x");
}

public static class OwnHelperPath {
    static string Own => Path.GetDirectoryName(typeof(OwnHelperPath).Assembly.Location);

    public static void Start() => SettingsFile.Save(Path.Combine(Own, "settings.txt"));
}
