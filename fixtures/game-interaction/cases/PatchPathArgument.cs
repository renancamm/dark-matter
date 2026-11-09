// SPDX-License-Identifier: MIT
// Probe case: a Harmony prefix writes to its string parameter. Harmony calls it with the patched game
// method's argument; the mod also calls it once with a path in its own folder. Expected: "Changes
// files outside the game" next to "Changes files in its own or the game's folders" (G1a review A11).
using System.IO;
using HarmonyLib;

[HarmonyPatch(typeof(KSA.UiText), "Draw")]
internal static class DrawLog {
    internal static void Prefix(string text) => File.WriteAllText(text, "x");
}

public static class DrawLogSetup {
    static string Own => Path.GetDirectoryName(typeof(DrawLogSetup).Assembly.Location);

    public static void Start() => DrawLog.Prefix(Path.Combine(Own, "draw.log"));
}
