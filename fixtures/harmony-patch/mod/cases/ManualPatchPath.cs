// SPDX-License-Identifier: MIT
// Negative (D7 review, a gap before policy 35): an internal method handed to Harmony by name (new HarmonyMethod(type,
// name)) is a patch method whatever it is called: Harmony calls it with the patched method's arguments, not only with
// what the mod's own call passes (a path in its own folder, as evasion/OwnHelperPath). Expected: Limited access, with
// "Changes files outside the game" next to the own-folder write (before: the own-folder label only).
using System.IO;
using HarmonyLib;

internal static class ManualPatchPathHooks {
    internal static void SaveHook(string path) => File.WriteAllText(path, "x");
}

public static class ManualPatchPath {
    static string Own => Path.GetDirectoryName(typeof(ManualPatchPath).Assembly.Location)!;

    public static void Start() {
        ManualPatchPathHooks.SaveHook(Path.Combine(Own, "settings.txt"));
        new Harmony("example.invalid").Patch(AccessTools.Method(typeof(KSA.GameSaves), "MakeSave"), new HarmonyMethod(typeof(ManualPatchPathHooks), "SaveHook"));
    }
}
