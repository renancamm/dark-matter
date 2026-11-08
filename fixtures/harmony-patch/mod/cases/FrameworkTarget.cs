// SPDX-License-Identifier: MIT
// A prefix on System.IO.File.Delete: it receives every path the game and other mods delete, and
// can change it. Expected: Known access, "Changes files outside the game" (path not traceable).
using HarmonyLib;

[HarmonyPatch(typeof(System.IO.File), "Delete")]
public static class FrameworkTargetPatch {
    public static void Prefix(ref string path) => path = path + ".bak";
}
