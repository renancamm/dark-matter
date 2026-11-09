// SPDX-License-Identifier: MIT
// Probe (H7b): a Harmony patch named through the mod's own type on a method only its game base type defines
// (AccessTools.Method searches the base types), whose prefix changes the file the game method starts.
// Expected: Broad access, "Starts other programs" (before: Limited access, "Changes how the game works").
using HarmonyLib;

internal class InheritedPatchType : KSA.StartsBase { }

[HarmonyPatch(typeof(InheritedPatchType), "InheritedRun")]
public static class InheritedPatchPrefix {
    public static void Prefix(ref string file) => file = "example.invalid";
}
