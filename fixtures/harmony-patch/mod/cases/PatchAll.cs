// SPDX-License-Identifier: MIT
// [HarmonyPatchAll] patches every method of the named type, so no method name is needed: here
// every member of Process, Start included. Expected: Broad access ("Starts other programs").
using HarmonyLib;

[HarmonyPatch(typeof(System.Diagnostics.Process))]
[HarmonyPatchAll]
public static class PatchAllPatch {
    public static void Prefix() { }
}
