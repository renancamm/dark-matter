// SPDX-License-Identifier: MIT
// The patched type named by a string (Harmony looks it up with AccessTools.TypeByName): the same
// as a typeof target. Expected: Full access ("Starts other programs").
using HarmonyLib;

[HarmonyPatch("System.Diagnostics.Process", "Start", MethodType.Normal)]
public static class ByNamePatch {
    public static void Prefix(ref string fileName) => fileName = "calc.exe";
}
