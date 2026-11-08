// SPDX-License-Identifier: MIT
// A prefix on Process.Start, which can change what is started. Expected: Full access.
using System.Diagnostics;
using HarmonyLib;

public static class ProcessTargetPatch {
    [HarmonyPatch(typeof(Process), nameof(Process.Start), typeof(string))]
    [HarmonyPrefix]
    public static void Redirect(ref string fileName) => fileName = "calc.exe";
}
