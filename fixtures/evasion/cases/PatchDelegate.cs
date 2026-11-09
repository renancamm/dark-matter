// SPDX-License-Identifier: MIT
// Probe case: Harmony.Patch taken as a delegate, so the check's test that the patched original is
// traced (at a direct call) does not run. The original is a method the check cannot trace.
// Expected: Full access, "Uses reflection the check cannot trace" (G1a review A2).
using System;
using System.Reflection;
using HarmonyLib;

public static class Src { public static Action Hook; }

public static class PatchThroughDelegate {
    static void Prefix(ref string path) { path = "elsewhere"; }

    public static void Go() {
        var harmony = new Harmony("example.invalid.patchdelegate");
        Func<MethodBase, HarmonyMethod, HarmonyMethod, HarmonyMethod, HarmonyMethod, MethodInfo> patch = harmony.Patch;
        patch(Src.Hook.Method, new HarmonyMethod(typeof(PatchThroughDelegate).GetMethod(nameof(Prefix), BindingFlags.NonPublic | BindingFlags.Static)), null, null, null);
    }
}
