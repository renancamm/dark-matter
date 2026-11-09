// SPDX-License-Identifier: MIT
// Probe case: Harmony.Patch called by reflection (MethodInfo.Invoke), so the check's test that the
// patched original is traced (at a direct call) does not run. The original is a method the check
// cannot trace. Expected: Broad access, "Uses reflection the check cannot trace" (G1a review A2).
using System;
using System.Reflection;
using HarmonyLib;

public static class Src { public static Action Hook; }

public static class PatchByReflection {
    static void Prefix(ref string path) { path = "elsewhere"; }

    public static void Go() {
        var harmony = new Harmony("example.invalid.patchinvoke");
        var prefix = new HarmonyMethod(typeof(PatchByReflection).GetMethod(nameof(Prefix), BindingFlags.NonPublic | BindingFlags.Static));
        typeof(Harmony).GetMethod("Patch").Invoke(harmony, new object[] { Src.Hook.Method, prefix, null, null, null });
    }
}
