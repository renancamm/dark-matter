// SPDX-License-Identifier: MIT
// Near miss (R3): the HarmonyMethod is given to Harmony.Patch as the transpiler, not as a prefix, postfix or
// finalizer: Harmony does not call it with the original's instance, so the handoff bounds nothing. Expected: Broad
// access (a transpiler the check cannot place, and reflection it cannot trace).
using HarmonyLib;

internal static class ManualInstanceTranspilerHooks {
    internal static void After(object __instance) => __instance.GetType().GetMethod("Rename")!.Invoke(__instance, ["name"]);
}

public static class ManualInstanceTranspiler {
    public static void Start() =>
        new Harmony("example.invalid").Patch(AccessTools.Method(typeof(KSA.Craft), "Update"), transpiler: new HarmonyMethod(typeof(ManualInstanceTranspilerHooks), "After"));
}
