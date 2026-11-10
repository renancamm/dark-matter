// SPDX-License-Identifier: MIT
// Near miss (R3): the patch method is named through a type that only inherits it. The handoff names a method that
// type does not declare, so it is not counted as one: the lookup reaches the base type's method like any other.
// Expected: Broad access, "Uses reflection the check cannot trace".
using HarmonyLib;

internal class ManualInstanceBaseHooks {
    internal static void After(object __instance) => __instance.GetType().GetMethod("Rename")!.Invoke(__instance, ["name"]);
}

internal class ManualInstanceDerivedHooks : ManualInstanceBaseHooks { }

public static class ManualInstanceBaseHook {
    public static void Start() =>
        new Harmony("example.invalid").Patch(AccessTools.Method(typeof(KSA.Craft), "Update"), postfix: new HarmonyMethod(typeof(ManualInstanceDerivedHooks), "After"));
}
