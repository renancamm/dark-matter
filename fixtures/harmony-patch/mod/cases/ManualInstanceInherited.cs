// SPDX-License-Identifier: MIT
// Near miss (R3): the original is looked up on a derived type that does not declare it, so Harmony patches the base
// type's method, which runs on instances of other types too. Expected: Broad access, "Uses reflection the check
// cannot trace".
using HarmonyLib;

internal static class ManualInstanceInheritedHooks {
    internal static void After(object __instance) => __instance.GetType().GetMethod("Rename")!.Invoke(__instance, ["name"]);
}

public static class ManualInstanceInherited {
    public static void Start() =>
        new Harmony("example.invalid").Patch(AccessTools.Method(typeof(KSA.Rover), "Update"), postfix: new HarmonyMethod(typeof(ManualInstanceInheritedHooks), "After"));
}
