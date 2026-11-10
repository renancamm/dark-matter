// SPDX-License-Identifier: MIT
// Near miss (R3): the original is whatever member the caller passes, so the instance can be any object. Expected:
// Broad access, "Uses reflection the check cannot trace".
using System.Reflection;
using HarmonyLib;

internal static class ManualInstanceUntracedHooks {
    internal static void After(object __instance) => __instance.GetType().GetMethod("Rename")!.Invoke(__instance, ["name"]);
}

public static class ManualInstanceUntraced {
    public static void Start(MethodBase original) =>
        new Harmony("example.invalid").Patch(original, postfix: new HarmonyMethod(typeof(ManualInstanceUntracedHooks), "After"));
}
