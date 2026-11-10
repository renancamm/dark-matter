// SPDX-License-Identifier: MIT
// Near miss (R10): the original's name has two overloads whose parameter "item" is of two types, so the check
// cannot tell which one Harmony passes. Expected: Broad access, "Uses reflection the check cannot trace".
using HarmonyLib;

internal static class ManualParameterOverloadsHooks {
    internal static void After(object item) => item.GetType().GetMethod("Rename")!.Invoke(item, ["name"]);
}

public static class ManualParameterOverloads {
    public static void Start() =>
        new Harmony("example.invalid").Patch(AccessTools.Method(typeof(KSA.Dock), "Swap"), postfix: new HarmonyMethod(typeof(ManualParameterOverloadsHooks), "After"));
}
