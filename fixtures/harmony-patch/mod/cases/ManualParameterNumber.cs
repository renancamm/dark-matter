// SPDX-License-Identifier: MIT
// Near miss (R10): the original's parameter of that name is a number, boxed for the patch method: not a class or
// struct the check types. Expected: Broad access, "Uses reflection the check cannot trace".
using HarmonyLib;

internal static class ManualParameterNumberHooks {
    internal static void After(object slot) => slot.GetType().GetMethod("Rename")!.Invoke(slot, ["name"]);
}

public static class ManualParameterNumber {
    public static void Start() =>
        new Harmony("example.invalid").Patch(AccessTools.Method(typeof(KSA.Dock), "Attach"), postfix: new HarmonyMethod(typeof(ManualParameterNumberHooks), "After"));
}
