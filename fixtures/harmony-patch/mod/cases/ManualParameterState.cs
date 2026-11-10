// SPDX-License-Identifier: MIT
// Near miss (R10): __state is the patch's own storage, filled by another patch method, not one of the original's
// parameters, even when the original has a parameter of that name. Expected: Broad access, "Uses reflection the
// check cannot trace".
using HarmonyLib;

internal static class ManualParameterStateHooks {
    internal static void After(object __state) => __state.GetType().GetMethod("Rename")!.Invoke(__state, ["name"]);
}

public static class ManualParameterState {
    public static void Start() =>
        new Harmony("example.invalid").Patch(AccessTools.Method(typeof(KSA.Dock), "Store"), postfix: new HarmonyMethod(typeof(ManualParameterStateHooks), "After"));
}
