// SPDX-License-Identifier: MIT
// Near miss (R10): the original has no parameter of that name (Harmony refuses the patch; the check only knows it
// cannot type the value). Expected: Broad access, "Uses reflection the check cannot trace".
using HarmonyLib;

internal static class ManualParameterMissingHooks {
    internal static void After(object vessel) => vessel.GetType().GetMethod("Rename")!.Invoke(vessel, ["name"]);
}

public static class ManualParameterMissing {
    public static void Start() =>
        new Harmony("example.invalid").Patch(AccessTools.Method(typeof(KSA.Dock), "Attach"), postfix: new HarmonyMethod(typeof(ManualParameterMissingHooks), "After"));
}
