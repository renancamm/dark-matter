// SPDX-License-Identifier: MIT
// Near miss (R10): the patch method is public on a public type, so code outside the mod can call it with any
// object, as for any parameter declared as object (D8). Expected: Broad access, "Uses reflection the check cannot
// trace".
using HarmonyLib;

public static class ManualParameterPublicHooks {
    public static void After(object craft) => craft.GetType().GetMethod("Rename")!.Invoke(craft, ["name"]);
}

public static class ManualParameterPublic {
    public static void Start() =>
        new Harmony("example.invalid").Patch(AccessTools.Method(typeof(KSA.Dock), "Attach"), postfix: new HarmonyMethod(typeof(ManualParameterPublicHooks), "After"));
}
