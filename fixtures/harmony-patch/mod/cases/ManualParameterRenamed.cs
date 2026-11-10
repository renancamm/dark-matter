// SPDX-License-Identifier: MIT
// Near miss (R10): [HarmonyArgument] gives the parameter named craft another of the original's arguments (a
// KSA.Terminal). Expected: Broad access, "Uses reflection the check cannot trace".
using HarmonyLib;

internal static class ManualParameterRenamedHooks {
    internal static void After([HarmonyArgument("console")] object craft) => craft.GetType().GetMethod("Run")!.Invoke(craft, ["example.invalid"]);
}

public static class ManualParameterRenamed {
    public static void Start() =>
        new Harmony("example.invalid").Patch(AccessTools.Method(typeof(KSA.Dock), "Attach"), postfix: new HarmonyMethod(typeof(ManualParameterRenamedHooks), "After"));
}
