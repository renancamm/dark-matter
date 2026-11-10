// SPDX-License-Identifier: MIT
// Near miss (R10): the mod also calls the patch method itself, with a value the check cannot type. Expected: Broad
// access, "Uses reflection the check cannot trace".
using HarmonyLib;

internal static class ManualParameterAlsoCalledHooks {
    internal static void After(object craft) => craft.GetType().GetMethod("Rename")!.Invoke(craft, ["name"]);
}

public static class ManualParameterAlsoCalled {
    public static void Again() => ManualParameterAlsoCalledHooks.After(KSA.Universe.Instance.Anything);

    public static void Start() =>
        new Harmony("example.invalid").Patch(AccessTools.Method(typeof(KSA.Dock), "Attach"), postfix: new HarmonyMethod(typeof(ManualParameterAlsoCalledHooks), "After"));
}
