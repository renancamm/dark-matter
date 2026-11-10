// SPDX-License-Identifier: MIT
// Near miss (R10): another patch method of the mod takes the same parameter of the original by reference, declared as
// object. Harmony hands it the address of the argument without comparing types, so it can store any object there
// before the postfix is given it. Expected: Broad access, "Uses reflection the check cannot trace".
using HarmonyLib;

internal static class ManualParameterReplacedHooks {
    internal static void Before(ref object craft) => craft = KSA.Universe.Instance.Anything;
    internal static void After(object craft) => craft.GetType().GetMethod("Rename")!.Invoke(craft, ["name"]);
}

public static class ManualParameterReplaced {
    public static void Start() {
        var harmony = new Harmony("example.invalid");
        harmony.Patch(AccessTools.Method(typeof(KSA.Dock), "Attach"), prefix: new HarmonyMethod(typeof(ManualParameterReplacedHooks), "Before"));
        harmony.Patch(AccessTools.Method(typeof(KSA.Dock), "Attach"), postfix: new HarmonyMethod(typeof(ManualParameterReplacedHooks), "After"));
    }
}
