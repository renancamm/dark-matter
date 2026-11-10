// SPDX-License-Identifier: MIT
// Near miss (R10): another patch method takes the original's first parameter by reference, by its index (__0),
// declared as object. That is the parameter named craft, so it can store any object there. Expected: Broad access,
// "Uses reflection the check cannot trace".
using HarmonyLib;

internal static class ManualParameterIndexReplacedHooks {
    internal static void Before(ref object __0) => __0 = KSA.Universe.Instance.Anything;
    internal static void After(object craft) => craft.GetType().GetMethod("Rename")!.Invoke(craft, ["name"]);
}

public static class ManualParameterIndexReplaced {
    public static void Start() {
        var harmony = new Harmony("example.invalid");
        harmony.Patch(AccessTools.Method(typeof(KSA.Dock), "Attach"), prefix: new HarmonyMethod(typeof(ManualParameterIndexReplacedHooks), "Before"));
        harmony.Patch(AccessTools.Method(typeof(KSA.Dock), "Attach"), postfix: new HarmonyMethod(typeof(ManualParameterIndexReplacedHooks), "After"));
    }
}
