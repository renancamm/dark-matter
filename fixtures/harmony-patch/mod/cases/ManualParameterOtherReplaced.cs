// SPDX-License-Identifier: MIT
// Probe (R10): other patch methods take different parameters of the original by reference: its number by name, and
// its second parameter by index (__1). Neither is the parameter named craft, which the game declares first.
// Expected: Limited access with "Uses the game's internals by reflection".
using HarmonyLib;

internal static class ManualParameterOtherReplacedHooks {
    internal static void Before(ref int slot) => slot = 0;
    internal static void Early(ref KSA.Terminal __1) => __1 = new KSA.Terminal();
    internal static void After(object craft) => craft.GetType().GetMethod("Rename")!.Invoke(craft, ["name"]);
}

public static class ManualParameterOtherReplaced {
    public static void Start() {
        var harmony = new Harmony("example.invalid");
        harmony.Patch(AccessTools.Method(typeof(KSA.Dock), "Attach"), prefix: new HarmonyMethod(typeof(ManualParameterOtherReplacedHooks), "Before"));
        harmony.Patch(AccessTools.Method(typeof(KSA.Dock), "Attach"), prefix: new HarmonyMethod(typeof(ManualParameterOtherReplacedHooks), "Early"));
        harmony.Patch(AccessTools.Method(typeof(KSA.Dock), "Attach"), postfix: new HarmonyMethod(typeof(ManualParameterOtherReplacedHooks), "After"));
    }
}
