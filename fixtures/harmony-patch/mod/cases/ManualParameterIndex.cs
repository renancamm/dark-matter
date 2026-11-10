// SPDX-License-Identifier: MIT
// Probe (R10): as ManualParameterGame, for __1 declared as object: the original's second parameter, a KSA.Terminal.
// The lookup names a member of it that does nothing. Expected: Limited access with "Uses the game's internals by
// reflection".
using HarmonyLib;

internal static class ManualParameterIndexHooks {
    internal static void After(object __1) => __1.GetType().GetMethod("Print")!.Invoke(__1, ["text"]);
}

public static class ManualParameterIndex {
    public static void Start() =>
        new Harmony("example.invalid").Patch(AccessTools.Method(typeof(KSA.Dock), "Attach"), postfix: new HarmonyMethod(typeof(ManualParameterIndexHooks), "After"));
}
