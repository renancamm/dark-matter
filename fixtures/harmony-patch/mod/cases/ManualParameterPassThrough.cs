// SPDX-License-Identifier: MIT
// Near miss (R10): a postfix that returns its first parameter's type is given the original's result there, whatever
// the parameter is called. Expected: Broad access, "Uses reflection the check cannot trace".
using HarmonyLib;

internal static class ManualParameterPassThroughHooks {
    internal static object After(object console) {
        console.GetType().GetMethod("Rename")!.Invoke(console, ["name"]);
        return console;
    }
}

public static class ManualParameterPassThrough {
    public static void Start() =>
        new Harmony("example.invalid").Patch(AccessTools.Method(typeof(KSA.Dock), "Attach"), postfix: new HarmonyMethod(typeof(ManualParameterPassThroughHooks), "After"));
}
