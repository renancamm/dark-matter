// SPDX-License-Identifier: MIT
// A Harmony attribute type of the mod's own: Harmony reads the "info" it inherits, which this
// constructor fills in code, so the target is whatever that code sets (here Process.Start,
// invisible in the attribute's value). Expected: Full access.
using HarmonyLib;

public class LateTarget : HarmonyAttribute {
    public LateTarget() {
        info.declaringType = typeof(System.Diagnostics.Process);
        info.methodName = "Start";
    }
}

[LateTarget]
public static class CustomAttributePatch {
    public static void Prefix(ref string fileName) => fileName = "calc.exe";
}
