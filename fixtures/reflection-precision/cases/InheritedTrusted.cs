// SPDX-License-Identifier: MIT
// Probe (H7b): reflection on the mod's own type finds a static method it inherits from a trusted library's
// type (the Harmony stand-in's StartsHost), which starts a program. Expected: Full access, "Starts other
// programs" (before: Limited access).
using System.Reflection;

internal class InheritedTrustedType : HarmonyLib.StartsHost { }

public static class InheritedTrustedEntry {
    public static void Go() =>
        typeof(InheritedTrustedType).GetMethod("InheritedStart", BindingFlags.Public | BindingFlags.Static | BindingFlags.FlattenHierarchy)!
            .Invoke(null, ["example.invalid"]);
}
