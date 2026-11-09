// SPDX-License-Identifier: MIT
// Control (H7b): as InheritedOwnName, for a trusted library's base type: a name only the mod's type has is its
// own member, not one of a nested type found from the library type (which would reach all of it). Expected:
// Limited access, no labels.
using System.Reflection;

internal class InheritedTrustedOwnNameType : HarmonyLib.StartsHost {
    public static void Mine(string file) { }
}

public static class InheritedTrustedOwnNameEntry {
    public static void Go() =>
        typeof(InheritedTrustedOwnNameType).GetMethod("Mine", BindingFlags.Public | BindingFlags.Static)!.Invoke(null, ["example.invalid"]);
}
