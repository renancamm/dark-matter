// SPDX-License-Identifier: MIT
// Control (H7b): the mod's own type derives from a game type, and the lookups name only its own members: a
// method and a property the game base type does not have (a property name no game member has must not make
// every inherited member reached, as it does for a game type's renamed accessors). Expected: Limited access,
// no labels.
using System.Reflection;

internal class InheritedOwnNameType : KSA.StartsBase {
    static int count;
    public static void Mine(string file) { }
    public static int Count { get => count; set => count = value; }
}

public static class InheritedOwnNameEntry {
    public static object? Go() {
        typeof(InheritedOwnNameType).GetMethod("Mine", BindingFlags.Public | BindingFlags.Static)!.Invoke(null, ["example.invalid"]);
        return typeof(InheritedOwnNameType).GetProperty("Count", BindingFlags.Public | BindingFlags.Static)!.GetValue(null);
    }
}
