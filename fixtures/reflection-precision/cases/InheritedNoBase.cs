// SPDX-License-Identifier: MIT
// Control (H7b): the mod's own type defines a method of the game method's name, and has no game base type: the
// lookup finds only the mod's own harmless method. Expected: Limited access, no labels.
using System.Reflection;

internal class InheritedNoBaseType {
    public static void InheritedRun(string file) { }
}

public static class InheritedNoBaseEntry {
    public static void Go() =>
        typeof(InheritedNoBaseType).GetMethod("InheritedRun", BindingFlags.Public | BindingFlags.Static)!.Invoke(null, ["example.invalid"]);
}
