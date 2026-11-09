// SPDX-License-Identifier: MIT
// Control (H7b review): as InheritedNested, with a lookup that names only a method of the mod's own types, which
// neither the nested type nor its game base type has. Expected: Limited access, no labels.
using System.Reflection;

internal static class InheritedNestedOwnNameType {
    internal class Inner : KSA.StartsBase {
        public static void Mine(string file) { }
    }
}

public static class InheritedNestedOwnNameEntry {
    public static void Go() =>
        typeof(InheritedNestedOwnNameType).GetNestedType("Inner", BindingFlags.NonPublic)!
            .GetMethod("Mine", BindingFlags.Public | BindingFlags.Static)!.Invoke(null, ["example.invalid"]);
}
