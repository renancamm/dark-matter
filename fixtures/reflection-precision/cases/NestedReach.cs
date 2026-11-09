// SPDX-License-Identifier: MIT
// A private method of a nested type, found through GetNestedType on its outer type, invoked by
// reflection with a Type argument no direct caller passes. Expected: Broad access, "Uses reflection
// the check cannot trace" (H1a-review H5; before policy 19 reflection on the outer type did not
// count for its nested types: Limited access, no labels). Control: NestedDirect.
using System;
using System.Reflection;

internal static class Outer {
    private static class Inner {
        private static void Run(Type t, string text) => t.GetMethod("CopyName")?.Invoke(null, [text]);
    }
}

public static class NestedReach {
    public static void Go(string text) =>
        typeof(Outer).GetNestedType("Inner", BindingFlags.NonPublic)!
            .GetMethod("Run", BindingFlags.NonPublic | BindingFlags.Static)!
            .Invoke(null, [typeof(KSA.UiText), text]);
}
