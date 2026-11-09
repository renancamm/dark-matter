// SPDX-License-Identifier: MIT
// Negative for H7's member-scoped reach (F1, guards 2 and 4): a private method of a nested type, found
// through GetNestedType on its outer type and by a name in another case (IgnoreCase), invoked by
// reflection with a Type argument no direct caller passes. The walker counts the nested type as the
// outer one, so the name looked up on Outer must reach Outer/Inner::Run, ignoring case. Expected: Full
// access, "Uses reflection the check cannot trace". (NestedReach is the same with the exact name.)
using System;
using System.Reflection;

internal static class Outer {
    private static class Inner {
        private static void Run(Type t, string text) => t.GetMethod("CopyName")?.Invoke(null, [text]);
    }
}

public static class NestedEntry {
    public static void Go(string text) =>
        typeof(Outer).GetNestedType("Inner", BindingFlags.NonPublic)!
            .GetMethod("run", BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.IgnoreCase)!
            .Invoke(null, [typeof(KSA.UiText), text]);
}
