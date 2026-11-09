// SPDX-License-Identifier: MIT
// Control for NestedReach: the same private method reached through typeof of the nested type.
// Expected: Full access, "Uses reflection the check cannot trace".
using System;
using System.Reflection;

internal static class Outer2 {
    internal static class Inner {
        private static void Run(Type t, string text) => t.GetMethod("CopyName")?.Invoke(null, [text]);
    }
}

public static class NestedDirect {
    public static void Go(string text) =>
        typeof(Outer2.Inner).GetMethod("Run", BindingFlags.NonPublic | BindingFlags.Static)!.Invoke(null, [typeof(KSA.UiText), text]);
}
