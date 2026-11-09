// SPDX-License-Identifier: MIT
// Negative for H7's member-scoped reach (F1, guard 1): the method holding the name parameter becomes
// reachable by reflection only through a Type field (a traced node). Q.P looks a member of R up by its
// name parameter; its only direct call names "Hello", but P is also invoked by reflection through the
// field `self`, with "Run", so R.Run's Type parameter is whatever that call passes. The reach through
// the field must be inside the name fixpoint. Expected: Broad access, "Uses reflection the check cannot
// trace" (a prototype without the guard gave Limited access; H1a-review probe XF1Order).
using System;
using System.Reflection;

internal static class Q {
    static readonly Type self = typeof(Q);
    private static void P(string name, object[] args) =>
        typeof(R).GetMethod(name, BindingFlags.NonPublic | BindingFlags.Static)?.Invoke(null, args);
    internal static void Hello() => P("Hello", []);
    internal static void Via(string text) =>
        self.GetMethod("P", BindingFlags.NonPublic | BindingFlags.Static)?.Invoke(null, ["Run", new object[] { typeof(KSA.UiText), text }]);
}

internal static class R {
    private static void Hello() { }
    private static void Run(Type t, string text) => t.GetMethod("CopyName")?.Invoke(null, [text]);
}

public static class F1Entry {
    public static void Go(string text) { Q.Hello(); Q.Via(text); }
}
