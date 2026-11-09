// SPDX-License-Identifier: MIT
// Probe (H7 review): an expression tree's lambda that calls a private method of the mod's own, compiled and
// called. The compiler names the method by a method handle (ldtoken), which no lookup by name records, and the
// compiled delegate passes the method whatever it is called with. Q.Run's one direct call passes KSA.UiText
// (no Open); the expression passes KSA.Links, whose Open starts what it is given. Expected: Full access,
// "Uses reflection the check cannot trace" (before: Limited access, nothing labelled).
using System;
using System.Linq.Expressions;

internal static class Q {
    static void Run(Type t) => t.GetMethod("Open")?.Invoke(null, ["example.invalid"]);
    internal static void Direct() => Run(typeof(KSA.UiText));
    internal static void ViaExpression() {
        Expression<Action<Type>> e = t => Run(t);
        e.Compile()(typeof(KSA.Links));
    }
}

public static class ExpressionTreeOwnCallEntry {
    public static void Go() { Q.Direct(); Q.ViaExpression(); }
}
