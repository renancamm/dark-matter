// SPDX-License-Identifier: MIT
// A private method of the mod reached by Expression.Call(Type, string, ...) with a Type argument
// no direct caller passes. Expected: Broad access, "Uses reflection the check cannot trace"
// (H1a-review XF1Expression; before policy 19, Limited access, no labels).
using System;
using System.Linq.Expressions;

internal static class ExpressionTarget {
    private static void Run(Type t, string text) => t.GetMethod("CopyName")?.Invoke(null, [text]);
}

public static class ExpressionByNameOwn {
    public static void Go(string text) {
        var call = Expression.Call(typeof(ExpressionTarget), "Run", null, Expression.Constant(typeof(KSA.UiText)), Expression.Constant(text));
        Expression.Lambda<Action>(call).Compile()();
    }
}
