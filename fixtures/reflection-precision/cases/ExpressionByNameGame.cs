// SPDX-License-Identifier: MIT
// A game method reached by Expression.Call(Type, string, Type[], params Expression[]), compiled
// and run: a lookup by name (ignoring case) on the type given. Expected: Broad access, "Starts other
// programs" (H1a-review H4; before policy 19, Limited access, no labels). Control: ExactNameGame.
using System;
using System.Linq.Expressions;

public static class ExpressionByNameGame {
    public static void Go() =>
        Expression.Lambda<Action>(Expression.Call(typeof(KSA.Tools.Shell), "Run", null, Expression.Constant("example.invalid"))).Compile()();
}
