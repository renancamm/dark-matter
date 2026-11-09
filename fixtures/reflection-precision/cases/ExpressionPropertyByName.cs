// SPDX-License-Identifier: MIT
// A game property found by Expression.Property(Expression, Type, string) and assigned in a compiled
// tree: its setter saves the game. Expected: Limited access, "Changes game saves" (H4; before
// policy 19, no labels).
using System;
using System.Linq.Expressions;

public static class ExpressionPropertyByName {
    public static void Go(KSA.VesselOptions options) {
        var p = Expression.Parameter(typeof(KSA.VesselOptions), "o");
        var set = Expression.Assign(Expression.Property(p, typeof(KSA.VesselOptions), "AutoSave"), Expression.Constant(true));
        Expression.Lambda<Action<KSA.VesselOptions>>(set, p).Compile()(options);
    }
}
