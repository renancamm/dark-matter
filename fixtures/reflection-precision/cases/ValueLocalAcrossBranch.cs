// SPDX-License-Identifier: MIT
// Control (policy 40): a value read by reflection through a field of a declared game type, kept in a local
// declared as object and used after the branches of null-conditional operators. The local holds that value on
// every path, so its run-time type is the game type or one derived from it. Expected: Limited access, the
// bounded label and what the member named can do ("Uses your clipboard"); before, "Uses reflection the check
// cannot trace", because a local declared as object was not followed across a branch.
using System.Reflection;

public static class ValueLocalAcrossBranch {
    static readonly FieldInfo Current = typeof(KSA.Universe).GetField("Current")!;

    public static object? Go() {
        object? value = Current?.GetValue(null);
        return value?.GetType().GetMethod("Rename")?.Invoke(value, ["name"]);
    }
}
