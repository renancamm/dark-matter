// SPDX-License-Identifier: MIT
// Probe (D5, policy 35): a value read with FieldInfo.GetValue from a game field found by a constant name on
// exactly a game type, declared as a game class, is of that class or a type derived from it, as GetType() of a
// game-typed value is. Expected: Full access, deep game access only (before: "Uses reflection the check cannot
// trace", the value was an object of any type).
public static class ValueFieldGame {
    public static void Go() {
        var current = typeof(KSA.Universe).GetField("Current")!.GetValue(KSA.Universe.Instance)!;
        current.GetType().GetMethod("Update")!.Invoke(current, null);
    }
}
