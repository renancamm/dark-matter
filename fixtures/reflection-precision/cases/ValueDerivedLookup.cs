// SPDX-License-Identifier: MIT
// Near miss (D5): the field is looked up on the run-time type of a game-typed value, which can be a derived type
// declaring a field of the same name and another type; its value is not typed. Expected: Full access, the
// bounded reason (for GetValue on that member) and "Uses reflection the check cannot trace" (for the value).
public static class ValueDerivedLookup {
    public static void Go(KSA.Universe universe) {
        var current = universe.GetType().GetField("Current")!.GetValue(universe)!;
        current.GetType().GetMethod("Update")!.Invoke(current, null);
    }
}
