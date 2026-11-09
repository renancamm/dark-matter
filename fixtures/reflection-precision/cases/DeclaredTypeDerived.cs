// SPDX-License-Identifier: MIT
// Near miss (D6): the field is looked up on the run-time type of a game-typed value; a derived type can declare a
// field of that name with another type. Expected: Broad access, "Uses reflection the check cannot trace".
public static class DeclaredTypeDerived {
    public static void Go(KSA.Universe universe, object target) =>
        universe.GetType().GetField("Console")!.FieldType.GetMethod("Print")!.Invoke(target, ["hello"]);
}
