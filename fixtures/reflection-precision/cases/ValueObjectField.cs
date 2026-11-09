// SPDX-License-Identifier: MIT
// Near miss (D5): the game field is declared as object, which bounds nothing. Expected: Broad access, "Uses
// reflection the check cannot trace".
public static class ValueObjectField {
    public static void Go() {
        var anything = typeof(KSA.Universe).GetField("Anything")!.GetValue(KSA.Universe.Instance)!;
        anything.GetType().GetMethod("Update")!.Invoke(anything, null);
    }
}
