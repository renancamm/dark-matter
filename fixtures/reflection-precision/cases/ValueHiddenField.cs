// SPDX-License-Identifier: MIT
// Near miss (D5): the game type hides a base type's field with one of the same name and another type; a lookup
// that searches the base types can find either, so the value is not typed. Expected: Full access, "Uses
// reflection the check cannot trace".
public static class ValueHiddenField {
    public static void Go(KSA.Hiding hiding) {
        var slot = typeof(KSA.Hiding).GetField("Slot")!.GetValue(hiding)!;
        slot.GetType().GetMethod("Update")!.Invoke(slot, null);
    }
}
