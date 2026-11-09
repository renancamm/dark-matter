// SPDX-License-Identifier: MIT
// Near miss (D5): the name finds two game fields that differ only in case (the check reads names ignoring case,
// as BindingFlags.IgnoreCase would), declared as different types; the value is not typed. Expected: Full access,
// "Uses reflection the check cannot trace".
public static class ValueCaseCollision {
    public static void Go() {
        var item = typeof(KSA.Universe).GetField("item")!.GetValue(KSA.Universe.Instance)!;
        item.GetType().GetMethod("Update")!.Invoke(item, null);
    }
}
