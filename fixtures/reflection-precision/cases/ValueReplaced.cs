// SPDX-License-Identifier: MIT
// Near miss (D5): the typed value is replaced on one path before its run-time type is used, so the local can
// hold an object of any type there. Expected: Full access, "Uses reflection the check cannot trace".
public static class ValueReplaced {
    public static void Go(object other, bool pick) {
        var value = typeof(KSA.Universe).GetField("Current")!.GetValue(KSA.Universe.Instance)!;
        if (pick) value = other;
        value.GetType().GetMethod("Update")!.Invoke(value, null);
    }
}
