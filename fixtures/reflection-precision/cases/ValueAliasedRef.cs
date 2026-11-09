// SPDX-License-Identifier: MIT
// Negative (D10): the typed value is stored into a local declared as object after a ref local took that local's
// address; a store through the ref local replaces it with any object. Expected: Full access, "Uses reflection the
// check cannot trace" (before D10 the walker trusted the last object it saw stored into a local whose address was taken).
public static class ValueAliasedRef {
    public static void Go(object other) {
        object value = "text";
        ref object alias = ref value;
        value = typeof(KSA.Universe).GetField("Current")!.GetValue(KSA.Universe.Instance)!;
        alias = other;
        value.GetType().GetMethod("Update")!.Invoke(value, null);
    }
}
