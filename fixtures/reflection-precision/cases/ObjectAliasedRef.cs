// SPDX-License-Identifier: MIT
// Negative (D10, a gap before D): as ValueAliasedRef, with an object of a game class read from a field: the ref
// local can replace it with any object. Expected: Full access, "Uses reflection the check cannot trace" (before:
// deep game access only; the walker trusted the last object it saw stored into a local whose address was taken).
public static class ObjectAliasedRef {
    public static void Go(object other) {
        object value = "text";
        ref object alias = ref value;
        value = KSA.Universe.Instance.Current;
        alias = other;
        value.GetType().GetMethod("Update")!.Invoke(value, null);
    }
}
