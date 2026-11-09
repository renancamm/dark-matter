// SPDX-License-Identifier: MIT
// Negative (D10): the typed value goes through a method of the mod declared to return object; the check does not
// carry the type through calls. Expected: Broad access, "Uses reflection the check cannot trace".
public static class ValuePassedThrough {
    static object Identity(object value) => value;

    public static void Go() {
        var value = Identity(typeof(KSA.Universe).GetField("Current")!.GetValue(KSA.Universe.Instance)!);
        value.GetType().GetMethod("Update")!.Invoke(value, null);
    }
}
