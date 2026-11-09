// SPDX-License-Identifier: MIT
// Negative (D10): the typed value is cast to object and back through a generic helper (unbox.any of a type
// parameter), which the check does not type. Expected: Broad access, "Uses reflection the check cannot trace".
public static class ValueCastGeneric {
    static T As<T>(object value) => (T)value;

    public static void Go() {
        var value = As<object>(typeof(KSA.Universe).GetField("Current")!.GetValue(KSA.Universe.Instance)!);
        value.GetType().GetMethod("Update")!.Invoke(value, null);
    }
}
