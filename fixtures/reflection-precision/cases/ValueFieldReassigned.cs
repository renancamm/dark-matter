// SPDX-License-Identifier: MIT
// Near miss (D5): the cached FieldInfo can also hold a field declared as object, so what is read through it is not
// typed. Expected: Broad access, "Uses reflection the check cannot trace".
using System.Reflection;

public static class ValueFieldReassigned {
    static FieldInfo field = typeof(KSA.Universe).GetField("Current")!;

    public static void Widen() => field = typeof(KSA.Universe).GetField("Anything")!;

    public static void Go(object universe) {
        var value = field.GetValue(universe)!;
        value.GetType().GetMethod("Update")!.Invoke(value, null);
    }
}
