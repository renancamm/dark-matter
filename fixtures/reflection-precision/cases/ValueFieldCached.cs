// SPDX-License-Identifier: MIT
// Probe (D5, policy 35): the FieldInfo is kept in a static field and read in another method, as mods cache their
// lookups. The value read through what the field holds is typed per mod (Nodes.TypeOfNode). Expected: Broad access,
// deep game access only (before: "Uses reflection the check cannot trace").
using System.Reflection;

public static class ValueFieldCached {
    static readonly FieldInfo Current = typeof(KSA.Universe).GetField("Current")!;

    public static void Go(object universe) {
        var craft = Current.GetValue(universe)!;
        craft.GetType().GetMethod("Update")!.Invoke(craft, null);
    }
}
