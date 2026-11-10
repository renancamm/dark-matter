// SPDX-License-Identifier: MIT
// Near miss (D8): the helper stores another object to its parameter before using it. Expected: Broad access, "Uses
// reflection the check cannot trace".
internal static class ObjectParameterReassignedHelpers {
    internal static object Other;

    internal static void Use(object target, bool swap) {
        if (swap) target = Other;
        target.GetType().GetMethod("Rename")!.Invoke(target, ["name"]);
    }
}

public static class ObjectParameterReassigned {
    public static void Go(KSA.Craft craft, object other) {
        ObjectParameterReassignedHelpers.Other = other;
        ObjectParameterReassignedHelpers.Use(craft, other != null);
    }
}
