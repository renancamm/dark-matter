// SPDX-License-Identifier: MIT
// Near miss (D8): the helper is also taken as a delegate, which can be called with any object. Expected: Broad
// access, "Uses reflection the check cannot trace".
using System;

internal static class ObjectParameterDelegateHelpers {
    internal static void Use(object target) => target.GetType().GetMethod("Rename")!.Invoke(target, ["name"]);
}

public static class ObjectParameterDelegate {
    public static Action<object> Go(KSA.Craft craft) {
        ObjectParameterDelegateHelpers.Use(craft);
        return ObjectParameterDelegateHelpers.Use;
    }
}
