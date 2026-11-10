// SPDX-License-Identifier: MIT
// Near miss (D8): one call passes a game object, another an object the check cannot type (read from a field declared
// as object). Expected: Broad access, "Uses reflection the check cannot trace".
internal static class ObjectParameterMixedHelpers {
    internal static object Anything;

    internal static void Use(object target) => target.GetType().GetMethod("Rename")!.Invoke(target, ["name"]);
}

public static class ObjectParameterMixed {
    public static void Go(KSA.Craft craft) {
        ObjectParameterMixedHelpers.Use(craft);
        ObjectParameterMixedHelpers.Use(ObjectParameterMixedHelpers.Anything);
    }
}
