// SPDX-License-Identifier: MIT
// Probe (D8, policy 42): a helper's parameter declared as object holds what every call passes. Nothing outside the
// mod can call the helper, and its one call passes a value declared as a game class, so the object's run-time type
// is that class or a type derived from it. Expected: Limited access with "Uses the game's internals by reflection"
// and "Uses your clipboard" (before: "Uses reflection the check cannot trace").
internal static class ObjectParameterTypedHelpers {
    internal static void Use(object target) => target.GetType().GetMethod("Rename")!.Invoke(target, ["name"]);
}

public static class ObjectParameterTyped {
    public static void Go(KSA.Craft craft) => ObjectParameterTypedHelpers.Use(craft);
}
