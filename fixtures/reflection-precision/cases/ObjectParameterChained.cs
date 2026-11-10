// SPDX-License-Identifier: MIT
// Probe (D8, policy 42): as ObjectParameterTyped, through two helpers: the second one's parameter holds what the
// first one's does. Expected: Limited access with "Uses the game's internals by reflection" and "Uses your clipboard".
internal static class ObjectParameterChainedHelpers {
    internal static void First(object target) => Second(target);
    static void Second(object target) => target.GetType().GetMethod("Rename")!.Invoke(target, ["name"]);
}

public static class ObjectParameterChained {
    public static void Go(KSA.Craft craft) => ObjectParameterChainedHelpers.First(craft);
}
