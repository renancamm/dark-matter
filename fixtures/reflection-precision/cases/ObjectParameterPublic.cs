// SPDX-License-Identifier: MIT
// Near miss (D8): the helper is public, so code outside the mod can call it with any object. Expected: Broad access,
// "Uses reflection the check cannot trace".
public static class ObjectParameterPublic {
    public static void Use(object target) => target.GetType().GetMethod("Rename")!.Invoke(target, ["name"]);
    public static void Go(KSA.Craft craft) => Use(craft);
}
