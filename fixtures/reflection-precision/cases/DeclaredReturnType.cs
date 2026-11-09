// SPDX-License-Identifier: MIT
// Probe (D6, policy 35): MethodInfo.ReturnType of a game method found by a constant name is its declared return
// type. Expected: Limited access, nothing labelled (before: "Uses reflection the check cannot trace").
public static class DeclaredReturnType {
    public static void Go(object craft) =>
        typeof(KSA.Universe).GetMethod("Find")!.ReturnType.GetMethod("Update")!.Invoke(craft, null);
}
