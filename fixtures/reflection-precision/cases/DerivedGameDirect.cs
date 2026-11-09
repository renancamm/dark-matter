// SPDX-License-Identifier: MIT
// Control (D9): the member looked up is the declared game type's own. Expected (before and after): Full access,
// deep game access only, "Uses your clipboard".
public static class DerivedGameDirect {
    public static void Go(KSA.Craft craft) => craft.GetType().GetMethod("Rename")!.Invoke(craft, ["name"]);
}
