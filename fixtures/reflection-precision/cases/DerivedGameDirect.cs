// SPDX-License-Identifier: MIT
// Control (D9): the member looked up is the declared game type's own. Expected (before and after): Broad access,
// deep game access only, "Uses your clipboard".
// Policy 38: reflection bounded to a game type is the label "Uses the game's internals by reflection", not a Broad-access reason.
public static class DerivedGameDirect {
    public static void Go(KSA.Craft craft) => craft.GetType().GetMethod("Rename")!.Invoke(craft, ["name"]);
}
