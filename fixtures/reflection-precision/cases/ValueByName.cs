// SPDX-License-Identifier: MIT
// Probe (D5, policy 35): the game type is found by name (AccessTools.TypeByName), as mods that do not reference the
// game's assemblies do; its field is typed from the game-API map, provided the game alone has a type of that name.
// Expected: Broad access, deep game access only (before: "Uses reflection the check cannot trace"). With the mod's
// other assembly defining a type of that name too (ShadowUniverse, checked by the harness), the lookup can find
// that one: "Uses reflection the check cannot trace".
using HarmonyLib;

public static class ValueByName {
    public static void Go(object universe) {
        var current = AccessTools.Field(AccessTools.TypeByName("KSA.Universe"), "Current").GetValue(universe)!;
        current.GetType().GetMethod("Update")!.Invoke(current, null);
    }
}
