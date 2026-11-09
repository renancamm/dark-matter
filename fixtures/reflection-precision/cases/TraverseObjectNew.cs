// SPDX-License-Identifier: MIT
// Control for H7's Traverse.Create(object): a Traverse made from a new game object is exactly of that
// type, so it reaches the type's members (KSA.Vehicle's do nothing the policy flags). Expected: Limited
// access, "Changes how the game works" as for any use of Traverse (before H7: Full access, "Uses
// reflection the check cannot trace").
using HarmonyLib;

public static class TraverseNewVehicle {
    public static object Update() => Traverse.Create((object)new KSA.Vehicle()).Method("Update").GetValue();
}
