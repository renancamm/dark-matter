// SPDX-License-Identifier: MIT
// Control for H7's Traverse.Create(object): a Traverse made from a game object of a declared class reads
// its private field. The object's run-time type is KSA.Vehicle or a type derived from it, as for
// GetType (BoundedGameType). Expected: Full access, deep game access only (before H7: "Uses reflection
// the check cannot trace", system access: a Traverse made from an object was not traced at all).
using HarmonyLib;

public static class TraverseVehicle {
    public static object Read(KSA.Vehicle vehicle) => Traverse.Create((object)vehicle).Field("mass").GetValue();
}
