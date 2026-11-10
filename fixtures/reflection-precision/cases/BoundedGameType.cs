// SPDX-License-Identifier: MIT
// Control: a mod reads a private field of a game object through the object's run-time type, which
// is KSA.Vehicle or a type derived from it. The check knows the field is in the game's code but not
// exactly which type it belongs to. Expected: Broad access, deep game access only.
// Policy 38: reflection bounded to a game type is the label "Uses the game's internals by reflection", not a Broad-access reason.
using System.Reflection;

public static class VehicleMass {
    public static float Read(KSA.Vehicle vehicle) =>
        (float)vehicle.GetType().GetField("mass", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(vehicle)!;
}
