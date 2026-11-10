// SPDX-License-Identifier: MIT
// Control (policy 38): as BoundedTypeCreates, for a game class whose members, and those of the game types
// derived from it, reach nothing. Expected: Limited access, the bounded label only.
using System;

public static class BoundedTypeCreatesPlain {
    public static object? Copy(KSA.Vehicle vehicle) => Activator.CreateInstance(vehicle.GetType());
}
