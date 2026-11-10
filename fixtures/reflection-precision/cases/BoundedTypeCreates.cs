// SPDX-License-Identifier: MIT
// Control (policy 38): an object created from the run-time type of a value declared as a game class. No member
// is looked up by name, so the type alone is known: KSA.Craft or a game type derived from it, and KSA.Rover has
// a member that starts a program. Expected: Broad access, "Starts other programs", and the bounded label.
using System;

public static class BoundedTypeCreates {
    public static object? Copy(KSA.Craft craft) => Activator.CreateInstance(craft.GetType());
}
