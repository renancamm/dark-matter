// SPDX-License-Identifier: MIT
// H9 review: a game type created by name runs its constructor, here one that starts a program, by
// Assembly.CreateInstance on the game's assembly and by Activator.CreateInstance(assembly name, type name).
// Expected: Full access, system access "Starts other programs" (before: Limited access, the constructor
// was not reached).
using System;

public static class GameCreateByName {
    public static object? ByAssembly() => typeof(KSA.Links).Assembly.CreateInstance("KSA.StartsOnCreate");
    public static object? ByActivator() => Activator.CreateInstance("KSA", "KSA.StartsOnCreate");
}
