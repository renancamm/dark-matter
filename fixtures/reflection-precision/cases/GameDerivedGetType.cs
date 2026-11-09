// SPDX-License-Identifier: MIT
// Probe (H7 review, H7b): GetType() of a value declared as a game class can be the mod's own type deriving from
// it, so a private method of that type found by name is called with any argument. Expected: Broad access with
// "Uses reflection the check cannot trace" besides the bounded game reflection (before: only the bounded
// reason; the method's Type argument was traced to its one direct call).
using System;
using System.Reflection;

internal class GameDerivedVehicle : KSA.Vehicle {
    void Run(Type t) => t.GetMethod("CopyName")?.Invoke(null, ["x"]);
    internal void Direct() => Run(typeof(KSA.Tools));
}

public static class GameDerivedGetTypeEntry {
    public static void Go(KSA.Vehicle v) {
        new GameDerivedVehicle().Direct();
        v.GetType().GetMethod("Run", BindingFlags.NonPublic | BindingFlags.Instance)?.Invoke(v, [typeof(KSA.UiText)]);
    }
}
