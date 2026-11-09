// SPDX-License-Identifier: MIT
// Control for TrustedIgnoreCase: the same lookup by the member's exact name. Expected: Full access,
// "Uses reflection the check cannot trace".
using System.Reflection;

public static class TrustedExactName {
    public static void Go() =>
        typeof(HarmonyLib.Harmony).GetMethod("Patch", BindingFlags.Public | BindingFlags.Instance)?
            .Invoke(new HarmonyLib.Harmony("example.invalid"), [null, null, null, null, null]);
}
