// SPDX-License-Identifier: MIT
// A trusted library's member found with BindingFlags.IgnoreCase under another spelling ("patch" for
// Harmony.Patch) and invoked: Harmony's patching API traces its arguments only at the mod's direct
// call, so reached by reflection it is unresolved. Expected: Full access, "Uses reflection the check
// cannot trace", with the evidence naming HarmonyLib.Harmony::Patch (H1; before policy 19 the profile
// had no member "patch", so the lookup counted as one of any member of the type: the same result, by
// the whole type). Control: TrustedExactName.
using System.Reflection;

public static class TrustedIgnoreCase {
    public static void Go() =>
        typeof(HarmonyLib.Harmony).GetMethod("patch", BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase)?
            .Invoke(new HarmonyLib.Harmony("example.invalid"), [null, null, null, null, null]);
}
