// SPDX-License-Identifier: MIT
// Control: the same over a game type. Each element is a property of KSA.VesselOptions, so the mod
// gets what that type's members do (one setter saves the game). Expected: Limited access, "Changes
// game saves".
public static class OptionsCopy {
    public static void Copy(KSA.VesselOptions from, KSA.VesselOptions to) {
        foreach (var property in typeof(KSA.VesselOptions).GetProperties())
            if (property.CanWrite) property.SetValue(to, property.GetValue(from));
    }
}
