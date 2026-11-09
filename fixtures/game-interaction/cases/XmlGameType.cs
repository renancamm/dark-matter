// SPDX-License-Identifier: MIT
// Control: the same game XML helper for one of the game's own types, which is the game's content,
// not a type the mod chooses. Expected: Limited access (no XML reason).
public static class LoadOptions {
    public static KSA.VesselOptions Load() => KSA.XmlStore.Load<KSA.VesselOptions>("options.xml");
    public static object LoadAs() => KSA.XmlStore.LoadAs(typeof(KSA.VesselOptions), "options.xml");
}
