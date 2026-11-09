// SPDX-License-Identifier: MIT
// The game's XML helper given a type the mod chooses: its own class as the type argument, and any
// object's run-time type as a Type. The game's own XmlSerializer use is exempt, but here the mod
// picks what it fills. Expected: Broad access, deep game access, "Has the game read or write XML into
// objects of types the mod chooses ..." (G1a review A17).
public class Settings { public int Volume { get; set; } }

public static class LoadSettings {
    public static Settings Load() => KSA.XmlStore.Load<Settings>("settings.xml");
    public static object LoadAny(object o) => KSA.XmlStore.LoadAs(o.GetType(), "any.xml");
}
