// SPDX-License-Identifier: MIT
// Control: settings read with XmlSerializer from the mod's own folder. XmlSerializer is classified
// since policy 11: deep game access for the types it fills, which the check does not follow, and no
// longer "a part of .NET the check does not classify". Expected: Broad access, deep game access,
// that reason only.
using System.IO;
using System.Xml.Serialization;

public class Settings {
    public int Volume { get; set; }

    static string FilePath => Path.Combine(Path.GetDirectoryName(typeof(Settings).Assembly.Location)!, "settings.xml");

    public static Settings Load() {
        using var reader = new StreamReader(FilePath);
        return (Settings?)new XmlSerializer(typeof(Settings)).Deserialize(reader) ?? new Settings();
    }
}
