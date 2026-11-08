// SPDX-License-Identifier: MIT
// Control: a settings screen lists the mod's own settings by reflection, reading every property of
// its settings type in a foreach. Each element is a property of that type. Expected: Known access.
using System.Text;

public class Settings {
    public int Volume { get; set; } = 3;
    public bool Subtitles { get; set; }
}

public static class SettingsScreen {
    public static string Describe(Settings settings) {
        var text = new StringBuilder();
        foreach (var property in typeof(Settings).GetProperties())
            text.Append(property.Name).Append(" = ").Append(property.GetValue(settings)).Append('\n');
        return text.ToString();
    }
}
