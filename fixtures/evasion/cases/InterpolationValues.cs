// SPDX-License-Identifier: MIT
// Control: numbers, booleans, GUIDs and the mod's own enum values formatted into a file name in the
// mod's folder, with an extension after a value, and a name chosen by a condition inside the
// interpolation. Their text has no separator and no "..".
// Expected: Limited access, "Changes files in its own or the game's folders" only.
using System;
using System.IO;

public enum Slot { First, Second }

public static class InterpolationValues {
    static string Own => Path.GetDirectoryName(typeof(InterpolationValues).Assembly.Location);
    static string Settings => Path.Combine(Own, "settings");

    public static void Save(int n, bool b, Slot slot, Guid id) => File.WriteAllText($"{Own}/save_{n}_{b}_{slot}_{id}_{n:D4}.json", "x");

    public static void Choice(bool b) => File.WriteAllText($"{Own}/{(b ? "a" : "b")}.txt", "x");

    public static void Backup() { File.WriteAllText($"{Settings}.json", "x"); File.WriteAllText(Settings + ".bak", "x"); }
}
