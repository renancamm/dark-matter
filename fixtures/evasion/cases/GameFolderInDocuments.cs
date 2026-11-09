// SPDX-License-Identifier: MIT
// Control: the game's folder in Documents, written the ways mods write it (Path.Combine with each
// name, one operand with both, an interpolated string, a concatenation, Path.Join, a field holding
// the folder). Expected: Limited access, "Changes files in its own or the game's folders" only.
using System;
using System.IO;

public static class GameFolderInDocuments {
    static readonly string Root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "My Games", "Kitten Space Agency", "Notes");
    static string Documents => Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

    public static void Combined() { Directory.CreateDirectory(Root); File.WriteAllText(Path.Combine(Root, "a.txt"), "x"); }
    public static void OneOperand() => File.WriteAllText(Path.Combine(Documents, "My Games/Kitten Space Agency/b.txt"), "x");
    public static void Interpolated() => File.WriteAllText($"{Documents}/My Games/Kitten Space Agency/c.txt", "x");
    public static void Concatenated() => File.WriteAllText(Documents + "/My Games/Kitten Space Agency/d.txt", "x");
    public static void Joined() => File.WriteAllText(Path.Join(Documents, "My Games", "Kitten Space Agency", "e.txt"), "x");
}
