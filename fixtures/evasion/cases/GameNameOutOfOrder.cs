// SPDX-License-Identifier: MIT
// Probe case: the game's folder names in Documents, but below another folder ("Documents/notes/My
// Games/Kitten Space Agency"), and below the folder above Documents. Neither is the game's folder.
// Expected: "Changes files outside the game" only (G1a review A5).
using System;
using System.IO;

public static class GameNameOutOfOrder {
    static string Documents => Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

    public static void Below() => File.WriteAllText(Path.Combine(Path.Combine(Documents, "notes", "My Games", "Kitten Space Agency"), "x.txt"), "x");

    public static void Above() => File.WriteAllText(Path.Combine(Path.GetDirectoryName(Documents), "My Games", "Kitten Space Agency", "x.txt"), "x");
}
