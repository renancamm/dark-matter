// SPDX-License-Identifier: MIT
// Probe case: a file under an environment variable's folder whose name contains "My Games". An
// environment variable can name any folder, and the name is a file name, not the game's folder.
// Expected: "Changes files outside the game", not the game's folders (G1a review A5).
using System;
using System.IO;

public static class GameNameInFile {
    public static void Save() => File.WriteAllText(Path.Combine(Environment.GetEnvironmentVariable("HOME"), "notes", "My Games.txt"), "x");
}
