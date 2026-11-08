// SPDX-License-Identifier: MIT
// File access labelled by where the path comes from.
using System;
using System.IO;

public class FileCases {
    // Inside the mod's own folder: no label.
    static string ModFolder => Path.GetDirectoryName(typeof(FileCases).Assembly.Location);
    public static void WriteOwnConfig() => File.WriteAllText(Path.Combine(ModFolder, "config.json"), "{}");

    // The user's profile folder: "Changes files outside the game".
    public static void WriteHome() => File.WriteAllText(
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "note.txt"), "");
}
