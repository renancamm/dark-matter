// SPDX-License-Identifier: MIT
// Probe case: ".." made of formatted chars between separators, and a char's text given to
// Path.Combine, where "/" replaces the mod's folder with the root. Expected: "Changes files outside
// the game", for each method (G1a review A14).
using System.IO;

public static class InterpolationChar {
    static char Dot = '.';
    static char Separator = '/';
    static string Own => Path.GetDirectoryName(typeof(InterpolationChar).Assembly.Location);

    public static void Formatted() => File.WriteAllText($"{Own}/{Dot}{Dot}/{Dot}{Dot}/a.txt", "x");

    public static void Rooted() => File.WriteAllText(Path.Combine(Own, Separator.ToString(), "tmp", "b.txt"), "x");
}
