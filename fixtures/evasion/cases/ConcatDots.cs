// SPDX-License-Identifier: MIT
// Probe case: ".." split across two operands of string.Concat, and across interpolation parts with
// an empty string between them. Expected: "Changes files outside the game" (G1a review A15).
using System.IO;

public static class ConcatDots {
    static string Empty = "";
    static string Own => Path.GetDirectoryName(typeof(ConcatDots).Assembly.Location);

    public static void Concatenated() => File.WriteAllText(string.Concat(Own, "/.", "./a.txt"), "x");

    public static void Interpolated() => File.WriteAllText($"{Own}/.{Empty}./.{Empty}./b.txt", "x");
}
