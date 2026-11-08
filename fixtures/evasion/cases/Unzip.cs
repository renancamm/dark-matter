// SPDX-License-Identifier: MIT
// Probe case: a file write through an API outside File/Directory. Expected: "Changes files outside the game".
using System.IO.Compression;

public class UnzipCase {
    public static void Run(string zip) => ZipFile.ExtractToDirectory(zip, "C:\\Users\\Public\\x");
}
