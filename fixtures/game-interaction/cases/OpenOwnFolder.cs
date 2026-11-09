// SPDX-License-Identifier: MIT
// Control: an "open folder" button. The mod creates a folder next to its assembly and opens it with
// the shell. Expected: Limited access, "Changes files in its own or the game's folders" and "Opens its
// own or the game's folders". (Starting a program, shell-open/program, stays Broad access.)
using System.Diagnostics;
using System.IO;

public static class ExportFolder {
    static string Folder => Path.Combine(Path.GetDirectoryName(typeof(ExportFolder).Assembly.Location)!, "exports");

    public static void OnOpenClicked() => Open(Folder);

    static void Open(string path) {
        Directory.CreateDirectory(path);
        Process.Start(new ProcessStartInfo { FileName = path, UseShellExecute = true });
    }
}
