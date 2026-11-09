// SPDX-License-Identifier: MIT
// Probe case: the mod creates a folder next to its assembly, then replaces the local holding its path
// through a ref local taken before, and starts it. What starts is a program, not the folder.
// Expected: Broad access, "Starts other programs" (it was "Opens its own or the game's folders" before policy 20).
using System.Diagnostics;
using System.IO;

public static class AliasedFolder {
    public static void Open() {
        string path = null;
        ref string alias = ref path;
        path = Path.Combine(Path.GetDirectoryName(typeof(AliasedFolder).Assembly.Location)!, "exports");
        Directory.CreateDirectory(path);
        alias = "example-program";
        Process.Start(path);
    }
}
