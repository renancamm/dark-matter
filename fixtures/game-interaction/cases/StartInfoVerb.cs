// SPDX-License-Identifier: MIT
// Near-miss guard (workstream A review): the folder-open proof accepts a ProcessStartInfo only when
// nothing but FileName and UseShellExecute is set. Here the mod creates a folder next to its assembly
// but also sets Verb, so the start is no longer a plain shell open and could carry a custom action.
// Expected: Full access, "Starts other programs" (the proof must not relabel it "Opens its own or the
// game's folders"). Control with no extra member is game-interaction/OpenOwnFolder (Limited access).
using System.Diagnostics;
using System.IO;

public static class StartInfoVerbEntry {
    static string Folder => Path.Combine(Path.GetDirectoryName(typeof(StartInfoVerbEntry).Assembly.Location)!, "exports");

    public static void OnOpenClicked() {
        Directory.CreateDirectory(Folder);
        Process.Start(new ProcessStartInfo { FileName = Folder, Verb = "open", UseShellExecute = true });
    }
}
