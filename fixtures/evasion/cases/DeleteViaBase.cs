// SPDX-License-Identifier: MIT
// Probe case: a delete through the FileSystemInfo base class. Expected: "Changes files outside the game".
using System.IO;

public class DeleteViaBaseCase {
    public static void Run(FileSystemInfo i) => i.Delete();
}
