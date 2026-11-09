// SPDX-License-Identifier: MIT
// H9 (policy 29): listing the computer's drives (a file browser's quick links) reads information about
// the computer: user-info (before H9: unclassified).
using System.Collections.Generic;
using System.IO;

public static class DriveList {
    public static List<string> QuickLinks() {
        var names = new List<string>();
        foreach (var d in DriveInfo.GetDrives())
            if (d.IsReady) names.Add(d.Name + " " + d.VolumeLabel);
        return names;
    }
}
