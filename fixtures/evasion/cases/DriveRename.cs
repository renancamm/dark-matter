// SPDX-License-Identifier: MIT
// H9 (policy 29): renaming a volume is a change to the computer the policy does not classify: still Full
// access, not fully checked (the DriveInfo queries are user-info, DriveList).
using System.IO;

public static class DriveRename {
    public static void Rename(string drive, string label) => new DriveInfo(drive).VolumeLabel = label;
}
