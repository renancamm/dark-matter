// SPDX-License-Identifier: MIT
// H9 (policy 29): the game's own process and its start time (a per-launch token): Limited access, nothing
// labelled (before H9: unclassified).
using System.Diagnostics;

public static class OwnProcessStart {
    public static long LaunchToken() {
        using var self = Process.GetCurrentProcess();
        return self.StartTime.Ticks ^ self.Id;
    }
}
