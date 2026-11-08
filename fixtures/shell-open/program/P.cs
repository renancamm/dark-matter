// SPDX-License-Identifier: MIT
// Starts a program, or opens a link whose target is not fixed. Full access.
using System.Diagnostics;

public class Programs {
    public static void RunTool() => Process.Start("tool.exe", "--flag");
    public static void OpenAnything(string target) => Process.Start(new ProcessStartInfo { FileName = target, UseShellExecute = true });
}
