// SPDX-License-Identifier: MIT
// Capabilities with a Limited access label of their own.
using System;
using System.Diagnostics;
using System.Runtime.Versioning;
using Microsoft.Win32;

public class LabelCases {
    // Reads information about you and your computer
    public static string Who() => Environment.UserName + "@" + Environment.MachineName;
    public static string Path() => Environment.GetEnvironmentVariable("PATH");
    public static int Running() => Process.GetProcesses().Length;

    // Changes system settings
    [SupportedOSPlatform("windows")]
    public static void Remember() => Registry.CurrentUser.CreateSubKey("Software\\Example").SetValue("Seen", 1);
    public static void Persist() => Environment.SetEnvironmentVariable("EXAMPLE", "1", EnvironmentVariableTarget.User);

    // No label: affects only this process
    public static void ForThisProcess() => Environment.SetEnvironmentVariable("EXAMPLE", "1");

    // Closes other programs
    public static void Close(int pid) => Process.GetProcessById(pid).Kill();
}
