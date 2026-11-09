// SPDX-License-Identifier: MIT
// Opens a fixed web address in the browser. Limited access: "Opens websites in your browser".
using System.Diagnostics;

public class Links {
    public static void OpenWiki() => Process.Start(new ProcessStartInfo { FileName = "https://example.invalid/wiki", UseShellExecute = true });
    public static void OpenSite() => Process.Start(new ProcessStartInfo("https://example.invalid/") { UseShellExecute = true });
}
