// SPDX-License-Identifier: MIT
// Probe case: a local holding a web address is replaced through a ref local taken before the address
// was stored, then handed to the shell. What starts is a program, not the web address.
// Expected: Broad access, "Starts other programs" (it was "Opens websites in your browser" before policy 20).
using System.Diagnostics;

public static class AliasedUrl {
    public static void Open() {
        string target = null;
        ref string alias = ref target;
        target = "https://example.invalid/";
        alias = "example-program";
        Process.Start(new ProcessStartInfo(target) { UseShellExecute = true });
    }
}
