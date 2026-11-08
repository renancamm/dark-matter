// SPDX-License-Identifier: MIT
// Access the analyzer cannot inspect. Every case here must place the assembly in Full access.
using System;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

public class FailOpenCases {
    // P/Invoke: calls native code that is not part of the assembly.
    [DllImport("libc", EntryPoint = "getpid")] static extern int GetPid();
    public int ViaPInvoke() => GetPid();

    // COM activation by CLSID: instantiates a component by GUID, with no type name in the IL.
    [SupportedOSPlatform("windows")]
    public object ViaComClsid() {
        var t = Type.GetTypeFromCLSID(new Guid("72C24DD5-D70A-438B-8A42-98424B88AFB8"));  // WScript.Shell
        return Activator.CreateInstance(t);
    }
}
