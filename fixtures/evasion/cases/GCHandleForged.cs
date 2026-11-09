// SPDX-License-Identifier: MIT
// H9 (policy 29): a GCHandle made from a native int reads whatever object reference the handle slot at
// that address holds: raw memory (before H9: unclassified).
using System;
using System.Runtime.InteropServices;

public static class GCHandleForged {
    public static object? Read(IntPtr p) => GCHandle.FromIntPtr(p).Target;
}
