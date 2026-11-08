// SPDX-License-Identifier: MIT
// Probe case: a Marshal member that reads memory. Expected: Full access.
using System;
using System.Runtime.InteropServices;

public class PeekCase {
    public static string Run(IntPtr p) => Marshal.PtrToStringAnsi(p);
}
