// SPDX-License-Identifier: MIT
// H8 negative: GetExceptionForHR(int, IntPtr) takes an IErrorInfo pointer. Broad access, "Reads or writes
// memory directly" (NoMemoryErrors is the control with the int-only forms).
using System;
using System.Runtime.InteropServices;

public static class ErrorInfoIntPtr {
    public static Exception Describe(int code, IntPtr info) => Marshal.GetExceptionForHR(code, info);
}
