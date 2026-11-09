// SPDX-License-Identifier: MIT
// H8 (policy 27): the error-code helpers keep or format an error number; they touch no memory. Limited
// access, nothing labelled (before H8: raw memory, through the Marshal:: rule). ErrorInfoIntPtr is the
// negative: the forms that take an IErrorInfo pointer stay raw memory.
using System;
using System.Runtime.InteropServices;

public static class NoMemoryErrors {
    public static string Describe(int code) {
        Marshal.SetLastPInvokeError(code);
        Marshal.SetLastSystemError(code);
        int hr = Marshal.GetHRForLastWin32Error();
        Exception e = Marshal.GetExceptionForHR(hr);
        if (code < 0) Marshal.ThrowExceptionForHR(code);
        return Marshal.GetPInvokeErrorMessage(code) + (e == null ? "" : e.Message);
    }
}
