// SPDX-License-Identifier: MIT
// H9 (policy 29): the [LibraryImport] marshallers copy data to unmanaged memory and free it: raw memory
// (before H9: unclassified, the members without a pointer in their signature).
using System;
using System.Runtime.InteropServices.Marshalling;

public static class MarshallerUse {
    public static void Copy(string s) {
        var m = new Utf8StringMarshaller.ManagedToUnmanagedIn();
        Span<byte> buffer = new byte[Utf8StringMarshaller.ManagedToUnmanagedIn.BufferSize];
        m.FromManaged(s, buffer);
        m.Free();
    }
}
