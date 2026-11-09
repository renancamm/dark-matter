// SPDX-License-Identifier: MIT
// C2 near-miss: another MemoryMarshal member with plain type arguments (AsRef, which returns a reference into
// the bytes; GetReference). Only AsBytes, Cast, Read, Write and the Try forms are accepted: the rest of
// MemoryMarshal stays "Reads or writes memory directly" (Broad access).
using System;
using System.Runtime.InteropServices;

public static class MemoryMarshalOther {
    public static int AsRef(Span<byte> s) => MemoryMarshal.AsRef<int>(s);
    public static int Reference(Span<int> s) => MemoryMarshal.GetReference(s);
}
