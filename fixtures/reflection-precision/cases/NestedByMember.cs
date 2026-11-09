// SPDX-License-Identifier: MIT
// A game type's nested type found with GetMember(name), then a method of it invoked. GetMember
// finds nested types as well as members, so the name reaches the nested type's members. Expected:
// Broad access, "Starts other programs" (the nested type's method starts what it is given; G1a
// review A8).
using System;

public static class NestedByMember {
    public static void Go() => ((Type)typeof(KSA.Tools).GetMember("Shell")[0]).GetMethod("Run").Invoke(null, new object[] { "example.invalid" });
}
