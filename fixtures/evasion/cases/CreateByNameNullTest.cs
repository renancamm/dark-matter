// SPDX-License-Identifier: MIT
// H9 review negative: Assembly.CreateInstance by a name with no assembly part runs the constructor of
// whatever type it finds before its result is tested for null or dropped, so the H9 null-test exception
// (a lookup only) does not apply: still "Calls code that was not analyzed" (H9 had made it Limited access).
using System;
using System.Reflection;

public static class CreateByNameNullTest {
    public static void Dropped(Assembly asm) { asm.CreateInstance("OtherMod.Feature"); }
    public static bool Tested(Assembly asm) => asm.CreateInstance("OtherMod.Feature") != null;
}
