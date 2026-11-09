// SPDX-License-Identifier: MIT
// Probe (H7 review, H7b): reflection on the mod's own type finds a member it inherits from a framework type
// (Process.Kill), which is reached as for reflection on the framework type itself. Expected: Broad access,
// "Starts other programs" (the policy's rules for Process; before: Limited access, nothing).
using System;
using System.Diagnostics;

internal class InheritedProcess : Process { }

public static class InheritedFrameworkEntry {
    public static void Go() => typeof(InheritedProcess).GetMethod("Kill", Type.EmptyTypes)!.Invoke(new InheritedProcess(), null);
}
