// SPDX-License-Identifier: MIT
// A framework member the policy does not classify (System.AppContext::SetSwitch), reached by
// reflection on a type named by a constant string rather than by a direct call.
// Expected: Full access, couldn't be fully checked, "Uses a part of .NET the check does not classify" only.
using System;

public static class SwitchByName {
    public static void Set() => Type.GetType("System.AppContext", true)!.GetMethod("SetSwitch")!.Invoke(null, ["Example.Switch", true]);
}
