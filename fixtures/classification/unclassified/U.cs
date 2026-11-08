// SPDX-License-Identifier: MIT
// A framework member the policy does not classify. AppContext.SetSwitch changes runtime
// behaviour, here re-enabling an unsafe serializer, and is deliberately left out of the policy
// (see the comment on "safe"). The check cannot say what it does, so the mod is Full access.
using System;

public class UnclassifiedFramework {
    public static void Enable() => AppContext.SetSwitch("System.Runtime.Serialization.EnableUnsafeBinaryFormatterSerialization", true);
}
