// SPDX-License-Identifier: MIT
// Probe case: a delegate bound by method name on an object's run-time type. Expected: Full access.
using System;

public class DelegateByNameCase {
    public static Delegate Run(object target, string method) => Delegate.CreateDelegate(typeof(Action), target, method);
}
