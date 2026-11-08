// SPDX-License-Identifier: MIT
// Probe case: Harmony's "Type:Member" lookup with a name built at run time. Expected: Full access.
using HarmonyLib;

public class HarmonyByRuntimeNameCase {
    public static object Run(string type, string method, object[] args) => AccessTools.Method(type + ":" + method).Invoke(null, args);
}
