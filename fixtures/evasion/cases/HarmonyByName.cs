// SPDX-License-Identifier: MIT
// Control: Harmony's "Type:Member" lookup with a constant name, then invoked. Expected: Known
// access, with the named type's capabilities ("Connects to the internet").
using HarmonyLib;

public class HarmonyByNameCase {
    public static object Run(object client, string url) =>
        AccessTools.Method("System.Net.Http.HttpClient:GetStringAsync", new[] { typeof(string) }).Invoke(client, new object[] { url });
}
