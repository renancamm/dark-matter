// SPDX-License-Identifier: MIT
// A Harmony delegate bound by attribute: AccessTools.HarmonyDelegate<T>() makes a delegate that
// calls the named method, here Process.Start. Expected: Full access.
using HarmonyLib;

[HarmonyDelegate(typeof(System.Diagnostics.Process), "Start")]
public delegate object StartDelegate(string fileName);
