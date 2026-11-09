// SPDX-License-Identifier: MIT
// AccessTools.MakeDeepCopy into the run-time type of an object of unknown type, which the check cannot
// trace. Expected: Broad access, "Uses reflection the check cannot trace" (G5a).
using HarmonyLib;

public static class Copier {
    public static object Copy(object source) => AccessTools.MakeDeepCopy(source, source.GetType());
}
