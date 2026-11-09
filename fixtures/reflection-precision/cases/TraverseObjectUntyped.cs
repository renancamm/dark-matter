// SPDX-License-Identifier: MIT
// Negative for H7's Traverse.Create(object): a Traverse made from a value declared only as object can be
// of any type, so what it runs is not traced. Expected (before and after H7): Full access, "Uses
// reflection the check cannot trace".
using HarmonyLib;

public static class TraverseAnything {
    public static object Run(object anything) => Traverse.Create(anything).Method("Run").GetValue();
}
