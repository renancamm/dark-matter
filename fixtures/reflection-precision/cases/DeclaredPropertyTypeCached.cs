// SPDX-License-Identifier: MIT
// Probe (D6, policy 35): PropertyInfo.PropertyType of a cached game property (a static field, read in another
// method) is that property's declared type; the method found on it copies to the clipboard. Expected: Limited
// access, "Uses your clipboard" (before: "Uses reflection the check cannot trace").
using System.Reflection;

public static class DeclaredPropertyTypeCached {
    static readonly PropertyInfo Focus = typeof(KSA.Universe).GetProperty("Focus")!;

    public static void Go(object craft) => Focus.PropertyType.GetMethod("Rename")!.Invoke(craft, ["name"]);
}
