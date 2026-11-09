// SPDX-License-Identifier: MIT
// Probe case: the dynamic keyword binds members by name at run time. Expected: Broad access.
public class DynCase {
    public static object Run(dynamic o, string arg) => o.Start(arg);
}
