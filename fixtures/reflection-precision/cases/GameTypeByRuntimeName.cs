// SPDX-License-Identifier: MIT
// Control (policy 38): a game type found by a name built at run time, in a game assembly. The check knows the
// assembly but not the type, so it cannot list what the type's members do. Expected: Broad access, deep game
// access only, "Uses reflection on a game type chosen at run time".
public static class GameTypeByRuntimeName {
    public static object? Find(string suffix) => typeof(KSA.Vehicle).Assembly.GetType("KSA." + suffix);
}
