// SPDX-License-Identifier: MIT
// A type named with an assembly qualifier that is another mod's assembly, which this check does not
// analyze with this mod (it is neither shipped here, the game, the framework nor a trusted library).
// Expected: Broad access, couldn't be fully checked, "Calls code that was not analyzed" only.
using System;

public static class OtherModBridge {
    public static object? Create() => Activator.CreateInstance(Type.GetType("OtherMod.Tools, OtherMod", true)!);
}
