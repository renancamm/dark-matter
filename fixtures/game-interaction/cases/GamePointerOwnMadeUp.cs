// SPDX-License-Identifier: MIT
// Control (policy 39): the mod's own method trusts its pointer argument, so a call that gives it a pointer
// made from a number is raw memory at the call. Expected: Broad access, deep game access.
public static unsafe class GamePointerOwnMadeUp {
    public static int Read(nint address) => Id((KSA.Viewport*)address);

    static int Id(KSA.Viewport* viewport) => viewport->Id;
}
