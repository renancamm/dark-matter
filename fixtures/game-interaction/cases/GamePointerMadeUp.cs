// SPDX-License-Identifier: MIT
// Control (policy 39): a game member given a pointer made from a number, not one the game returned.
// Expected: Broad access, deep game access, "Reads or writes memory directly".
public static unsafe class GamePointerMadeUp {
    public static void Use(nint address) => KSA.Ui.Use((KSA.Viewport*)address);
}
