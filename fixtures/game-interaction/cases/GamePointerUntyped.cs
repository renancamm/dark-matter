// SPDX-License-Identifier: MIT
// Control (policy 39): a void pointer names no type to match what it is passed as, so it is not followed.
// Expected: Broad access, deep game access.
public static unsafe class GamePointerUntyped {
    public static void Pass() => KSA.Ui.UseRaw(KSA.Ui.Raw());
}
