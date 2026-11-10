// SPDX-License-Identifier: MIT
// Control (policy 39): pointers the game returned, only kept in locals, passed back to game members and to the
// mod's own method as the same pointer type, and read through for fields of the type they point to. The mod
// never makes an address up or writes through one. Expected: Limited access, no label.
public static unsafe class GamePointerPassedOn {
    public static float Width() {
        KSA.Viewport* viewport = KSA.Ui.GetMainViewport();
        KSA.ViewportPtr wrapped = viewport;
        KSA.Ui.Use(wrapped);
        KSA.Ui.SetNextPos(in viewport->Pos);
        return Left(viewport) + viewport->Size.X + viewport->Id;
    }

    static float Left(KSA.Viewport* viewport) => viewport == null ? 0 : viewport->Pos.X;
}
