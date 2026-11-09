// SPDX-License-Identifier: MIT
// Helper for ValueByName (D5): another assembly of the same mod that defines a type named like the game's
// KSA.Universe, whose field Current is declared as object. Analyzed only together with ValueByName.
#pragma warning disable CS0436  // the name of a type the referenced game stand-in also has, on purpose
namespace KSA {
    public class Universe {
        public object Current = new();
    }
}
