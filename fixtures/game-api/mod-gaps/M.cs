// SPDX-License-Identifier: MIT
// Calls game members the game-API map has not read: one that reaches a game method whose body the
// check cannot decode, and one the game build profiled does not define (the harness patches a copy of
// the game stand-in for both). Kept is a game member that exists and reaches nothing. The last three
// call members the derived game types declare themselves; the harness renames them in a copy of this
// mod to a member of the game base type, one of the framework base type and one neither has.
namespace GameApiModGaps {
    public class Mod {
        public int Read(int x) => KSA.Unreadable.Caller(x);
        public void Old() => KSA.Vanishing.RemovedInThisBuild();
        public void Fine() => KSA.Vanishing.Kept();
        public void Inherited(string file) => KSA.StartsDerived.DeclaredHere(file);
        public void FromFramework(KSA.ListDerived list) => list.OwnTrimmer();
        public void Nowhere(KSA.ListDerived list) => list.OwnMissing();

        // Controls: references that name the mod's own types are its own code (a generic type's
        // members, and those of a multi-dimensional array of its own type, which the runtime provides).
        public int Own() {
            var grid = new Cell[2, 2];
            grid[0, 1] = new Cell { Value = 1 };
            return grid[0, 1].Value + new Box<int>().Get() + grid.Length;
        }
    }

    public struct Cell {
        public int Value;
    }

    public class Box<T> {
        public T? Item;
        public T? Get() => Item;
    }
}
