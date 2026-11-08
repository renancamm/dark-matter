// SPDX-License-Identifier: MIT
// Carries one manifest resource (see embedded.csproj). The code reads nothing: what matters is
// what the assembly ships. A program, library or archive inside it is code the check did not
// read, so the mod is Full access whatever it does with the bytes.
namespace Embedded {
    public class Holder {
        public static int Answer() => 42;
    }
}
