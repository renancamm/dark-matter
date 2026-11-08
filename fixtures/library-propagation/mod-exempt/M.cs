// SPDX-License-Identifier: MIT
// Calls a library member that builds code at run time. Full access, unless the policy exempts
// that member's code generation (the test policy does, the built-in one does not).
namespace PropagationModExempt {
    public class Mod {
        public int Run() => ToolHelper.Compiler.Constant(42)();
    }
}
