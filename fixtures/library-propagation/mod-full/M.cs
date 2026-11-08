// SPDX-License-Identifier: MIT
// Calls a library member whose override starts a program: the mod is Full access through the
// library's profile.
namespace PropagationModFull {
    public class Mod {
        public void Run() => ToolHelper.Job.Create("example.invalid").Run();
    }
}
