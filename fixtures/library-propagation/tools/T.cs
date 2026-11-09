// SPDX-License-Identifier: MIT
// A trusted helper library: one member reaches a process start only through an override (Broad
// access), one builds code at run time (Broad access unless the policy exempts it).
using System.Diagnostics;
using System.Reflection.Emit;

namespace ToolHelper {
    // A call to Job.Run can dispatch to StartJob.Run, which the mod never names.
    public abstract class Job {
        public abstract void Run();
        public static Job Create(string target) => new StartJob(target);
    }

    sealed class StartJob(string target) : Job {
        public override void Run() => Process.Start(target);
    }

    public static class Compiler {
        public static Func<int> Constant(int value) {
            var dm = new DynamicMethod("Constant", typeof(int), Type.EmptyTypes);
            var il = dm.GetILGenerator();
            il.Emit(OpCodes.Ldc_I4, value);
            il.Emit(OpCodes.Ret);
            return dm.CreateDelegate<Func<int>>();
        }
    }
}
