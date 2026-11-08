// SPDX-License-Identifier: MIT
// The real API next to the transpiler control: a method built with DynamicMethod and ILGenerator.
// Expected: Full access, "Builds code at run time".
using System;
using System.Reflection.Emit;

public static class Builder {
    public static Func<int> Build() {
        var method = new DynamicMethod("Answer", typeof(int), Type.EmptyTypes);
        var il = method.GetILGenerator();
        il.Emit(OpCodes.Ldc_I4, 42);
        il.Emit(OpCodes.Ret);
        return (Func<int>)method.CreateDelegate(typeof(Func<int>));
    }
}
