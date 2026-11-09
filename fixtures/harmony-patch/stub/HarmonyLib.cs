// SPDX-License-Identifier: MIT
// Stand-ins for Harmony's attributes and the few members the cases use, with the real
// constructor signatures. Each constructor stores its arguments in "info" as Harmony's do.
using System;
using System.Reflection;

namespace HarmonyLib {
    public enum MethodType { Normal, Getter, Setter, Constructor, StaticConstructor, Enumerator, Async }

    public class HarmonyMethod {
        public MethodInfo method;
        public Type declaringType;
        public string methodName;
        public MethodType? methodType;
        public Type[] argumentTypes;
        public HarmonyMethod() { }
        public HarmonyMethod(MethodInfo method) { this.method = method; }
        public HarmonyMethod(Type methodType, string methodName, Type[] argumentTypes = null) { declaringType = methodType; this.methodName = methodName; this.argumentTypes = argumentTypes; }
    }

    public class HarmonyAttribute : Attribute {
        public HarmonyMethod info = new HarmonyMethod();
    }

    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
    public class HarmonyPatch : HarmonyAttribute {
        public HarmonyPatch() { }
        public HarmonyPatch(Type declaringType) { info.declaringType = declaringType; }
        public HarmonyPatch(Type declaringType, string methodName) { info.declaringType = declaringType; info.methodName = methodName; }
        public HarmonyPatch(Type declaringType, string methodName, params Type[] argumentTypes) { info.declaringType = declaringType; info.methodName = methodName; info.argumentTypes = argumentTypes; }
        public HarmonyPatch(Type declaringType, MethodType methodType) { info.declaringType = declaringType; info.methodType = methodType; }
        public HarmonyPatch(string methodName) { info.methodName = methodName; }
        public HarmonyPatch(string typeName, string methodName, MethodType methodType = MethodType.Normal) {
            info.declaringType = AccessTools.TypeByName(typeName);
            info.methodName = methodName;
            info.methodType = methodType;
        }
    }

    [AttributeUsage(AttributeTargets.Delegate, AllowMultiple = true)]
    public class HarmonyDelegate : HarmonyPatch {
        public HarmonyDelegate(Type declaringType, string methodName) : base(declaringType, methodName) { }
    }

    [AttributeUsage(AttributeTargets.Method)]
    public class HarmonyReversePatch : HarmonyAttribute { }

    // Gives a patch method's parameter the original's argument of that name or index instead of the one its own name would.
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method | AttributeTargets.Parameter, AllowMultiple = true)]
    public class HarmonyArgument : Attribute {
        public HarmonyArgument(string originalName) { }
        public HarmonyArgument(int index) { }
        public HarmonyArgument(string originalName, string newName) { }
    }

    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
    public class HarmonyPatchAll : HarmonyAttribute { }

    [AttributeUsage(AttributeTargets.Method)]
    public class HarmonyPrefix : Attribute { }

    [AttributeUsage(AttributeTargets.Method)]
    public class HarmonyTargetMethod : Attribute { }

    [AttributeUsage(AttributeTargets.Method)]
    public class HarmonyPostfix : Attribute { }

    // The instruction a transpiler reads and returns, with Harmony's public fields.
    public class CodeInstruction {
        public System.Reflection.Emit.OpCode opcode;
        public object operand;
        public CodeInstruction(System.Reflection.Emit.OpCode opcode, object operand = null) { this.opcode = opcode; this.operand = operand; }
    }

    public static class AccessTools {
        public static Type TypeByName(string name) => null;
        public static MethodInfo Method(Type type, string name, Type[] parameters = null, Type[] generics = null) => null;
        public static MethodInfo Method(string typeColonName, Type[] parameters = null, Type[] generics = null) => null;
        public static PropertyInfo Indexer(Type type, Type[] parameters = null) => null;
        public static FieldInfo Field(Type type, string name) => null;
        public static T MakeDeepCopy<T>(object source) where T : class => null;
        public static object MakeDeepCopy(object source, Type resultType, Func<string, Traverse, Traverse, object> processor = null, string pathRoot = "") => null;
    }

    public class Traverse {
        public static Traverse Create(Type type) => null;
        public static Traverse Create(object root) => null;
        public static Traverse CreateWithType(string name) => null;
        public Traverse Method(string name, params object[] arguments) => null;
        public Traverse Field(string name) => null;
        public object GetValue() => null;
    }

    // A transpiler helper that stores the operand it is given (as Harmony's does).
    public class CodeMatcher {
        readonly System.Collections.Generic.List<CodeInstruction> codes = new();
        int pos;
        public CodeMatcher(System.Collections.Generic.IEnumerable<CodeInstruction> instructions) { codes.AddRange(instructions); }
        public CodeMatcher SetOperandAndAdvance(object operand) { codes[pos].operand = operand; pos++; return this; }
        public ref object Operand => ref codes[pos].operand;
        public System.Collections.Generic.IEnumerable<CodeInstruction> InstructionEnumeration() => codes;
    }

    public class Harmony {
        public Harmony(string id) { }
        public void PatchAll() { }
        public MethodInfo Patch(MethodBase original, HarmonyMethod prefix = null, HarmonyMethod postfix = null, HarmonyMethod transpiler = null, HarmonyMethod finalizer = null) => null;
        public PatchProcessor CreateProcessor(MethodBase original) => new PatchProcessor(this, original);
        public static MethodInfo ReversePatch(MethodBase original, HarmonyMethod standin, MethodInfo transpiler = null) => null;
    }

    // Not Harmony's: a stand-in type with a nested type whose method of the same name starts a program,
    // for lookups by name on a nested type found from its outer one (reflection-precision TrustedNested*).
    public static class NestedHost {
        public static void Run() { }
        public static class Inner {
            public static void Run() => System.Diagnostics.Process.Start("example.invalid");
        }
    }

    // Not Harmony's: a stand-in base type whose static method starts a program, for a lookup on a mod type
    // deriving from it that finds the inherited method (reflection-precision InheritedTrusted*, H7b).
    public class StartsHost {
        public static void InheritedStart(string file) => System.Diagnostics.Process.Start(file);
    }

    // Manual patching of one original, with the patch methods added one by one.
    public class PatchProcessor {
        readonly MethodBase original;
        HarmonyMethod transpiler;
        public PatchProcessor(Harmony instance, MethodBase original) { this.original = original; }
        public PatchProcessor AddTranspiler(HarmonyMethod transpiler) { this.transpiler = transpiler; return this; }
        public MethodInfo Patch() => null;
    }
}
