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
    }

    public class Traverse {
        public static Traverse Create(Type type) => null;
        public static Traverse CreateWithType(string name) => null;
        public Traverse Method(string name, params object[] arguments) => null;
        public object GetValue() => null;
    }

    public class Harmony {
        public Harmony(string id) { }
        public void PatchAll() { }
    }
}
