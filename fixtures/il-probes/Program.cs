// SPDX-License-Identifier: MIT
// Writes hand-written-IL probe assemblies into the folder given as the only argument (H7; from the
// H1a review's generator). The test harness analyzes them; nothing written here is run. Each probe is
// benign: what it would call is harmless or never reached, and only the shape of its IL matters.
using System.Reflection;
using System.Reflection.Emit;

var outDir = args[0];
const BindingFlags NS = BindingFlags.NonPublic | BindingFlags.Static;
var getTypeFromHandle = typeof(Type).GetMethod("GetTypeFromHandle")!;
var getMethodStr = typeof(Type).GetMethod("GetMethod", [typeof(string)])!;
var getMethodFlags = typeof(Type).GetMethod("GetMethod", [typeof(string), typeof(BindingFlags)])!;
var getPropFlags = typeof(Type).GetMethod("GetProperty", [typeof(string), typeof(BindingFlags)])!;
var objGetType = typeof(object).GetMethod("GetType")!;
var invoke = typeof(MethodBase).GetMethod("Invoke", [typeof(object), typeof(object[])])!;
var setValue = typeof(PropertyInfo).GetMethod("SetValue", [typeof(object), typeof(object)])!;

(PersistedAssemblyBuilder, ModuleBuilder) Assembly(string name) {
    var ab = new PersistedAssemblyBuilder(new AssemblyName(name), typeof(object).Assembly);
    return (ab, ab.DefineDynamicModule(name));
}

// ProbeLoopStloc: a member array (holding a lookup on the probe's own type) is carried on the stack
// along a conditional backward branch. At the loop head a member found on an object's run-time type is
// stored into it through that stack copy; after the loop the array's element is invoked from the local.
// The fall-through copy is consumed by a stloc. Expected: Broad access, "Uses reflection the check cannot
// trace" (before H7: Limited access, nothing labelled: the stack copy along the backward branch was never
// dropped). ProbeStraight: the same store in straight-line code (control: Broad access, before and after).
foreach (var variant in new[] { "LoopStloc", "Straight" }) {
    var (ab, mb) = Assembly("Probe" + variant);
    var tb = mb.DefineType("Probe" + variant + "Code", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed);
    var noop = tb.DefineMethod("Noop", MethodAttributes.Private | MethodAttributes.Static, typeof(void), Type.EmptyTypes);
    noop.GetILGenerator().Emit(OpCodes.Ret);
    var go = tb.DefineMethod("Go", MethodAttributes.Public | MethodAttributes.Static, typeof(void), [typeof(object)]);
    var il = go.GetILGenerator();
    var arr = il.DeclareLocal(typeof(MethodInfo[]));
    var i = il.DeclareLocal(typeof(int));
    // arr = new MethodInfo[1]; arr[0] = typeof(Code).GetMethod("Noop", NonPublic|Static)
    il.Emit(OpCodes.Ldc_I4_1); il.Emit(OpCodes.Newarr, typeof(MethodInfo)); il.Emit(OpCodes.Stloc, arr);
    il.Emit(OpCodes.Ldloc, arr); il.Emit(OpCodes.Ldc_I4_0);
    il.Emit(OpCodes.Ldtoken, tb); il.Emit(OpCodes.Call, getTypeFromHandle);
    il.Emit(OpCodes.Ldstr, "Noop"); il.Emit(OpCodes.Ldc_I4, (int)NS); il.Emit(OpCodes.Callvirt, getMethodFlags);
    il.Emit(OpCodes.Stelem_Ref);
    if (variant == "LoopStloc") {
        var head = il.DefineLabel(); var skip = il.DefineLabel();
        il.Emit(OpCodes.Ldc_I4_0); il.Emit(OpCodes.Stloc, i);
        il.Emit(OpCodes.Ldnull);                                   // [null]
        il.MarkLabel(head);                                        // [x]: null, then arr
        il.Emit(OpCodes.Ldloc, i); il.Emit(OpCodes.Brfalse, skip); // first time round: no store
        il.Emit(OpCodes.Dup); il.Emit(OpCodes.Ldc_I4_0);
        il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Callvirt, objGetType);
        il.Emit(OpCodes.Ldstr, "Run"); il.Emit(OpCodes.Callvirt, getMethodStr);
        il.Emit(OpCodes.Stelem_Ref);                               // x[0] = o.GetType().GetMethod("Run")
        il.MarkLabel(skip);
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ldloc, i); il.Emit(OpCodes.Ldc_I4_1); il.Emit(OpCodes.Add); il.Emit(OpCodes.Stloc, i);
        il.Emit(OpCodes.Ldloc, arr);                               // [arr]
        il.Emit(OpCodes.Ldloc, i); il.Emit(OpCodes.Ldc_I4_2); il.Emit(OpCodes.Blt, head); // back with [arr]
        il.Emit(OpCodes.Stloc, il.DeclareLocal(typeof(MethodInfo[])));
    } else {
        il.Emit(OpCodes.Ldloc, arr); il.Emit(OpCodes.Ldc_I4_0);
        il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Callvirt, objGetType);
        il.Emit(OpCodes.Ldstr, "Run"); il.Emit(OpCodes.Callvirt, getMethodStr);
        il.Emit(OpCodes.Stelem_Ref);
    }
    il.Emit(OpCodes.Ldloc, arr); il.Emit(OpCodes.Ldc_I4_0); il.Emit(OpCodes.Ldelem_Ref);
    il.Emit(OpCodes.Ldnull); il.Emit(OpCodes.Ldnull); il.Emit(OpCodes.Callvirt, invoke); il.Emit(OpCodes.Pop);
    il.Emit(OpCodes.Ret);
    tb.CreateType();
    ab.Save(Path.Combine(outDir, "Probe" + variant + ".dll"));
}

// AccessorOdd: a property whose setter is a private method named Run, not set_P. The setter takes a Type
// and invokes a method found on it; it is reached only through GetProperty("P").SetValue, which runs the
// setter the metadata names. Expected: Broad access, "Uses reflection the check cannot trace" (a lookup by
// the property's name reaches its accessors whatever they are called; H7's F1 guard 3). AccessorPlain: the
// same with the setter named set_P (Broad access).
foreach (var variant in new[] { "Odd", "Plain" }) {
    var (ab, mb) = Assembly("Accessor" + variant);
    var r = mb.DefineType("AccessorHolder" + variant, TypeAttributes.NotPublic | TypeAttributes.Abstract | TypeAttributes.Sealed);
    var setter = r.DefineMethod(variant == "Odd" ? "Run" : "set_P", MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.HideBySig, typeof(void), [typeof(Type)]);
    var sil = setter.GetILGenerator();
    sil.Emit(OpCodes.Ldarg_0); sil.Emit(OpCodes.Ldstr, "Exit"); sil.Emit(OpCodes.Callvirt, getMethodStr);
    sil.Emit(OpCodes.Ldnull); sil.Emit(OpCodes.Ldnull); sil.Emit(OpCodes.Callvirt, invoke); sil.Emit(OpCodes.Pop); sil.Emit(OpCodes.Ret);
    var pb = r.DefineProperty("P", PropertyAttributes.None, typeof(Type), null);
    pb.SetSetMethod(setter);
    var e = mb.DefineType("AccessorEntry" + variant, TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed);
    var go = e.DefineMethod("Go", MethodAttributes.Public | MethodAttributes.Static, typeof(void), Type.EmptyTypes);
    var il = go.GetILGenerator();
    il.Emit(OpCodes.Ldtoken, r); il.Emit(OpCodes.Call, getTypeFromHandle);
    il.Emit(OpCodes.Ldstr, "P"); il.Emit(OpCodes.Ldc_I4, (int)NS); il.Emit(OpCodes.Callvirt, getPropFlags);
    il.Emit(OpCodes.Ldnull);
    il.Emit(OpCodes.Ldtoken, typeof(Math)); il.Emit(OpCodes.Call, getTypeFromHandle);
    il.Emit(OpCodes.Callvirt, setValue);
    il.Emit(OpCodes.Ret);
    r.CreateType(); e.CreateType();
    ab.Save(Path.Combine(outDir, "Accessor" + variant + ".dll"));
}

// BranchIntoInstruction: a branch to the second byte of a ldc.i4's operand. Read from there, the bytes
// are other instructions (nop, nop, ret) than the ones read in order. Expected: Broad access, "Contains code
// the check cannot read" (H7: a branch target must be an instruction).
{
    var (ab, mb) = Assembly("BranchIntoInstruction");
    var tb = mb.DefineType("BranchIntoInstructionCode", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed);
    var go = tb.DefineMethod("Go", MethodAttributes.Public | MethodAttributes.Static, typeof(void), Type.EmptyTypes);
    var il = go.GetILGenerator();
    il.Emit(OpCodes.Br_S, (sbyte)1);          // IL_0000: to IL_0003, inside the operand below
    il.Emit(OpCodes.Ldc_I4, 0x2A000000);      // IL_0002: 20 00 00 00 2A
    il.Emit(OpCodes.Pop);                     // IL_0007
    il.Emit(OpCodes.Ret);                     // IL_0008
    tb.CreateType();
    ab.Save(Path.Combine(outDir, "BranchIntoInstruction.dll"));
}
// Stackalloc of 1-byte elements with a variable count (H8): `n = arg; localloc n; new Span<T>(p, n)` with no
// multiply. StackallocByteIl (control): a Span<byte> of the same local, the same store: Limited access,
// nothing labelled. The negatives keep "Reads or writes memory directly" (Broad access): StackallocByteWide,
// a Span<int> (4-byte elements over n bytes); StackallocByteAliased, the count local's address is taken
// elsewhere in the method (it may change between the size and the length); StackallocByteRestored, the
// count is stored again between them; StackallocByteTruncated, the size is the count cut to a byte
// (conv.u1). Nothing generated is run; the span is only made and dropped.
foreach (var variant in new[] { "Il", "Wide", "Aliased", "Restored", "Truncated" }) {
    var (ab, mb) = Assembly("StackallocByte" + variant);
    var tb = mb.DefineType("StackallocByte" + variant + "Code", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed);
    var go = tb.DefineMethod("Go", MethodAttributes.Public | MethodAttributes.Static, typeof(void), [typeof(int)]);
    var il = go.GetILGenerator();
    var spanType = variant == "Wide" ? typeof(Span<int>) : typeof(Span<byte>);
    var ctor = spanType.GetConstructor([typeof(void*), typeof(int)])!;
    var n = il.DeclareLocal(typeof(int));
    var span = il.DeclareLocal(spanType);
    il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Stloc, n);
    if (variant == "Aliased") { il.Emit(OpCodes.Ldloca, n); il.Emit(OpCodes.Pop); il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Stloc, n); }
    il.Emit(OpCodes.Ldloc, n);
    il.Emit(variant == "Truncated" ? OpCodes.Conv_U1 : OpCodes.Conv_U);
    il.Emit(OpCodes.Localloc);
    if (variant == "Restored") { il.Emit(OpCodes.Ldc_I4, 1000); il.Emit(OpCodes.Stloc, n); }
    il.Emit(OpCodes.Ldloc, n);
    il.Emit(OpCodes.Newobj, ctor);
    il.Emit(OpCodes.Stloc, span);
    il.Emit(OpCodes.Ret);
    tb.CreateType();
    ab.Save(Path.Combine(outDir, "StackallocByte" + variant + ".dll"));
}
// H8 review: the span's length must be the count's own value. Each negative keeps "Reads or writes memory
// directly" (Broad access): StackallocByteSelfLength, the buffer is duplicated as its own length;
// StackallocByteReloaded, the buffer is kept in a native-int local and that local is loaded as buffer and
// length; StackallocByteScaledLength, the length is the count times 4 over a buffer of count bytes;
// StackallocByteZeroScale, the size is the count times 0, converted; StackallocCountReloaded, a byte count
// (count times 4, mul.ovf.un) kept in a local is the size and a Span<int>'s length (accepted since H4 before
// the review). StackallocCountControl is the compiler's Span<int> form (Limited access). Nothing generated
// is run.
foreach (var variant in new[] { "ByteSelfLength", "ByteReloaded", "ByteScaledLength", "ByteZeroScale", "CountReloaded", "CountControl" }) {
    var (ab, mb) = Assembly("Stackalloc" + variant);
    var tb = mb.DefineType("Stackalloc" + variant + "Code", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed);
    var go = tb.DefineMethod("Go", MethodAttributes.Public | MethodAttributes.Static, typeof(void), [typeof(int)]);
    var il = go.GetILGenerator();
    var spanType = variant.StartsWith("Count", StringComparison.Ordinal) ? typeof(Span<int>) : typeof(Span<byte>);
    var n = il.DeclareLocal(typeof(int));
    var span = il.DeclareLocal(spanType);
    il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Stloc, n);
    switch (variant) {
        case "ByteSelfLength":
            il.Emit(OpCodes.Ldloc, n); il.Emit(OpCodes.Conv_U); il.Emit(OpCodes.Localloc); il.Emit(OpCodes.Dup);
            break;
        case "ByteReloaded":
            var p = il.DeclareLocal(typeof(IntPtr));
            il.Emit(OpCodes.Ldloc, n); il.Emit(OpCodes.Conv_U); il.Emit(OpCodes.Localloc); il.Emit(OpCodes.Stloc, p);
            il.Emit(OpCodes.Ldloc, p); il.Emit(OpCodes.Ldloc, p);
            break;
        case "ByteScaledLength":
            il.Emit(OpCodes.Ldloc, n); il.Emit(OpCodes.Conv_U); il.Emit(OpCodes.Localloc);
            il.Emit(OpCodes.Ldloc, n); il.Emit(OpCodes.Ldc_I4_4); il.Emit(OpCodes.Mul_Ovf_Un);
            break;
        case "ByteZeroScale":
            il.Emit(OpCodes.Ldloc, n); il.Emit(OpCodes.Ldc_I4_0); il.Emit(OpCodes.Mul_Ovf_Un); il.Emit(OpCodes.Conv_U); il.Emit(OpCodes.Localloc);
            il.Emit(OpCodes.Ldloc, n);
            break;
        case "CountReloaded":
            var q = il.DeclareLocal(typeof(int));
            il.Emit(OpCodes.Ldloc, n); il.Emit(OpCodes.Ldc_I4_4); il.Emit(OpCodes.Mul_Ovf_Un); il.Emit(OpCodes.Stloc, q);
            il.Emit(OpCodes.Ldloc, q); il.Emit(OpCodes.Localloc); il.Emit(OpCodes.Ldloc, q);
            break;
        default:  // CountControl
            il.Emit(OpCodes.Ldloc, n); il.Emit(OpCodes.Conv_U); il.Emit(OpCodes.Ldc_I4_4); il.Emit(OpCodes.Mul_Ovf_Un); il.Emit(OpCodes.Localloc);
            il.Emit(OpCodes.Ldloc, n);
            break;
    }
    il.Emit(OpCodes.Newobj, spanType.GetConstructor([typeof(void*), typeof(int)])!);
    il.Emit(OpCodes.Stloc, span);
    il.Emit(OpCodes.Ret);
    tb.CreateType();
    ab.Save(Path.Combine(outDir, "Stackalloc" + variant + ".dll"));
}
// H9 (H8 review): a delegate constructed with newobj Action::.ctor(object, IntPtr) calls the code address it
// is given. DelegateFromInt: the address is the method's argument (no ldftn or ldvirtftn made it): native
// code (before H9: Limited access, nothing labelled). DelegateFromLdftn, the control: the pointers come
// straight from ldftn of a framework method (Console.WriteLine()) and ldvirtftn (object.ToString), as C#
// emits for method groups: Limited access, nothing labelled. Nothing generated is run.
foreach (var variant in new[] { "FromInt", "FromLdftn" }) {
    var (ab, mb) = Assembly("Delegate" + variant);
    var tb = mb.DefineType("Delegate" + variant + "Code", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed);
    var go = tb.DefineMethod("Go", MethodAttributes.Public | MethodAttributes.Static, typeof(void), [typeof(IntPtr)]);
    var il = go.GetILGenerator();
    var actionCtor = typeof(Action).GetConstructor([typeof(object), typeof(IntPtr)])!;
    il.Emit(OpCodes.Ldnull);
    if (variant == "FromInt") il.Emit(OpCodes.Ldarg_0);
    else il.Emit(OpCodes.Ldftn, typeof(Console).GetMethod("WriteLine", Type.EmptyTypes)!);
    il.Emit(OpCodes.Newobj, actionCtor);
    il.Emit(OpCodes.Callvirt, typeof(Action).GetMethod("Invoke")!);
    if (variant == "FromLdftn") {
        il.Emit(OpCodes.Ldstr, "x"); il.Emit(OpCodes.Dup);
        il.Emit(OpCodes.Ldvirtftn, typeof(object).GetMethod("ToString")!);
        il.Emit(OpCodes.Newobj, typeof(Func<string>).GetConstructor([typeof(object), typeof(IntPtr)])!);
        il.Emit(OpCodes.Callvirt, typeof(Func<string>).GetMethod("Invoke")!);
        il.Emit(OpCodes.Pop);
    }
    il.Emit(OpCodes.Ret);
    tb.CreateType();
    ab.Save(Path.Combine(outDir, "Delegate" + variant + ".dll"));
}
// H10b review: a member reference names the probe's own type, which derives from Process and declares Kill(int),
// for Kill() (the signature Process.Kill has): the runtime looks a member reference up by name and signature
// through the base types, so it runs Process.Kill(). OverloadOwnType is written calling Process::Kill() and then
// has that reference's parent changed to the probe's type: Broad access, "Calls code that was not analyzed" (before:
// Limited access, nothing labelled; a member of that name made it the mod's own code). OverloadOwnMatch, the
// control, calls its own generic type's Kill(int) through an instantiation (the reference C# writes, with the
// definition's signature): Limited access, nothing labelled. OverloadOwnInherited (H5 review fix 3, which had no
// fixture): the same reference through a type that declares no Kill at all: Broad access, "Calls code that was not
// analyzed". Nothing generated is run.
foreach (var variant in new[] { "OwnType", "OwnMatch", "OwnInherited" }) {
    var (ab, mb) = Assembly("Overload" + variant);
    var p = mb.DefineType("OverloadProcess" + variant, TypeAttributes.Public, typeof(System.Diagnostics.Process));
    if (variant == "OwnMatch") p.DefineGenericParameters("T");
    p.DefineDefaultConstructor(MethodAttributes.Public);
    var kill = p.DefineMethod(variant == "OwnInherited" ? "Stop" : "Kill", MethodAttributes.Public | MethodAttributes.HideBySig, typeof(void), [typeof(int)]);
    kill.GetILGenerator().Emit(OpCodes.Ret);
    var tb = mb.DefineType("Overload" + variant + "Code", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed);
    var go = tb.DefineMethod("Go", MethodAttributes.Public | MethodAttributes.Static, typeof(void), [typeof(System.Diagnostics.Process)]);
    var il = go.GetILGenerator();
    il.Emit(OpCodes.Ldarg_0);
    if (variant != "OwnMatch") {
        il.Emit(OpCodes.Callvirt, typeof(System.Diagnostics.Process).GetMethod("Kill", Type.EmptyTypes)!);
    } else {
        il.Emit(OpCodes.Ldc_I4_0);
        il.Emit(OpCodes.Callvirt, TypeBuilder.GetMethod(p.MakeGenericType(typeof(int)), kill));
    }
    il.Emit(OpCodes.Ret);
    p.CreateType();
    tb.CreateType();
    var path = Path.Combine(outDir, "Overload" + variant + ".dll");
    ab.Save(path);
    if (variant != "OwnMatch") ReparentMemberRef(path, "Kill", "Process", "OverloadProcess" + variant);
}

// H12: a member reference through the probe's own generic type whose signature names the type of the parameter
// another way than the definition does (a type reference into the probe itself, where the definition has the type
// definition; a merged assembly does the same with mscorlib's and netstandard's System.Exception). The probe type
// derives from Process and declares Kill(OverloadMarker...); the call is written with that definition's signature,
// then pointed at the signature of Stop(StringBuilder) after StringBuilder's type reference is turned into a
// reference into the probe. OverloadOwnEquivalent names OverloadMarkerOwnEquivalent there, the same type: the
// probe's own Kill, Limited access, nothing labelled (before H12: Broad access, "Calls code that was not analyzed",
// the blobs differ). OverloadOwnUnresolved names a type the probe does not define ("Stop"), which no definition
// matches: Broad access, "Calls code that was not analyzed". Nothing generated is run.
foreach (var variant in new[] { "OwnEquivalent", "OwnUnresolved" }) {
    var (ab, mb) = Assembly("Overload" + variant);
    var marker = mb.DefineType("OverloadMarker" + variant, TypeAttributes.Public);
    var p = mb.DefineType("OverloadProcess" + variant, TypeAttributes.Public, typeof(System.Diagnostics.Process));
    p.DefineGenericParameters("T");
    p.DefineDefaultConstructor(MethodAttributes.Public);
    var kill = p.DefineMethod("Kill", MethodAttributes.Public | MethodAttributes.HideBySig, typeof(void), [marker]);
    kill.GetILGenerator().Emit(OpCodes.Ret);
    var stop = p.DefineMethod("Stop", MethodAttributes.Public | MethodAttributes.HideBySig, typeof(void), [typeof(System.Text.StringBuilder)]);
    stop.GetILGenerator().Emit(OpCodes.Ret);
    var tb = mb.DefineType("Overload" + variant + "Code", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed);
    var go = tb.DefineMethod("Go", MethodAttributes.Public | MethodAttributes.Static, typeof(void), [typeof(System.Diagnostics.Process)]);
    var il = go.GetILGenerator();
    il.Emit(OpCodes.Ldarg_0);
    il.Emit(OpCodes.Ldnull);
    il.Emit(OpCodes.Callvirt, TypeBuilder.GetMethod(p.MakeGenericType(typeof(int)), kill));
    il.Emit(OpCodes.Ret);
    marker.CreateType();
    p.CreateType();
    tb.CreateType();
    var path = Path.Combine(outDir, "Overload" + variant + ".dll");
    ab.Save(path);
    RenameTypeRefSignature(path, "StringBuilder", variant == "OwnEquivalent" ? "OverloadMarker" + variant : "Stop", "Kill", "Stop");
}

// B review (direct memory access): cpblk and initblk copy or fill a caller-chosen number of bytes from a
// destination address. A managed address bounds a single ldind/stind to one value of its type, but it does
// not bound the byte-count operand of these two, so a length past the destination is an out-of-bounds write
// from a valid managed address. Before this review the check flagged them only when the destination address
// was not a managed reference, so a block copy or fill through the address of a local (ldloca) was Limited
// access. CpblkManaged and InitblkManaged are that gap (Limited before, Broad access / "Reads or writes memory
// directly" now); CpblkForged, the near-miss, fills from a native int the method is handed and stayed Broad
// access throughout. The C# compiler never emits a bare cpblk/initblk. Nothing generated is run.
foreach (var variant in new[] { "CpblkManaged", "CpblkForged", "InitblkManaged" }) {
    var (ab, mb) = Assembly(variant);
    var tb = mb.DefineType(variant + "Code", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed);
    bool forged = variant == "CpblkForged";
    var go = tb.DefineMethod("Go", MethodAttributes.Public | MethodAttributes.Static, typeof(void), forged ? [typeof(IntPtr)] : Type.EmptyTypes);
    var il = go.GetILGenerator();
    var dest = il.DeclareLocal(typeof(long));  // a 16-byte buffer; the blit length below runs well past it
    var dest2 = il.DeclareLocal(typeof(long));
    var src = il.DeclareLocal(typeof(long));
    var src2 = il.DeclareLocal(typeof(long));
    // destination address
    if (forged) il.Emit(OpCodes.Ldarg_0);        // a native int the caller chose: not a managed reference
    else il.Emit(OpCodes.Ldloca, dest);          // the address of a local: a managed reference
    if (variant == "InitblkManaged") {
        il.Emit(OpCodes.Ldc_I4_0);               // fill byte
        il.Emit(OpCodes.Ldc_I4, 4096);           // length, past the 16-byte destination
        il.Emit(OpCodes.Initblk);
    } else {
        il.Emit(OpCodes.Ldloca, src);            // source address (a managed reference)
        il.Emit(OpCodes.Ldc_I4, 4096);           // length, past the 16-byte destination
        il.Emit(OpCodes.Cpblk);
    }
    il.Emit(OpCodes.Ret);
    tb.CreateType();
    ab.Save(Path.Combine(outDir, variant + ".dll"));
}

// C review (policy 34), C4: the stackalloc-initializer shapes by hand, with each bound broken by one unit. The
// controls are the compiler's shapes (Limited access): a 4-byte store at offset 4 of an 8-byte buffer (InitStoreIl),
// a fill of 8 bytes (InitblkIl), a copy of 8 bytes from 8 bytes of constant data by its address (CpblkIl), and a copy
// of 8 bytes from the first element of the ReadOnlySpan<int> RuntimeHelpers.CreateSpan made over them
// (CreateSpanIl). The near-misses keep "Reads or writes memory directly": a store at offset 5 (InitStoreOffByOne,
// ends at 9) or at offset 8 (InitStorePastEnd), a reference stored into the buffer (InitStoreRef: stack memory the
// collector does not scan), a fill of 9 bytes (InitblkOverrun), a copy of 8 bytes into a 4-byte buffer
// (CpblkOverrun), a copy of 16 bytes from 8 bytes of data (CpblkSourceShort), and a copy of 8 bytes from the span's
// second element, past which only 4 bytes remain (CreateSpanIndexOverrun). The constant data lives in a
// <PrivateImplementationDetails> type, as the compiler's does. Nothing generated is run.
foreach (var variant in new[] { "InitStoreIl", "InitStoreOffByOne", "InitStorePastEnd", "InitStoreRef", "InitblkIl", "InitblkOverrun",
                                "CpblkIl", "CpblkOverrun", "CpblkSourceShort", "CreateSpanIl", "CreateSpanIndexOverrun" }) {
    var (ab, mb) = Assembly(variant);
    var details = mb.DefineType("<PrivateImplementationDetails>", TypeAttributes.NotPublic | TypeAttributes.Abstract | TypeAttributes.Sealed);
    var data = details.DefineInitializedData("D8", [1, 0, 0, 0, 2, 0, 0, 0], FieldAttributes.Assembly | FieldAttributes.Static);
    var tb = mb.DefineType(variant + "Code", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed);
    var go = tb.DefineMethod("Go", MethodAttributes.Public | MethodAttributes.Static, typeof(void), Type.EmptyTypes);
    var il = go.GetILGenerator();
    int size = variant == "CpblkOverrun" ? 4 : variant == "CpblkSourceShort" ? 16 : 8;
    il.Emit(OpCodes.Ldc_I4, size); il.Emit(OpCodes.Conv_U); il.Emit(OpCodes.Localloc);   // the buffer
    switch (variant) {
        case "InitStoreIl" or "InitStoreOffByOne" or "InitStorePastEnd":
            il.Emit(OpCodes.Dup); il.Emit(OpCodes.Ldc_I4, variant == "InitStoreIl" ? 4 : variant == "InitStoreOffByOne" ? 5 : 8); il.Emit(OpCodes.Add);
            il.Emit(OpCodes.Ldc_I4_1); il.Emit(OpCodes.Stind_I4);
            break;
        case "InitStoreRef":
            il.Emit(OpCodes.Dup); il.Emit(OpCodes.Ldnull); il.Emit(OpCodes.Stind_Ref);
            break;
        case "InitblkIl" or "InitblkOverrun":
            il.Emit(OpCodes.Dup); il.Emit(OpCodes.Ldc_I4_0); il.Emit(OpCodes.Ldc_I4, variant == "InitblkIl" ? 8 : 9); il.Emit(OpCodes.Initblk);
            break;
        case "CpblkIl" or "CpblkOverrun" or "CpblkSourceShort":
            il.Emit(OpCodes.Dup); il.Emit(OpCodes.Ldsflda, data); il.Emit(OpCodes.Ldc_I4, variant == "CpblkSourceShort" ? 16 : 8); il.Emit(OpCodes.Cpblk);
            break;
        default: {  // CreateSpanIl, CreateSpanIndexOverrun
            var span = il.DeclareLocal(typeof(ReadOnlySpan<int>));
            il.Emit(OpCodes.Dup);
            il.Emit(OpCodes.Ldtoken, data);
            il.Emit(OpCodes.Call, typeof(System.Runtime.CompilerServices.RuntimeHelpers).GetMethod("CreateSpan")!.MakeGenericMethod(typeof(int)));
            il.Emit(OpCodes.Stloc, span);
            il.Emit(OpCodes.Ldloca, span); il.Emit(variant == "CreateSpanIl" ? OpCodes.Ldc_I4_0 : OpCodes.Ldc_I4_1);
            il.Emit(OpCodes.Call, typeof(ReadOnlySpan<int>).GetProperty("Item")!.GetMethod!);
            il.Emit(OpCodes.Ldc_I4_8); il.Emit(OpCodes.Cpblk);
            break;
        }
    }
    il.Emit(OpCodes.Pop);  // the buffer
    il.Emit(OpCodes.Ret);
    details.CreateType(); tb.CreateType();
    ab.Save(Path.Combine(outDir, variant + ".dll"));
}

// C review (policy 34), C1: a Span<E> of an enum E over a stackalloc buffer, by hand. EnumSpanIl is the compiler's
// shape (8 int-sized elements over 32 bytes): Limited access. EnumSpanOverrun asks for 8 elements over 16 bytes, and
// EnumSpanLongOverrun for 8 long-sized elements over 32 bytes: both keep "Reads or writes memory directly".
// Nothing generated is run.
foreach (var variant in new[] { "EnumSpanIl", "EnumSpanOverrun", "EnumSpanLongOverrun" }) {
    var (ab, mb) = Assembly(variant);
    var hue = mb.DefineEnum("Hue" + variant, TypeAttributes.Public, variant == "EnumSpanLongOverrun" ? typeof(long) : typeof(int));
    hue.DefineLiteral("Red", variant == "EnumSpanLongOverrun" ? 0L : 0);
    var hueType = hue.CreateType()!;
    var spanType = typeof(Span<>).MakeGenericType(hueType);
    var tb = mb.DefineType(variant + "Code", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed);
    var go = tb.DefineMethod("Go", MethodAttributes.Public | MethodAttributes.Static, typeof(void), Type.EmptyTypes);
    var il = go.GetILGenerator();
    var span = il.DeclareLocal(spanType);
    il.Emit(OpCodes.Ldc_I4, variant == "EnumSpanOverrun" ? 16 : 32); il.Emit(OpCodes.Conv_U); il.Emit(OpCodes.Localloc);
    il.Emit(OpCodes.Ldc_I4_8);
    il.Emit(OpCodes.Newobj, TypeBuilder.GetConstructor(spanType, typeof(Span<>).GetConstructor([typeof(void*), typeof(int)])!));
    il.Emit(OpCodes.Stloc, span);
    il.Emit(OpCodes.Ret);
    tb.CreateType();
    ab.Save(Path.Combine(outDir, variant + ".dll"));
}

// D review (policy 35), D5: what is read through a member is typed only from a member of the kind the read is made
// on, whose declared type is one class. Holder's static field Target and property P are declared as the probe's own
// class Runner, whose Run method is then invoked on the run-time type of the value read. ValueKindField (control):
// FieldInfo.GetValue of the field: deep game access only (bounded to Runner). ValueKindMismatch: PropertyInfo.GetValue
// called on that FieldInfo (unverifiable IL): the value is not typed, "Uses reflection the check cannot trace".
// PropertyGetterMatch (control): PropertyInfo.GetValue of P, whose getter returns Runner: deep game access only.
// PropertyGetterMismatch: P's signature says Runner, its getter returns object (hand-written metadata; GetValue runs
// the getter): not typed, "Uses reflection the check cannot trace". Nothing generated is run.
var getFieldStr = typeof(Type).GetMethod("GetField", [typeof(string)])!;
var getPropertyStr = typeof(Type).GetMethod("GetProperty", [typeof(string)])!;
var fieldGetValue = typeof(FieldInfo).GetMethod("GetValue", [typeof(object)])!;
var propertyGetValue = typeof(PropertyInfo).GetMethod("GetValue", [typeof(object)])!;
foreach (var variant in new[] { "ValueKindField", "ValueKindMismatch", "PropertyGetterMatch", "PropertyGetterMismatch" }) {
    var (ab, mb) = Assembly(variant);
    var runner = mb.DefineType(variant + "Runner", TypeAttributes.Public);
    runner.DefineMethod("Run", MethodAttributes.Public, typeof(void), Type.EmptyTypes).GetILGenerator().Emit(OpCodes.Ret);
    var holder = mb.DefineType(variant + "Holder", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed);
    var target = holder.DefineField("Target", runner, FieldAttributes.Public | FieldAttributes.Static);
    bool property = variant.StartsWith("Property", StringComparison.Ordinal);
    if (property) {
        var getter = holder.DefineMethod("get_P", MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.HideBySig,
            variant == "PropertyGetterMismatch" ? typeof(object) : runner, Type.EmptyTypes);
        var gil = getter.GetILGenerator();
        gil.Emit(OpCodes.Ldsfld, target); gil.Emit(OpCodes.Ret);
        holder.DefineProperty("P", PropertyAttributes.None, runner, null).SetGetMethod(getter);
    }
    var go = holder.DefineMethod("Go", MethodAttributes.Public | MethodAttributes.Static, typeof(void), Type.EmptyTypes);
    var il = go.GetILGenerator();
    il.Emit(OpCodes.Ldtoken, holder); il.Emit(OpCodes.Call, getTypeFromHandle);
    il.Emit(OpCodes.Ldstr, property ? "P" : "Target"); il.Emit(OpCodes.Callvirt, property ? getPropertyStr : getFieldStr);
    il.Emit(OpCodes.Ldnull); il.Emit(OpCodes.Callvirt, variant == "ValueKindField" ? fieldGetValue : propertyGetValue);
    il.Emit(OpCodes.Callvirt, objGetType);
    il.Emit(OpCodes.Ldstr, "Run"); il.Emit(OpCodes.Callvirt, getMethodStr);
    il.Emit(OpCodes.Ldnull); il.Emit(OpCodes.Ldnull); il.Emit(OpCodes.Callvirt, invoke); il.Emit(OpCodes.Pop);
    il.Emit(OpCodes.Ret);
    runner.CreateType(); holder.CreateType();
    ab.Save(Path.Combine(outDir, variant + ".dll"));
}

// Turns the type reference `typeRef` into a reference to the type named `to` in the file itself (scope: this
// module; `to` must already be in the string heap), and points the signature of the member reference `member`
// at the signature of the method `like` defined in the file, in place.
static void RenameTypeRefSignature(string path, string typeRef, string to, string member, string like) {
    var bytes = File.ReadAllBytes(path);
    using (var pe = new System.Reflection.PortableExecutable.PEReader(new MemoryStream(bytes))) {
        var md = System.Reflection.Metadata.PEReaderExtensions.GetMetadataReader(pe);
        var trs = md.TypeReferences.Where(h => md.GetString(md.GetTypeReference(h).Name) == typeRef).ToList();
        var names = md.TypeDefinitions.Select(h => md.GetTypeDefinition(h).Name).Concat(md.MethodDefinitions.Select(h => md.GetMethodDefinition(h).Name))
            .Where(n => md.GetString(n) == to).Distinct().ToList();
        var refs = md.MemberReferences.Where(h => md.GetString(md.GetMemberReference(h).Name) == member).ToList();
        var likes = md.MethodDefinitions.Where(h => md.GetString(md.GetMethodDefinition(h).Name) == like).ToList();
        var trTable = System.Reflection.Metadata.Ecma335.TableIndex.TypeRef;
        var mrTable = System.Reflection.Metadata.Ecma335.TableIndex.MemberRef;
        if (trs.Count != 1 || names.Count != 1 || refs.Count != 1 || likes.Count != 1
            || System.Reflection.Metadata.Ecma335.MetadataReaderExtensions.GetTableRowSize(md, trTable) != 6
            || System.Reflection.Metadata.Ecma335.MetadataReaderExtensions.GetTableRowSize(md, mrTable) != 6) throw new InvalidOperationException($"{path}: unexpected metadata layout");
        static void Put(byte[] b, int at, int v) { b[at] = (byte)v; b[at + 1] = (byte)(v >> 8); }
        int tr = pe.PEHeaders.MetadataStartOffset + System.Reflection.Metadata.Ecma335.MetadataReaderExtensions.GetTableMetadataOffset(md, trTable)
            + (System.Reflection.Metadata.Ecma335.MetadataTokens.GetRowNumber(trs[0]) - 1) * 6;
        Put(bytes, tr, (1 << 2) | 0);  // ResolutionScope: Module row 1 (tag 0)
        Put(bytes, tr + 2, System.Reflection.Metadata.Ecma335.MetadataTokens.GetHeapOffset(names[0]));
        Put(bytes, tr + 4, 0);  // no namespace
        int mr = pe.PEHeaders.MetadataStartOffset + System.Reflection.Metadata.Ecma335.MetadataReaderExtensions.GetTableMetadataOffset(md, mrTable)
            + (System.Reflection.Metadata.Ecma335.MetadataTokens.GetRowNumber(refs[0]) - 1) * 6;
        Put(bytes, mr + 4, System.Reflection.Metadata.Ecma335.MetadataTokens.GetHeapOffset(md.GetMethodDefinition(likes[0]).Signature));
    }
    File.WriteAllBytes(path, bytes);
}

// Changes the parent of the member reference `member` on the type reference `from` to the type `to` defined in
// the file (a coded index into the TypeDef table), in place.
static void ReparentMemberRef(string path, string member, string from, string to) {
    var bytes = File.ReadAllBytes(path);
    using (var pe = new System.Reflection.PortableExecutable.PEReader(new MemoryStream(bytes))) {
        var md = System.Reflection.Metadata.PEReaderExtensions.GetMetadataReader(pe);
        var refs = md.MemberReferences.Where(h => {
            var r = md.GetMemberReference(h);
            return md.GetString(r.Name) == member && r.Parent.Kind == System.Reflection.Metadata.HandleKind.TypeReference
                && md.GetString(md.GetTypeReference((System.Reflection.Metadata.TypeReferenceHandle)r.Parent).Name) == from;
        }).ToList();
        var defs = md.TypeDefinitions.Where(h => md.GetString(md.GetTypeDefinition(h).Name) == to).ToList();
        var table = System.Reflection.Metadata.Ecma335.TableIndex.MemberRef;
        if (refs.Count != 1 || defs.Count != 1 || System.Reflection.Metadata.Ecma335.MetadataReaderExtensions.GetTableRowSize(md, table) != 6) throw new InvalidOperationException($"{path}: unexpected metadata layout");
        int row = System.Reflection.Metadata.Ecma335.MetadataTokens.GetRowNumber(refs[0]);
        int at = pe.PEHeaders.MetadataStartOffset + System.Reflection.Metadata.Ecma335.MetadataReaderExtensions.GetTableMetadataOffset(md, table) + (row - 1) * 6;
        int parent = System.Reflection.Metadata.Ecma335.MetadataTokens.GetRowNumber(defs[0]) << 3;  // MemberRefParent tag 0: TypeDef
        bytes[at] = (byte)parent;
        bytes[at + 1] = (byte)(parent >> 8);
    }
    File.WriteAllBytes(path, bytes);
}
Console.WriteLine("ok");
