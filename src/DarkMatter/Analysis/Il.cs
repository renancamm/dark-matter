// SPDX-License-Identifier: MIT
using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Security.Cryptography;

namespace DarkMatter.Analysis;

/// <summary>One decoded IL instruction. <c>Next</c> is the offset of the following instruction.</summary>
internal readonly record struct Instruction(int Offset, OpCode OpCode, int OperandOffset, int Next);

/// <summary>IL decoding, metadata naming and signature decoding.</summary>
internal static class Il {
    const int MaxDepth = 32;  // bound on recursive name resolution; malformed metadata can be cyclic
    static readonly OpCode[] OneByte = new OpCode[256];
    static readonly OpCode[] TwoByte = new OpCode[256];

    static Il() {
        foreach (var f in typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static)) {
            var oc = (OpCode)f.GetValue(null)!;
            var v = (ushort)oc.Value;
            if (oc.Size == 1) OneByte[v] = oc; else TwoByte[v & 0xFF] = oc;
        }
    }

    /// <summary>
    /// Decodes a complete method body. Throws <see cref="InvalidDataException"/> on an undefined
    /// opcode or a truncated operand, so callers treat the method as unanalyzable instead of
    /// silently analyzing a prefix of it.
    /// </summary>
    public static List<Instruction> Decode(byte[] il) {
        var code = new List<Instruction>();
        int pos = 0;
        while (pos < il.Length) {
            int start = pos;
            byte b = il[pos++];
            OpCode oc;
            if (b == 0xFE) {
                if (pos >= il.Length) throw new InvalidDataException($"truncated opcode at IL_{start:X4}");
                oc = TwoByte[il[pos++]];
            } else {
                oc = OneByte[b];
            }
            if (oc.Size == 0 || oc.OpCodeType == OpCodeType.Nternal)
                throw new InvalidDataException($"undefined opcode at IL_{start:X4}");
            long next = pos + OperandSize(oc, il, pos);
            if (next > il.Length) throw new InvalidDataException($"truncated operand at IL_{start:X4}");
            code.Add(new Instruction(start, oc, pos, (int)next));
            pos = (int)next;
        }
        return code;
    }

    static long OperandSize(OpCode oc, byte[] il, int pos) => oc.OperandType switch {
        OperandType.InlineNone => 0,
        OperandType.ShortInlineBrTarget or OperandType.ShortInlineI or OperandType.ShortInlineVar => 1,
        OperandType.InlineVar => 2,
        OperandType.InlineI8 or OperandType.InlineR => 8,
        OperandType.InlineSwitch => 4 + (4L * (uint)ReadInt32(il, pos)),
        _ => 4,
    };

    public static int ReadInt32(byte[] il, int pos) {
        if (pos < 0 || pos + 4 > il.Length) throw new InvalidDataException($"truncated operand at {pos}");
        return BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(pos));
    }

    public static ushort ReadUInt16(byte[] il, int pos) {
        if (pos < 0 || pos + 2 > il.Length) throw new InvalidDataException($"truncated operand at {pos}");
        return BinaryPrimitives.ReadUInt16LittleEndian(il.AsSpan(pos));
    }

    /// <summary>The 4-byte metadata token operand of an instruction.</summary>
    public static int Token(byte[] il, Instruction ins) => ReadInt32(il, ins.OperandOffset);

    /// <summary>
    /// Offsets that control can reach other than by falling through: branch targets, switch
    /// targets, and the start of every protected region, handler and filter.
    /// </summary>
    public static HashSet<int> BlockStarts(byte[] il, List<Instruction> code, MethodBodyBlock body) {
        var starts = new HashSet<int>();
        foreach (var ins in code) starts.UnionWith(BranchTargets(il, ins));
        foreach (var r in body.ExceptionRegions) starts.Add(r.TryOffset);
        starts.UnionWith(HandlerStarts(body));
        return starts;
    }

    /// <summary>
    /// Throws <see cref="InvalidDataException"/> when a branch or switch target, or the start of a
    /// protected region, handler or filter, is not the start of an instruction, or a region does not
    /// end at one (or at the end of the code). The walker reads the code once, in order, and carries
    /// what is on the stack to each branch target (H7): code entered in the middle of an instruction
    /// would be other instructions than the ones it read. The runtime rejects such code; the check
    /// does not rely on that, and treats the method as one it cannot read.
    /// </summary>
    public static void CheckTargets(byte[] il, List<Instruction> code, MethodBodyBlock body) {
        var at = new HashSet<int>(code.Select(i => i.Offset));
        foreach (var ins in code)
            foreach (var t in BranchTargets(il, ins))
                if (!at.Contains(t)) throw new InvalidDataException($"branch to IL_{t:X4}, which is not an instruction, at IL_{ins.Offset:X4}");
        int end = il.Length;
        foreach (var r in body.ExceptionRegions) {
            bool Start(int o) => at.Contains(o);
            bool End(int o) => o == end || at.Contains(o);
            if (!Start(r.TryOffset) || !End(r.TryOffset + r.TryLength) || !Start(r.HandlerOffset) || !End(r.HandlerOffset + r.HandlerLength)
                || (r.Kind == ExceptionRegionKind.Filter && !Start(r.FilterOffset)))
                throw new InvalidDataException("an exception region that does not begin and end at instructions");
        }
    }

    /// <summary>Offsets an instruction can branch to (empty if it is not a branch).</summary>
    public static List<int> BranchTargets(byte[] il, Instruction ins) {
        switch (ins.OpCode.OperandType) {
            case OperandType.ShortInlineBrTarget:
                return [ins.Next + (sbyte)il[ins.OperandOffset]];
            case OperandType.InlineBrTarget:
                return [ins.Next + ReadInt32(il, ins.OperandOffset)];
            case OperandType.InlineSwitch:
                int n = ReadInt32(il, ins.OperandOffset);
                var targets = new List<int>(n);
                for (int k = 0; k < n; k++) targets.Add(ins.Next + ReadInt32(il, ins.OperandOffset + 4 + (4 * k)));
                return targets;
            default:
                return [];
        }
    }

    /// <summary>Start offsets of every exception handler and filter: entered with a fresh stack.</summary>
    public static HashSet<int> HandlerStarts(MethodBodyBlock body) {
        var starts = new HashSet<int>();
        foreach (var r in body.ExceptionRegions) {
            starts.Add(r.HandlerOffset);
            if (r.Kind == ExceptionRegionKind.Filter) starts.Add(r.FilterOffset);
        }
        return starts;
    }

    /// <summary>Whether control can continue to the next instruction.</summary>
    public static bool FallsThrough(Instruction ins) =>
        ins.OpCode.FlowControl is not (FlowControl.Branch or FlowControl.Return or FlowControl.Throw);

    /// <summary>"Namespace.Type", with nested types as "Outer/Inner". Generic instances resolve to their definition.</summary>
    public static string TypeName(MetadataReader md, EntityHandle h) => TypeName(md, h, 0);

    static string TypeName(MetadataReader md, EntityHandle h, int depth) {
        if (depth > MaxDepth) return "?";
        switch (h.Kind) {
            case HandleKind.TypeReference: {
                var t = md.GetTypeReference((TypeReferenceHandle)h);
                var n = md.GetString(t.Name);
                if (t.ResolutionScope.Kind == HandleKind.TypeReference)
                    return TypeName(md, t.ResolutionScope, depth + 1) + "/" + n;
                var ns = md.GetString(t.Namespace);
                return ns.Length > 0 ? ns + "." + n : n;
            }
            case HandleKind.TypeDefinition: {
                var t = md.GetTypeDefinition((TypeDefinitionHandle)h);
                var n = md.GetString(t.Name);
                if (t.IsNested) return TypeName(md, t.GetDeclaringType(), depth + 1) + "/" + n;
                var ns = md.GetString(t.Namespace);
                return ns.Length > 0 ? ns + "." + n : n;
            }
            case HandleKind.TypeSpecification: {
                var b = md.GetBlobReader(md.GetTypeSpecification((TypeSpecificationHandle)h).Signature);
                if (b.ReadSignatureTypeCode() == SignatureTypeCode.GenericTypeInstance) {
                    b.ReadByte();
                    return TypeName(md, b.ReadTypeHandle(), depth + 1);
                }
                return "?spec";
            }
        }
        return "?";
    }

    /// <summary>The type a member's parent refers to (a MethodDefinition parent means a vararg call site).</summary>
    public static EntityHandle ParentType(MetadataReader md, EntityHandle parent) =>
        parent.Kind == HandleKind.MethodDefinition ? md.GetMethodDefinition((MethodDefinitionHandle)parent).GetDeclaringType() : parent;

    /// <summary>"Namespace.Type::Member" for a method, field or member reference; the type name for a type token.</summary>
    public static string MemberName(MetadataReader md, EntityHandle h) {
        if (h.Kind == HandleKind.MethodSpecification) {
            h = md.GetMethodSpecification((MethodSpecificationHandle)h).Method;
            if (h.Kind == HandleKind.MethodSpecification) return "?";
        }
        switch (h.Kind) {
            case HandleKind.MemberReference: {
                var m = md.GetMemberReference((MemberReferenceHandle)h);
                return TypeName(md, ParentType(md, m.Parent)) + "::" + md.GetString(m.Name);
            }
            case HandleKind.MethodDefinition: {
                var m = md.GetMethodDefinition((MethodDefinitionHandle)h);
                return TypeName(md, m.GetDeclaringType()) + "::" + md.GetString(m.Name);
            }
            case HandleKind.FieldDefinition: {
                var f = md.GetFieldDefinition((FieldDefinitionHandle)h);
                return TypeName(md, f.GetDeclaringType()) + "::" + md.GetString(f.Name);
            }
            case HandleKind.TypeReference:
            case HandleKind.TypeDefinition:
            case HandleKind.TypeSpecification:
                return TypeName(md, h);
        }
        return "?";
    }

    /// <summary>Decoded signature of a method token or a calli signature; null for anything else.</summary>
    public static MethodSignature<string>? Signature(MetadataReader md, EntityHandle h) {
        var names = SignatureNames.Instance;
        if (h.Kind == HandleKind.MethodSpecification) h = md.GetMethodSpecification((MethodSpecificationHandle)h).Method;
        switch (h.Kind) {
            case HandleKind.MethodDefinition:
                return md.GetMethodDefinition((MethodDefinitionHandle)h).DecodeSignature(names, null);
            case HandleKind.MemberReference: {
                var mr = md.GetMemberReference((MemberReferenceHandle)h);
                return mr.GetKind() == MemberReferenceKind.Method ? mr.DecodeMethodSignature(names, null) : null;
            }
            case HandleKind.StandaloneSignature: {
                var ss = md.GetStandaloneSignature((StandaloneSignatureHandle)h);
                return ss.GetKind() == StandaloneSignatureKind.Method ? ss.DecodeMethodSignature(names, null) : null;
            }
        }
        return null;
    }

    public static string Sha256(byte[] data) => Convert.ToHexStringLower(SHA256.HashData(data));

    /// <summary>
    /// Expands "@listfile" arguments into the paths that file lists, one per line. Blank lines
    /// and lines starting with '#' are ignored.
    /// </summary>
    public static List<string> ExpandArgs(IEnumerable<string> args) {
        var files = new List<string>();
        foreach (var a in args) {
            if (!a.StartsWith('@')) { files.Add(a); continue; }
            foreach (var line in File.ReadLines(a[1..])) {
                var l = line.Trim();
                if (l.Length > 0 && !l.StartsWith('#')) files.Add(l);
            }
        }
        return files;
    }
}

/// <summary>A decoded signature type that keeps its definition handle and generic arguments.</summary>
internal sealed record TypeShape(string Name, EntityHandle Definition, ImmutableArray<TypeShape> Args) {
    public static TypeShape Of(string name) => new(name, default, []);
    public override string ToString() => Args.IsDefaultOrEmpty ? Name : Name + "<" + string.Join(",", Args) + ">";
}

/// <summary>Decodes signature types to <see cref="TypeShape"/>.</summary>
internal sealed class TypeShapes : ISignatureTypeProvider<TypeShape, object?> {
    public static readonly TypeShapes Instance = new();
    public TypeShape GetArrayType(TypeShape elementType, ArrayShape shape) => TypeShape.Of(elementType + "[" + new string(',', Math.Max(0, shape.Rank - 1)) + "]");
    public TypeShape GetByReferenceType(TypeShape elementType) => TypeShape.Of(elementType + "&");
    public TypeShape GetFunctionPointerType(MethodSignature<TypeShape> signature) => TypeShape.Of("method*");
    public TypeShape GetGenericInstantiation(TypeShape genericType, ImmutableArray<TypeShape> typeArguments) => genericType with { Args = typeArguments };
    public TypeShape GetGenericMethodParameter(object? genericContext, int index) => TypeShape.Of("!!" + index);
    public TypeShape GetGenericTypeParameter(object? genericContext, int index) => TypeShape.Of("!" + index);
    public TypeShape GetModifiedType(TypeShape modifier, TypeShape unmodifiedType, bool isRequired) => unmodifiedType;
    public TypeShape GetPinnedType(TypeShape elementType) => elementType;
    public TypeShape GetPointerType(TypeShape elementType) => TypeShape.Of(elementType + "*");
    public TypeShape GetPrimitiveType(PrimitiveTypeCode typeCode) => TypeShape.Of("System." + typeCode);
    public TypeShape GetSZArrayType(TypeShape elementType) => TypeShape.Of(elementType + "[]");
    public TypeShape GetTypeFromDefinition(MetadataReader reader, TypeDefinitionHandle handle, byte rawTypeKind) => new(Il.TypeName(reader, handle), handle, []);
    public TypeShape GetTypeFromReference(MetadataReader reader, TypeReferenceHandle handle, byte rawTypeKind) => new(Il.TypeName(reader, handle), handle, []);
    public TypeShape GetTypeFromSpecification(MetadataReader reader, object? genericContext, TypeSpecificationHandle handle, byte rawTypeKind) => TypeShape.Of(Il.TypeName(reader, handle));
}

/// <summary>Renders signature types as names, e.g. "System.String" or "System.Byte[]".</summary>
internal sealed class SignatureNames : ISignatureTypeProvider<string, object?> {
    public static readonly SignatureNames Instance = new();
    public string GetArrayType(string elementType, ArrayShape shape) => elementType + "[" + new string(',', Math.Max(0, shape.Rank - 1)) + "]";
    public string GetByReferenceType(string elementType) => elementType + "&";
    public string GetFunctionPointerType(MethodSignature<string> signature) => "method*";
    public string GetGenericInstantiation(string genericType, ImmutableArray<string> typeArguments) => genericType;
    public string GetGenericMethodParameter(object? genericContext, int index) => "!!" + index;
    public string GetGenericTypeParameter(object? genericContext, int index) => "!" + index;
    public string GetModifiedType(string modifier, string unmodifiedType, bool isRequired) => unmodifiedType;
    public string GetPinnedType(string elementType) => elementType;
    public string GetPointerType(string elementType) => elementType + "*";
    public string GetPrimitiveType(PrimitiveTypeCode typeCode) => "System." + typeCode;
    public string GetSZArrayType(string elementType) => elementType + "[]";
    public string GetTypeFromDefinition(MetadataReader reader, TypeDefinitionHandle handle, byte rawTypeKind) => Il.TypeName(reader, handle);
    public string GetTypeFromReference(MetadataReader reader, TypeReferenceHandle handle, byte rawTypeKind) => Il.TypeName(reader, handle);
    public string GetTypeFromSpecification(MetadataReader reader, object? genericContext, TypeSpecificationHandle handle, byte rawTypeKind) => Il.TypeName(reader, handle);
}
