// SPDX-License-Identifier: MIT
using System.Collections.Immutable;
using System.Reflection;
using System.Reflection.Metadata;

namespace DarkMatter.Analysis;

// ── explicit-layout overlaps ─────────────────────────────────────────────────────────────
//
// A type with [StructLayout(LayoutKind.Explicit)] can place two fields at the same bytes. When one
// of them holds a reference, a pointer, a native integer or a managed reference, the runtime then
// reads one field's bits as the other's type: a type confusion that reaches any memory, with no API
// call. Overlaps of plain data only (integers, floats, bools, chars, enums and structs of those) are
// ordinary unions and stay fine. A field whose size or contents the check cannot work out counts as
// not plain and as reaching to the end of the type (fail closed).
//
// The layout of a value type is read from metadata: the mod's own types from this module, and
// (since policy 34) the framework's value types and enums from the shared framework's own
// assemblies (see FrameworkLayouts). A framework type is used only when it holds plain data: a
// size the check reads from its own runtime for a type that holds a reference is not trusted to
// bound that reference in the game's runtime.
internal sealed partial class AssemblyWalker : Layouts.IScope {
    // Framework value types known to hold plain data only: size and alignment in bytes, as the
    // 64-bit runtime lays them out (Int128 is 16-byte aligned since .NET 8, which the natural
    // alignment of its two fields would not give). Consulted before the framework's metadata.
    static readonly Dictionary<string, (int Size, int Align)> PlainFrameworkStructs = new(StringComparer.Ordinal) {
        ["System.Half"] = (2, 2),
        ["System.DateTime"] = (8, 8),
        ["System.TimeSpan"] = (8, 8),
        ["System.Decimal"] = (16, 8),
        ["System.Guid"] = (16, 4),
        ["System.Int128"] = (16, 16),
        ["System.UInt128"] = (16, 16),
        ["System.Numerics.Vector2"] = (8, 4),
        ["System.Numerics.Vector3"] = (12, 4),
        ["System.Numerics.Vector4"] = (16, 4),
        ["System.Numerics.Quaternion"] = (16, 4),
        ["System.Numerics.Plane"] = (16, 4),
        ["System.Numerics.Complex"] = (16, 8),
        ["System.Numerics.Matrix3x2"] = (24, 4),
        ["System.Numerics.Matrix4x4"] = (64, 4),
    };

    readonly Dictionary<TypeDefinitionHandle, FieldLayout> structLayouts = [];
    readonly HashSet<TypeDefinitionHandle> structsInProgress = [];

    MetadataReader Layouts.IScope.Metadata => Metadata;
    FieldLayout Layouts.IScope.Definition(TypeDefinitionHandle h, int depth) => StructLayout(h, depth);
    FieldLayout Layouts.IScope.Reference(TypeReferenceHandle h, int depth) => ReferencedStruct(h, depth);
    bool Layouts.IScope.NamesValueTypeBase(TypeDefinitionHandle h) => NamesValueTypeBase(h);

    // Records raw-memory for every explicit-layout type of this assembly whose fields overlap where
    // either field is not plain data.
    void CheckExplicitLayouts() {
        var md = Metadata;
        foreach (var th in md.TypeDefinitions) {
            var t = md.GetTypeDefinition(th);
            if ((t.Attributes & TypeAttributes.LayoutMask) != TypeAttributes.ExplicitLayout) continue;
            if (ExplicitOverlap(th, t) is { } detail)
                facts.Caps.Add(new("raw-memory", detail, Origin.Structure));
        }
    }

    // Why an explicit-layout type is a type confusion, or null if it is not.
    string? ExplicitOverlap(TypeDefinitionHandle th, TypeDefinition t) {
        var md = Metadata;
        var typeName = Il.TypeName(md, th);
        var fields = new List<(string Name, int Offset, FieldLayout Layout)>();
        try {
            foreach (var fh in t.GetFields()) {
                var f = md.GetFieldDefinition(fh);
                if ((f.Attributes & FieldAttributes.Static) != 0) continue;
                var name = md.GetString(f.Name);
                int offset = f.GetOffset();
                // Every instance field of an explicit-layout type has an offset; one without (or past
                // 2 GiB) is a layout the check cannot place.
                if (offset < 0) return $"{typeName}::{name} has no field offset the check can read (explicit layout)";
                fields.Add((name, offset, f.DecodeSignature(new Layouts.Provider(this, 0), null)));
            }
        } catch (BadImageFormatException) {
            return $"{typeName} has fields the check cannot decode (explicit layout)";
        }
        string? first = null;
        int count = 0;
        for (int i = 0; i < fields.Count; i++)
            for (int j = i + 1; j < fields.Count; j++) {
                var (a, b) = (fields[i], fields[j]);
                if (a.Layout.Plain && b.Layout.Plain) continue;
                if (!Layouts.Overlaps(a.Offset, a.Layout.Size, b.Offset, b.Layout.Size)) continue;
                first ??= $"{typeName}::{a.Name} overlaps {typeName}::{b.Name} (explicit layout)";
                count++;
            }
        return first == null ? null : count == 1 ? first : $"{first}, and {count - 1} more overlapping field pairs";
    }

    // The layout of a value type defined here: its fields laid out as the runtime does (explicit
    // offsets, or sequential with natural alignment; auto layout is never larger), at least the
    // declared size. Unknown for a cycle, a generic type, an inline array or an undecodable field.
    FieldLayout StructLayout(TypeDefinitionHandle th, int depth) {
        if (structLayouts.TryGetValue(th, out var known)) return known;
        if (depth > Layouts.MaxDepth || !structsInProgress.Add(th)) return FieldLayout.Unknown;
        var result = FieldLayout.Unknown;
        try {
            // An enum derives from the framework's System.Enum; the framework's InlineArray attribute, as the
            // compiler emits it (an attribute of that name from elsewhere still makes the layout one the check
            // does not rely on).
            result = Layouts.Compute(this, th, depth, IsValueTypeDefinition, t => FindAttribute(t.GetCustomAttributes(), InlineArrayAttribute) != null);
        } catch (BadImageFormatException) { } finally { structsInProgress.Remove(th); }
        structLayouts[th] = result;
        return result;
    }

    bool IsValueTypeDefinition(TypeDefinition t) {
        if (t.BaseType.IsNil) return false;
        var b = Il.TypeName(Metadata, t.BaseType);
        return (b is "System.ValueType" or "System.Enum") && FrameworkType(t.BaseType);
    }

    // Whether a type of this assembly derives from a type named System.ValueType or System.Enum, in
    // any scope (a value type, or one named like one).
    bool NamesValueTypeBase(TypeDefinitionHandle th) {
        var t = Metadata.GetTypeDefinition(th);
        return !t.BaseType.IsNil && Il.TypeName(Metadata, t.BaseType) is "System.ValueType" or "System.Enum";
    }

    // Layout of a framework value type: one the check knows to hold plain data (the table above), or
    // one the shared framework's own metadata shows to hold plain data only (an enum, a struct of
    // plain fields). Anything else, a framework type that holds a reference included, is unknown.
    FieldLayout ReferencedStruct(TypeReferenceHandle h, int depth) {
        if (!FrameworkType(h)) return FieldLayout.Unknown;
        var name = Il.TypeName(Metadata, h);
        if (PlainFrameworkStructs.TryGetValue(name, out var s)) return new(s.Size, s.Align, true);
        var fl = FrameworkLayouts.Shared.Layout(TypeAssembly(h), name, depth);
        return fl is { Plain: true, Size: not null } ? fl : FieldLayout.Unknown;
    }

    /// <summary>
    /// The layout of a type as a signature names it (see <see cref="Layouts.Provider"/>): a primitive,
    /// a value type of this assembly or of the framework; unknown for a generic instantiation or
    /// parameter, an array, a pointer or a managed reference.
    /// </summary>
    public FieldLayout LayoutOf(TypeShape type) {
        if (!type.Args.IsDefaultOrEmpty) return FieldLayout.Unknown;
        if (type.Definition.IsNil) return Layouts.Primitive(type.Name);
        try {
            return type.Definition.Kind switch {
                HandleKind.TypeDefinition => StructLayout((TypeDefinitionHandle)type.Definition, 0),
                HandleKind.TypeReference => ReferencedStruct((TypeReferenceHandle)type.Definition, 0),
                _ => FieldLayout.Unknown,
            };
        } catch (BadImageFormatException) {
            return FieldLayout.Unknown;
        }
    }

    /// <summary>
    /// The size in bytes of one element of a span of this type, where the runtime fixes it exactly: a
    /// primitive, or an enum (of this assembly or of the framework), which is laid out as its one
    /// instance field. Null for anything else.
    /// </summary>
    public int? ElementSize(TypeShape type) {
        if (!type.Args.IsDefaultOrEmpty) return null;
        if (type.Definition.IsNil) return Layouts.PrimitiveSize(type.Name);
        try {
            switch (type.Definition.Kind) {
                case HandleKind.TypeDefinition: {
                    var th = (TypeDefinitionHandle)type.Definition;
                    var t = Metadata.GetTypeDefinition(th);
                    return !t.BaseType.IsNil && Il.TypeName(Metadata, t.BaseType) == "System.Enum" && FrameworkType(t.BaseType) ? Layouts.EnumSize(Metadata, t) : null;
                }
                case HandleKind.TypeReference: {
                    var h = (TypeReferenceHandle)type.Definition;
                    return FrameworkType(h) ? FrameworkLayouts.Shared.EnumSize(TypeAssembly(h), Il.TypeName(Metadata, h)) : null;
                }
                default:
                    return null;
            }
        } catch (BadImageFormatException) {
            return null;
        }
    }
}

/// <summary>
/// The layout facts of a field's type: its size in bytes (null when unknown, which reaches to
/// the end of the type), its alignment, and whether it holds plain data only.
/// </summary>
internal readonly record struct FieldLayout(int? Size, int Align, bool Plain) {
    public static readonly FieldLayout Unknown = new(null, Layouts.PointerSize, false);
    public static readonly FieldLayout Reference = new(Layouts.PointerSize, Layouts.PointerSize, false);
    public static FieldLayout Data(int size) => new(size, size, true);
}

/// <summary>Lays value types out from metadata, for this module's types and the framework's alike.</summary>
internal static class Layouts {
    public const int PointerSize = 8;
    public const int MaxDepth = 32;

    /// <summary>Where a signature's type tokens resolve: the module they are read in.</summary>
    public interface IScope {
        MetadataReader Metadata { get; }
        /// <summary>Layout of a value type defined in the module.</summary>
        FieldLayout Definition(TypeDefinitionHandle h, int depth);
        /// <summary>Layout of a value type the module references.</summary>
        FieldLayout Reference(TypeReferenceHandle h, int depth);
        /// <summary>Whether a type of the module derives from a type named System.ValueType or System.Enum, in any scope.</summary>
        bool NamesValueTypeBase(TypeDefinitionHandle h);
    }

    /// <summary>Whether [a, a + aSize) and [b, b + bSize) intersect; an unknown size reaches to the end.</summary>
    public static bool Overlaps(long a, int? aSize, long b, int? bSize) =>
        (aSize is not int sa || b < a + sa) && (bSize is not int sb || a < b + sb);

    /// <summary>Size of a primitive type by its signature name, for the plain ones; null otherwise.</summary>
    public static int? PrimitiveSize(string name) => name switch {
        "System.Byte" or "System.SByte" or "System.Boolean" => 1,
        "System.Char" or "System.Int16" or "System.UInt16" => 2,
        "System.Int32" or "System.UInt32" or "System.Single" => 4,
        "System.Int64" or "System.UInt64" or "System.Double" => 8,
        _ => null,
    };

    /// <summary>Layout of a primitive type by its signature name.</summary>
    public static FieldLayout Primitive(string name) => PrimitiveSize(name) is int s ? FieldLayout.Data(s)
        // Native integers hold addresses as often as numbers; String and Object are references.
        : name is "System.IntPtr" or "System.UIntPtr" or "System.String" or "System.Object" ? FieldLayout.Reference
        : FieldLayout.Unknown;

    static FieldLayout Primitive(PrimitiveTypeCode typeCode) => typeCode switch {
        PrimitiveTypeCode.Boolean or PrimitiveTypeCode.Byte or PrimitiveTypeCode.SByte => FieldLayout.Data(1),
        PrimitiveTypeCode.Char or PrimitiveTypeCode.Int16 or PrimitiveTypeCode.UInt16 => FieldLayout.Data(2),
        PrimitiveTypeCode.Int32 or PrimitiveTypeCode.UInt32 or PrimitiveTypeCode.Single => FieldLayout.Data(4),
        PrimitiveTypeCode.Int64 or PrimitiveTypeCode.UInt64 or PrimitiveTypeCode.Double => FieldLayout.Data(8),
        PrimitiveTypeCode.IntPtr or PrimitiveTypeCode.UIntPtr or PrimitiveTypeCode.String or PrimitiveTypeCode.Object => FieldLayout.Reference,
        // TypedReference (a managed reference and a type handle) and anything else.
        _ => FieldLayout.Unknown,
    };

    /// <summary>
    /// The size of an enum: that of its one instance field, which ECMA-335 requires to be a built-in
    /// integral type and which the runtime lays the enum out as. Null when the type is not shaped so.
    /// </summary>
    public static int? EnumSize(MetadataReader md, TypeDefinition t) {
        if ((t.Attributes & TypeAttributes.Sealed) == 0 || t.GetGenericParameters().Count > 0) return null;
        int? size = null;
        foreach (var fh in t.GetFields()) {
            var f = md.GetFieldDefinition(fh);
            if ((f.Attributes & FieldAttributes.Static) != 0) continue;
            if (size != null) return null;  // more than one instance field: not an enum the runtime loads
            var fl = f.DecodeSignature(PrimitivesOnly.Instance, null);
            if (fl is not { Plain: true, Size: int s }) return null;
            size = s;
        }
        return size;
    }

    /// <summary>
    /// A value type's fields laid out as the runtime does (explicit offsets, or sequential with natural
    /// alignment; auto layout is never larger), at least the declared size. Unknown for a generic type,
    /// a type that is not a value type, an inline array (repeated Length times, not laid out from its
    /// fields) or an undecodable field.
    /// </summary>
    public static FieldLayout Compute(IScope scope, TypeDefinitionHandle th, int depth, Func<TypeDefinition, bool> isValueType, Func<TypeDefinition, bool> isInlineArray) {
        var md = scope.Metadata;
        var t = md.GetTypeDefinition(th);
        if (t.GetGenericParameters().Count > 0 || !isValueType(t) || isInlineArray(t)) return FieldLayout.Unknown;
        var layout = t.GetLayout();
        int pack = layout.PackingSize;
        bool isExplicit = (t.Attributes & TypeAttributes.LayoutMask) == TypeAttributes.ExplicitLayout;
        bool plain = true;
        long end = 0;
        int align = 1;
        foreach (var fh in t.GetFields()) {
            var f = md.GetFieldDefinition(fh);
            if ((f.Attributes & FieldAttributes.Static) != 0) continue;
            var fl = f.DecodeSignature(new Provider(scope, depth + 1), null);
            if (fl.Size is not int size) return FieldLayout.Unknown;
            plain &= fl.Plain;
            int a = pack > 0 ? Math.Min(fl.Align, pack) : fl.Align;
            align = Math.Max(align, a);
            long offset;
            if (isExplicit) {
                offset = f.GetOffset();
                if (offset < 0) return FieldLayout.Unknown;
            } else {
                offset = (end + a - 1) / a * a;
            }
            end = Math.Max(end, offset + size);
        }
        end = Math.Max(end, Math.Max(layout.Size, 1));
        end = (end + align - 1) / align * align;
        return end > int.MaxValue ? FieldLayout.Unknown : new((int)end, align, plain);
    }

    /// <summary>Decodes a field's type to its <see cref="FieldLayout"/>, at a nesting depth of value types.</summary>
    public sealed class Provider(IScope scope, int depth) : ISignatureTypeProvider<FieldLayout, object?> {
        public FieldLayout GetArrayType(FieldLayout elementType, ArrayShape shape) => FieldLayout.Reference;
        public FieldLayout GetSZArrayType(FieldLayout elementType) => FieldLayout.Reference;
        public FieldLayout GetByReferenceType(FieldLayout elementType) => FieldLayout.Reference;
        public FieldLayout GetPointerType(FieldLayout elementType) => FieldLayout.Reference;
        public FieldLayout GetFunctionPointerType(MethodSignature<FieldLayout> signature) => FieldLayout.Reference;
        // A generic instantiation or parameter: contents the check does not lay out.
        public FieldLayout GetGenericInstantiation(FieldLayout genericType, ImmutableArray<FieldLayout> typeArguments) => FieldLayout.Unknown;
        public FieldLayout GetGenericMethodParameter(object? genericContext, int index) => FieldLayout.Unknown;
        public FieldLayout GetGenericTypeParameter(object? genericContext, int index) => FieldLayout.Unknown;
        public FieldLayout GetModifiedType(FieldLayout modifier, FieldLayout unmodifiedType, bool isRequired) => unmodifiedType;
        public FieldLayout GetPinnedType(FieldLayout elementType) => elementType;
        public FieldLayout GetTypeFromSpecification(MetadataReader reader, object? genericContext, TypeSpecificationHandle handle, byte rawTypeKind) => FieldLayout.Unknown;
        public FieldLayout GetPrimitiveType(PrimitiveTypeCode typeCode) => Primitive(typeCode);

        // A value type encoded as a class (hand-written IL) is not known to be laid out as a reference: unknown.
        public FieldLayout GetTypeFromDefinition(MetadataReader reader, TypeDefinitionHandle handle, byte rawTypeKind) =>
            rawTypeKind == (byte)SignatureTypeKind.Class ? (scope.NamesValueTypeBase(handle) ? FieldLayout.Unknown : FieldLayout.Reference)
            : rawTypeKind == (byte)SignatureTypeKind.ValueType ? scope.Definition(handle, depth)
            : FieldLayout.Unknown;

        public FieldLayout GetTypeFromReference(MetadataReader reader, TypeReferenceHandle handle, byte rawTypeKind) =>
            rawTypeKind == (byte)SignatureTypeKind.Class ? FieldLayout.Reference
            : rawTypeKind == (byte)SignatureTypeKind.ValueType ? scope.Reference(handle, depth)
            : FieldLayout.Unknown;
    }

    // A field signature that is a primitive and nothing else (an enum's value__).
    sealed class PrimitivesOnly : ISignatureTypeProvider<FieldLayout, object?> {
        public static readonly PrimitivesOnly Instance = new();
        public FieldLayout GetPrimitiveType(PrimitiveTypeCode typeCode) => Primitive(typeCode);
        public FieldLayout GetArrayType(FieldLayout elementType, ArrayShape shape) => FieldLayout.Unknown;
        public FieldLayout GetSZArrayType(FieldLayout elementType) => FieldLayout.Unknown;
        public FieldLayout GetByReferenceType(FieldLayout elementType) => FieldLayout.Unknown;
        public FieldLayout GetPointerType(FieldLayout elementType) => FieldLayout.Unknown;
        public FieldLayout GetFunctionPointerType(MethodSignature<FieldLayout> signature) => FieldLayout.Unknown;
        public FieldLayout GetGenericInstantiation(FieldLayout genericType, ImmutableArray<FieldLayout> typeArguments) => FieldLayout.Unknown;
        public FieldLayout GetGenericMethodParameter(object? genericContext, int index) => FieldLayout.Unknown;
        public FieldLayout GetGenericTypeParameter(object? genericContext, int index) => FieldLayout.Unknown;
        public FieldLayout GetModifiedType(FieldLayout modifier, FieldLayout unmodifiedType, bool isRequired) => FieldLayout.Unknown;
        public FieldLayout GetPinnedType(FieldLayout elementType) => FieldLayout.Unknown;
        public FieldLayout GetTypeFromSpecification(MetadataReader reader, object? genericContext, TypeSpecificationHandle handle, byte rawTypeKind) => FieldLayout.Unknown;
        public FieldLayout GetTypeFromDefinition(MetadataReader reader, TypeDefinitionHandle handle, byte rawTypeKind) => FieldLayout.Unknown;
        public FieldLayout GetTypeFromReference(MetadataReader reader, TypeReferenceHandle handle, byte rawTypeKind) => FieldLayout.Unknown;
    }
}
