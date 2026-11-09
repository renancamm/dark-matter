// SPDX-License-Identifier: MIT
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;

namespace DarkMatter.Analysis;

/// <summary>
/// Layouts of the shared framework's value types and enums, read from the framework's own
/// assemblies (the runtime directory this program runs on, as <c>Evaluation.Boundary</c> reads the
/// framework's type names), following type forwarders as the runtime does (System.Runtime forwards
/// to System.Private.CoreLib). Nothing is loaded or run: the files are read as metadata. The check
/// uses a framework layout only for a type that holds plain data (see <c>AssemblyWalker.ReferencedStruct</c>):
/// the size this runtime gives a struct is taken to be the size the game's runtime gives it, which
/// holds for plain value types across runtime versions, and the check never relies on it to bound a
/// reference. A runtime directory that cannot be read gives no layouts, which fails closed.
/// </summary>
internal sealed class FrameworkLayouts {
    public static readonly FrameworkLayouts Shared = new();

    readonly object gate = new();
    readonly Lazy<Dictionary<string, string>> files = new(ListRuntimeFiles);  // assembly name -> path
    readonly Dictionary<string, Module?> modules = new(StringComparer.OrdinalIgnoreCase);
    readonly Dictionary<string, FieldLayout> layouts = new(StringComparer.Ordinal);  // "assembly|Namespace.Type"
    readonly HashSet<string> inProgress = new(StringComparer.Ordinal);

    FrameworkLayouts() { }

    static Dictionary<string, string> ListRuntimeFiles() {
        var found = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try {
            foreach (var path in Directory.EnumerateFiles(RuntimeEnvironment.GetRuntimeDirectory(), "*.dll"))
                found.TryAdd(Path.GetFileNameWithoutExtension(path), path);
        } catch (Exception e) when (e is IOException or UnauthorizedAccessException) {
            // Silence on purpose: no framework layouts, which fails closed.
        }
        return found;
    }

    /// <summary>Layout of the value type <paramref name="typeName"/> ("Namespace.Outer/Inner") of the framework assembly <paramref name="assembly"/>; unknown when it cannot be read.</summary>
    public FieldLayout Layout(string assembly, string typeName, int depth) {
        lock (gate) return LayoutLocked(assembly, typeName, depth);
    }

    /// <summary>Size of the framework enum <paramref name="typeName"/> (see <see cref="Layouts.EnumSize"/>), or null.</summary>
    public int? EnumSize(string assembly, string typeName) {
        lock (gate) {
            if (Resolve(assembly, typeName, 0) is not var (module, th)) return null;
            try {
                var t = module.Metadata.GetTypeDefinition(th);
                return !t.BaseType.IsNil && Il.TypeName(module.Metadata, t.BaseType) == "System.Enum" ? Layouts.EnumSize(module.Metadata, t) : null;
            } catch (BadImageFormatException) {
                return null;
            }
        }
    }

    FieldLayout LayoutLocked(string assembly, string typeName, int depth) {
        if (depth > Layouts.MaxDepth || assembly.Length == 0) return FieldLayout.Unknown;
        var key = assembly + "|" + typeName;
        if (layouts.TryGetValue(key, out var known)) return known;
        if (!inProgress.Add(key)) return FieldLayout.Unknown;  // a cycle
        var result = FieldLayout.Unknown;
        try {
            if (Resolve(assembly, typeName, 0) is var (module, th))
                result = Layouts.Compute(module, th, depth, module.IsValueType, module.IsInlineArray);
        } catch (BadImageFormatException) {
        } finally {
            inProgress.Remove(key);
        }
        layouts[key] = result;
        return result;
    }

    // The module that defines the type, following forwarders.
    (Module, TypeDefinitionHandle)? Resolve(string assembly, string typeName, int hops) {
        if (hops > 8 || Load(assembly) is not { } module) return null;
        if (module.Definitions.TryGetValue(typeName, out var th)) return (module, th);
        return module.Forwards.TryGetValue(typeName, out var to) ? Resolve(to, typeName, hops + 1) : null;
    }

    Module? Load(string assembly) {
        if (modules.TryGetValue(assembly, out var m)) return m;
        Module? loaded = null;
        if (files.Value.TryGetValue(assembly, out var path)) {
            try {
                loaded = new Module(this, assembly, new PEReader(File.OpenRead(path)));
            } catch (Exception e) when (e is IOException or UnauthorizedAccessException or BadImageFormatException or InvalidOperationException) {
                // Silence on purpose: this assembly's types are not known, which fails closed.
            }
        }
        return modules[assembly] = loaded;
    }

    /// <summary>One framework assembly, read as metadata, with its type definitions and forwarders by name.</summary>
    sealed class Module : Layouts.IScope {
        readonly FrameworkLayouts owner;
        readonly string name;
        readonly PEReader pe;  // kept open for the metadata reader's lifetime (the process)
        public MetadataReader Metadata { get; }
        public Dictionary<string, TypeDefinitionHandle> Definitions { get; } = new(StringComparer.Ordinal);
        public Dictionary<string, string> Forwards { get; } = new(StringComparer.Ordinal);  // type -> assembly

        public Module(FrameworkLayouts owner, string name, PEReader pe) {
            this.owner = owner;
            this.name = name;
            this.pe = pe;
            if (!pe.HasMetadata) throw new BadImageFormatException("no metadata");
            Metadata = pe.GetMetadataReader();
            var md = Metadata;
            foreach (var th in md.TypeDefinitions) Definitions.TryAdd(Il.TypeName(md, th), th);
            foreach (var eh in md.ExportedTypes)
                if (ForwardedTo(eh, 0) is { } to) Forwards.TryAdd(ExportedName(eh, 0), to);
        }

        string ExportedName(ExportedTypeHandle eh, int depth) {
            var md = Metadata;
            var e = md.GetExportedType(eh);
            var n = md.GetString(e.Name);
            if (e.Implementation.Kind == HandleKind.ExportedType && depth < Layouts.MaxDepth) return ExportedName((ExportedTypeHandle)e.Implementation, depth + 1) + "/" + n;
            var ns = md.GetString(e.Namespace);
            return ns.Length > 0 ? ns + "." + n : n;
        }

        // The assembly an exported type forwards to (through its outer types for a nested one), or null.
        string? ForwardedTo(ExportedTypeHandle eh, int depth) {
            var md = Metadata;
            var e = md.GetExportedType(eh);
            return e.Implementation.Kind switch {
                HandleKind.AssemblyReference => md.GetString(md.GetAssemblyReference((AssemblyReferenceHandle)e.Implementation).Name),
                HandleKind.ExportedType when depth < Layouts.MaxDepth => ForwardedTo((ExportedTypeHandle)e.Implementation, depth + 1),
                _ => null,
            };
        }

        // The assembly a type reference of this module names: the referenced assembly, this one for a module scope.
        string ReferencedAssembly(TypeReferenceHandle h, int depth) {
            var md = Metadata;
            var rs = md.GetTypeReference(h).ResolutionScope;
            return rs.Kind switch {
                HandleKind.AssemblyReference => md.GetString(md.GetAssemblyReference((AssemblyReferenceHandle)rs).Name),
                HandleKind.TypeReference when depth < Layouts.MaxDepth => ReferencedAssembly((TypeReferenceHandle)rs, depth + 1),
                HandleKind.ModuleDefinition => name,
                _ => "",
            };
        }

        // Within the framework's own files, a base type named System.ValueType or System.Enum is the framework's.
        public bool IsValueType(TypeDefinition t) => !t.BaseType.IsNil && Il.TypeName(Metadata, t.BaseType) is "System.ValueType" or "System.Enum";
        public bool NamesValueTypeBase(TypeDefinitionHandle h) => IsValueType(Metadata.GetTypeDefinition(h));

        public bool IsInlineArray(TypeDefinition t) {
            var md = Metadata;
            foreach (var ah in t.GetCustomAttributes()) {
                var ctor = md.GetCustomAttribute(ah).Constructor;
                var type = ctor.Kind switch {
                    HandleKind.MemberReference => Il.TypeName(md, Il.ParentType(md, md.GetMemberReference((MemberReferenceHandle)ctor).Parent)),
                    HandleKind.MethodDefinition => Il.TypeName(md, md.GetMethodDefinition((MethodDefinitionHandle)ctor).GetDeclaringType()),
                    _ => "",
                };
                if (type == "System.Runtime.CompilerServices.InlineArrayAttribute") return true;
            }
            return false;
        }

        public FieldLayout Definition(TypeDefinitionHandle h, int depth) => owner.LayoutLocked(name, Il.TypeName(Metadata, h), depth);
        public FieldLayout Reference(TypeReferenceHandle h, int depth) => owner.LayoutLocked(ReferencedAssembly(h, 0), Il.TypeName(Metadata, h), depth);
    }
}
