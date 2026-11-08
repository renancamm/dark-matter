// SPDX-License-Identifier: MIT
using System.Collections.Immutable;
using System.Globalization;
using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Text.RegularExpressions;

namespace DarkMatter.Analysis;

/// <summary>
/// Analyzes one assembly: classifies it against the allowlist, records assembly-level findings,
/// and walks every method. Also owns the cross-method knowledge a <see cref="MethodWalker"/>
/// needs: node keys and the validated compiler helpers.
/// </summary>
internal sealed partial class AssemblyWalker {
    const string HelperType = "<PrivateImplementationDetails>";
    const string InlineArrayAttribute = "System.Runtime.CompilerServices.InlineArrayAttribute";
    const string UnverifiableCodeAttribute = "System.Security.UnverifiableCodeAttribute";
    const string HarmonyPatchAttribute = "HarmonyLib.HarmonyPatch";
    const string HarmonyDelegateAttribute = "HarmonyLib.HarmonyDelegate";
    const string HarmonyReversePatchAttribute = "HarmonyLib.HarmonyReversePatch";
    const string HarmonyPatchAllAttribute = "HarmonyLib.HarmonyPatchAll";
    const string HarmonyTargetMethodAttribute = "HarmonyLib.HarmonyTargetMethod";
    const string HarmonyTargetMethodsAttribute = "HarmonyLib.HarmonyTargetMethods";
    const string HarmonyMethodType = "HarmonyLib.HarmonyMethod";
    const string HarmonyInstructionType = "HarmonyLib.CodeInstruction";
    const string XmlSerializerAssemblyAttribute = "System.Xml.Serialization.XmlSerializerAssemblyAttribute";

    // Compiler-generated inline-array helpers (collection expressions, params spans). Their
    // bodies use Unsafe and MemoryMarshal; they are exempt only when the body matches the
    // compiler's template and every call site passes a matching buffer type and an in-range
    // constant index or length.
    static readonly HashSet<string> HelperNames = [
        "InlineArrayAsSpan", "InlineArrayAsReadOnlySpan", "InlineArrayElementRef",
        "InlineArrayElementRefReadOnly", "InlineArrayFirstElementRef", "InlineArrayFirstElementRefReadOnly",
    ];
    static readonly HashSet<string> HelperCalls = [
        "System.Runtime.CompilerServices.Unsafe::As", "System.Runtime.CompilerServices.Unsafe::AsRef",
        "System.Runtime.CompilerServices.Unsafe::Add", "System.Runtime.InteropServices.MemoryMarshal::CreateSpan",
        "System.Runtime.InteropServices.MemoryMarshal::CreateReadOnlySpan",
    ];

    [GeneratedRegex(@"^System\.Runtime\.CompilerServices\.InlineArray(\d+)`1$")]
    private static partial Regex FrameworkInlineArray();

    readonly Allowlist allow;
    readonly PEReader pe;
    readonly AssemblyFacts facts;
    readonly HashSet<MethodDefinitionHandle> helpers = [];
    readonly Dictionary<MethodDefinitionHandle, string?> getters = [];
    readonly Dictionary<MethodDefinitionHandle, TargetMethodKind> targetMethods = [];
    readonly Dictionary<string, TypeDefinitionHandle> typeHandles = new(StringComparer.Ordinal);
    readonly Dictionary<string, string?> iterators = new(StringComparer.Ordinal);
    readonly Dictionary<string, int> unionIds = new(StringComparer.Ordinal);
    readonly Dictionary<string, PatchEffect> patchClassEffects = new(StringComparer.Ordinal);
    readonly List<IReadOnlySet<HeldType>> unions = [];
    string asm;

    public AssemblyWalker(Policy policy, Allowlist allow, IReadOnlyDictionary<string, string[]> gameApi, IReadOnlySet<string> framework,
        IReadOnlySet<string>? game, PEReader pe, AssemblyFacts facts) {
        Policy = policy;
        GameApi = gameApi;
        this.framework = framework;
        this.game = game;
        Metadata = pe.GetMetadataReader();
        this.allow = allow;
        this.pe = pe;
        this.facts = facts;
        asm = facts.Name;
    }

    public Policy Policy { get; }
    public IReadOnlyDictionary<string, string[]> GameApi { get; }
    readonly IReadOnlySet<string> framework;
    readonly IReadOnlySet<string>? game;
    const string HarmonyAssembly = "0Harmony";

    /// <summary>
    /// Whether a member named like an API the walker or the policy models by name (a framework member,
    /// a game member such as a path source, or Harmony's for a "HarmonyLib." name) is that API: it lives
    /// in an assembly of the .NET shared framework or of the game (in 0Harmony for Harmony's names). A
    /// type of the same name defined here, in another of the mod's assemblies or in code that was not
    /// analyzed is ordinary code, with none of the modelled semantics (which narrow what a call counts
    /// as). A shipped file named like any of them is a name collision (Full access), so a reference to
    /// those names is the real one.
    /// </summary>
    public bool Models(EntityHandle h, string name) {
        var a = ExternalAssemblyOf(h) ?? asm;
        if (name.StartsWith("HarmonyLib.", StringComparison.Ordinal)) return string.Equals(a, HarmonyAssembly, StringComparison.OrdinalIgnoreCase);
        return framework.Contains(a) || (game != null ? game.Contains(a) : Policy.MatchesName(Policy.GameAssemblies, a));
    }
    public MetadataReader Metadata { get; }
    /// <summary>This assembly's name.</summary>
    public string Name => asm;

    /// <summary>Whether this assembly defines a type of that name ("Namespace.Outer/Inner").</summary>
    public bool DefinesType(string name) => facts.Types.ContainsKey(name);

    public void Run() {
        var md = Metadata;
        if (md.IsAssembly) asm = md.GetString(md.GetAssemblyDefinition().Name);
        facts.Name = asm;
        // A trusted library is not analyzed: what it does is the allowlist's responsibility.
        if (facts.Sha256 != null && allow.Hashes.Contains(facts.Sha256)) { facts.Classification = FileClass.LibraryKnown; return; }
        facts.Classification = allow.Names.Contains(asm) ? FileClass.LibraryImpersonation : FileClass.Mod;
        foreach (var ar in md.AssemblyReferences) facts.AssemblyRefs.Add(md.GetString(md.GetAssemblyReference(ar).Name));

        if (pe.PEHeaders.CorHeader is { } cor) {
            if ((cor.Flags & CorFlags.ILOnly) == 0)
                facts.Caps.Add(new("native-code", "assembly contains native code (not IL-only)", Origin.Structure));
            // ReadyToRun and NGEN images carry precompiled native bodies that the runtime may run
            // instead of the IL the check reads.
            if (cor.ManagedNativeHeaderDirectory.Size != 0 || (cor.Flags & CorFlags.ILLibrary) != 0)
                facts.Caps.Add(new("native-code", "assembly contains precompiled native code (ReadyToRun or NGEN)", Origin.Structure));
        }
        if (FindAttribute(md.GetModuleDefinition().GetCustomAttributes(), UnverifiableCodeAttribute) != null)
            facts.Caps.Add(new("raw-memory", "assembly is compiled with unsafe code enabled", Origin.Structure));
        foreach (var fh in md.FieldDefinitions) {
            var f = md.GetFieldDefinition(fh);
            var type = f.DecodeSignature(SignatureNames.Instance, null);
            facts.Fields.Add(Il.MemberName(md, fh));
            if (IsPointer(type)) {
                facts.Caps.Add(new("raw-memory", $"pointer field {Il.TypeName(md, f.GetDeclaringType())}::{md.GetString(f.Name)}", Origin.Structure));
                facts.PointerFields.Add(asm + "|" + Il.MemberName(md, fh));
            }
            // A Type or member field that other assemblies can assign holds values this
            // assembly's writers do not account for.
            // A public field of a private type (a closure's display class, an iterator) cannot be
            // named from another assembly.
            var access = f.Attributes & FieldAttributes.FieldAccessMask;
            bool open = (f.Attributes & FieldAttributes.InitOnly) == 0 && access is FieldAttributes.Public or FieldAttributes.Family or FieldAttributes.FamORAssem
                && TypeVisible(f.GetDeclaringType());
            if (open && (ReflectionApis.IsReflectionType(type) || ReflectionApis.IsReflectionArray(type))) facts.OpenFields.Add(asm + "|" + Il.MemberName(md, fh));
            // Likewise for a path field: other assemblies' stores to it are not this assembly's to trace.
            if (open && PathAtoms.IsPathType(type)) facts.OpenPathFields.Add(asm + "|" + Il.MemberName(md, fh));
        }

        RecordTypes();
        ScanResources();
        RecordAttributes();
        FindCompilerHelpers();
        foreach (var mh in md.MethodDefinitions) AnalyzeMethod(mh);
    }

    // ── manifest resources ───────────────────────────────────────────────────────────────

    // Every manifest resource must be readable and look like data: a program, library or archive
    // inside the assembly is code the check did not read.
    void ScanResources() {
        var md = Metadata;
        var dir = pe.PEHeaders.CorHeader?.ResourcesDirectory ?? default;
        foreach (var rh in md.ManifestResources) {
            var r = md.GetManifestResource(rh);
            var name = md.GetString(r.Name);
            // A nil implementation means the bytes are in this file (its kind reads as AssemblyFile).
            switch (r.Implementation.IsNil ? default(HandleKind?) : r.Implementation.Kind) {
                case null:
                    break;
                case HandleKind.AssemblyFile:
                    // A linked resource: the bytes are in a separate file of a multi-file assembly,
                    // which is not one of the files read here.
                    facts.EmbeddedBinaries.Add($"{name}: stored in the linked file {md.GetString(md.GetAssemblyFile((AssemblyFileHandle)r.Implementation).Name)}, which the check does not read");
                    continue;
                case HandleKind.AssemblyReference:
                    // Silence on purpose: the resource lives in a referenced assembly, which is checked
                    // as that assembly (its own resources if it is one of the mod's files, the
                    // AssemblyRef check otherwise).
                    continue;
                default:
                    facts.EmbeddedBinaries.Add($"{name}: stored somewhere the check cannot read");
                    continue;
            }
            if (EmbeddedResources.NamedLikeBinary(name)) facts.EmbeddedBinaries.Add($"{name}: named like a bundled program or library");
            if (Resource(dir, r.Offset) is not { } data) { facts.EmbeddedBinaries.Add($"{name}: cannot be read"); continue; }
            if (EmbeddedResources.Kind(data.AsSpan()) is { } what) facts.EmbeddedBinaries.Add($"{name}: {what}");
        }
    }

    // The bytes of an embedded resource: a 4-byte length and the data, at an offset into the
    // assembly's resources directory. Null if that does not fit inside the directory.
    byte[]? Resource(DirectoryEntry dir, long offset) {
        if (dir.Size <= 0 || offset < 0 || offset + 4 > dir.Size) return null;
        try {
            var block = pe.GetSectionData(dir.RelativeVirtualAddress);
            if (block.Length < dir.Size) return null;
            var reader = block.GetReader((int)offset, dir.Size - (int)offset);
            int length = reader.ReadInt32();
            return length < 0 || length > reader.RemainingBytes ? null : reader.ReadBytes(length);
        } catch (Exception e) when (e is BadImageFormatException or ArgumentOutOfRangeException or InvalidOperationException) {
            return null;  // reported as unreadable by the caller
        }
    }

    // ── attributes ───────────────────────────────────────────────────────────────────────

    // Harmony reads patch targets from attributes; other assemblies' attribute constructors run
    // when anything reads the attributes. Both are recorded here.
    void RecordAttributes() {
        var md = Metadata;
        foreach (var th in md.TypeDefinitions) {
            var t = md.GetTypeDefinition(th);
            string typeName = Il.TypeName(md, th);
            if (IsHarmonyAttributeType(t))
                facts.UndecodedPatches.Add($"{typeName} is a Harmony attribute type of the mod: Harmony reads the patch target its constructor sets, which the check does not decode");
            AttributeRefs(t.GetCustomAttributes(), typeName);
            // XmlSerializer loads the serializer assembly this attribute names (by name or by path)
            // for the type it is on.
            if (FindAttribute(t.GetCustomAttributes(), XmlSerializerAssemblyAttribute) != null)
                facts.Caps.Add(new("dynamic-load", $"[XmlSerializerAssembly] on {typeName}: XmlSerializer loads the assembly it names", Origin.Structure));
            // Harmony reads a patch class's attributes with inherit: true (GetCustomAttributes(true)
            // in HarmonyMethodExtensions.GetFromType) and merges them, so a [HarmonyPatch] on a base
            // class names the target of the derived class's patch methods too.
            var outer = PatchSpecs(t.GetCustomAttributes(), typeName);
            bool outerAll = FindAttribute(t.GetCustomAttributes(), HarmonyPatchAllAttribute) != null;
            var outsideBase = InheritPatchSpecs(t, typeName, outer, ref outerAll);
            bool patchClass = outer.Count > 0 || outerAll;
            foreach (var mh in t.GetMethods()) {
                var m = md.GetMethodDefinition(mh);
                var attrs = m.GetCustomAttributes();
                string simple = md.GetString(m.Name), name = typeName + "::" + simple;
                AttributeRefs(attrs, name);
                // Harmony finds these by name or by attribute in a patch class. Any type is
                // checked: requiring the class attribute as well would only add ways to miss one.
                if (simple == "TargetMethod" || FindAttribute(attrs, HarmonyTargetMethodAttribute) != null) targetMethods[mh] = TargetMethodKind.Single;
                else if (simple == "TargetMethods" || FindAttribute(attrs, HarmonyTargetMethodsAttribute) != null) targetMethods[mh] = TargetMethodKind.Multiple;
                patchClass |= HarmonyMethodNames.Contains(simple) || HasHarmonyAttribute(attrs);
                var own = PatchSpecs(attrs, name);
                if (own.Count > 0)
                    AddPatchTargets(own, outer, FindAttribute(attrs, HarmonyReversePatchAttribute) != null,
                        outerAll || FindAttribute(attrs, HarmonyPatchAllAttribute) != null, name, MethodEffect(m));
            }
            // A base class defined elsewhere can carry [HarmonyPatch] attributes this assembly does
            // not contain; for a class Harmony would use as a patch class, its target is not known.
            if (outsideBase != null && patchClass)
                facts.UndecodedPatches.Add($"{typeName} derives from {outsideBase}, which is not defined in this assembly: Harmony merges the [HarmonyPatch] attributes a patch class inherits, which the check cannot read");
            // The class's own and inherited attributes: the target of the patch methods that have none.
            if (outer.Count > 0) AddPatchTargets([], outer, false, outerAll, typeName, PatchClassEffect(typeName));
        }
    }

    // Names of the methods Harmony uses in a patch class (patches, targeting and lifecycle hooks).
    static readonly HashSet<string> HarmonyMethodNames = ["Prefix", "Postfix", "Transpiler", "Finalizer", "TargetMethod", "TargetMethods", "Prepare", "Cleanup"];

    bool HasHarmonyAttribute(CustomAttributeHandleCollection attrs) {
        var md = Metadata;
        foreach (var ah in attrs)
            if (AttributeTypeName(md.GetCustomAttribute(ah)).StartsWith("HarmonyLib.", StringComparison.Ordinal)) return true;
        return false;
    }

    // Adds the [HarmonyPatch] values of the base classes defined in this assembly to specs, and
    // returns the first base class defined elsewhere (other than the root types every class, struct
    // and delegate derives from), or null.
    string? InheritPatchSpecs(TypeDefinition t, string where, List<PatchSpec> specs, ref bool all) {
        var md = Metadata;
        var seen = new HashSet<TypeDefinitionHandle>();
        var b = t.BaseType;
        while (!b.IsNil) {
            if (b.Kind == HandleKind.TypeSpecification) {
                // A generic base class: its definition carries the attributes.
                var blob = md.GetBlobReader(md.GetTypeSpecification((TypeSpecificationHandle)b).Signature);
                if (blob.ReadSignatureTypeCode() != SignatureTypeCode.GenericTypeInstance) return Il.TypeName(md, b);
                blob.ReadByte();
                b = blob.ReadTypeHandle();
                continue;
            }
            if (b.Kind == HandleKind.TypeDefinition) {
                var h = (TypeDefinitionHandle)b;
                if (!seen.Add(h)) return null;  // a cycle (malformed metadata) adds nothing new; the runtime refuses to load it
                var bt = md.GetTypeDefinition(h);
                specs.AddRange(PatchSpecs(bt.GetCustomAttributes(), $"{where} (inherited from {Il.TypeName(md, h)})"));
                all |= FindAttribute(bt.GetCustomAttributes(), HarmonyPatchAllAttribute) != null;
                b = bt.BaseType;
                continue;
            }
            var name = Il.TypeName(md, b);
            return name is "System.Object" or "System.ValueType" or "System.Enum" or "System.MulticastDelegate" or "System.Delegate" ? null : name;
        }
        return null;
    }

    // Attribute constructors in other assemblies, for the Evaluator to resolve like calls. Only a
    // trusted library's constructor is applied (its profile); framework and game attribute
    // constructors only store their arguments, so they are recorded as classified: the policy does
    // not list framework attribute types, and every one would otherwise be unclassified. An attribute
    // of an assembly that was not analyzed is reported as a reference to that assembly.
    void AttributeRefs(CustomAttributeHandleCollection attrs, string owner) {
        var md = Metadata;
        foreach (var ah in attrs) {
            var ctor = md.GetCustomAttribute(ah).Constructor;
            if (ExternalAssemblyOf(ctor) is { } a) facts.AttributeRefs.Add((new(a, Il.MemberName(md, ctor), Classified: true), owner));
        }
    }

    // A type Harmony takes patch information from: it derives from one of Harmony's attribute
    // types (which carry the HarmonyMethod "info" field) or declares an "info" field of that type
    // itself. Harmony matches both by name, so a type named like Harmony's in another assembly
    // counts too.
    bool IsHarmonyAttributeType(TypeDefinition t) {
        var md = Metadata;
        if (!t.BaseType.IsNil && t.BaseType.Kind is HandleKind.TypeReference or HandleKind.TypeDefinition
            && Il.TypeName(md, t.BaseType).StartsWith("HarmonyLib.Harmony", StringComparison.Ordinal)) return true;
        foreach (var fh in t.GetFields()) {
            var f = md.GetFieldDefinition(fh);
            if (md.GetString(f.Name) == "info" && f.DecodeSignature(SignatureNames.Instance, null) == HarmonyMethodType) return true;
        }
        return false;
    }

    /// <summary>
    /// The id (negative) of a set of traced types and members: what a value is when the ways into a
    /// block disagree on which traced type or member it holds. Shared by every walker of this assembly,
    /// so the same set has the same id in every pass.
    /// </summary>
    public int Union(IEnumerable<HeldType> held) {
        var set = held.ToHashSet();
        var key = string.Join("\n", set.Select(h => $"{h.Type}|{h.Assembly}|{h.Member}|{h.Bounded}").Order(StringComparer.Ordinal));
        if (!unionIds.TryGetValue(key, out var id)) {
            unions.Add(set);
            unionIds[key] = id = -unions.Count;
        }
        return id;
    }

    /// <summary>The types and members of a set made by <see cref="Union"/>.</summary>
    public IReadOnlySet<HeldType> UnionOf(int id) => unions[-id - 1];

    /// <summary>How Harmony uses a method of this assembly when it is in a patch class.</summary>
    public TargetMethodKind TargetMethodOf(MethodDefinitionHandle h) => targetMethods.GetValueOrDefault(h);

    // One [HarmonyPatch] or [HarmonyDelegate]: each part null when the attribute leaves it out.
    readonly record struct PatchSpec(string? Type, string? Assembly, string? Name, int? MethodType, bool Delegate);

    // Combines a method's attributes with its class's as Harmony merges them: each part comes
    // from the method's attributes if any names it, else from the class's. When several
    // attributes name a part (their order is not defined), every combination is recorded.
    // With [HarmonyPatchAll], every method of the type is patched: member null.
    void AddPatchTargets(List<PatchSpec> own, List<PatchSpec> outer, bool reverse, bool all, string where, PatchEffect effect) {
        List<T> Part<T>(Func<PatchSpec, T?> get) where T : class {
            var mine = own.Select(get).OfType<T>().Distinct().ToList();
            return mine.Count > 0 ? mine : [.. outer.Select(get).OfType<T>().Distinct()];
        }
        var types = own.Where(s => s.Type != null).ToList() is { Count: > 0 } ot ? ot : outer.Where(s => s.Type != null).ToList();
        var names = Part(s => s.Name);
        var kinds = own.Where(s => s.MethodType != null).Select(s => s.MethodType).Distinct().ToList() is { Count: > 0 } ok ? ok
            : outer.Where(s => s.MethodType != null).Select(s => s.MethodType).Distinct().ToList();
        bool runs = reverse || own.Concat(outer).Any(s => s.Delegate);
        var members = new HashSet<string?>();
        bool named = all;
        if (all) members.Add(null);
        foreach (var n in all ? [] : names.Count > 0 ? names.Cast<string?>() : [null])
            foreach (var k in kinds.Count > 0 ? kinds : [null])
                if (PatchedMember(n, k, out var member)) { members.Add(member); named = true; }
        if (!named) {
            // Silence on purpose (facts only): with the method's, the class's and its base classes'
            // attributes merged (a base class outside this assembly is unresolved reflection, see
            // RecordAttributes), no method name and no constructor kind is named. The target then
            // comes from a TargetMethod, which the walker checks, or there is none and Harmony
            // reports an error instead of patching.
            facts.PatchTargets.Add(new(null, null, null, $"[HarmonyPatch] naming no method on {where}", runs, effect));
            return;
        }
        if (types.Count == 0) {
            // Silence on purpose (facts only): with every attribute merged as above, none names a
            // type. The target then comes from a TargetMethod (checked by the walker), or there is none.
            foreach (var m in members) facts.PatchTargets.Add(new(null, null, m, $"[HarmonyPatch] without a type on {where}", runs, effect));
            return;
        }
        foreach (var t in types)
            foreach (var m in members)
                facts.PatchTargets.Add(new(t.Type, t.Assembly, m, $"{(runs ? "runs" : effect == PatchEffect.Observes ? "observes" : "patches")} {t.Type}{(m != null ? "::" + m : "")}{(t.Assembly != null ? " in " + t.Assembly : "")}  <-  {where}", runs, effect));
    }

    // ── what patch methods can do ────────────────────────────────────────────────────────

    // Harmony's patch kinds, by method name or attribute. A transpiler (or a MonoMod IL manipulator)
    // rewrites the target; a reverse patch copies it (and runs it, see AddPatchTargets).
    static readonly Dictionary<string, string> PatchKindAttributes = new(StringComparer.Ordinal) {
        ["HarmonyLib.HarmonyPrefix"] = "Prefix",
        ["HarmonyLib.HarmonyPostfix"] = "Postfix",
        ["HarmonyLib.HarmonyFinalizer"] = "Finalizer",
        ["HarmonyLib.HarmonyTranspiler"] = "Transpiler",
        ["HarmonyLib.HarmonyILManipulator"] = "Transpiler",
        ["HarmonyLib.HarmonyReversePatch"] = "ReversePatch",
    };

    // Parameter types a patch method cannot change the patched member's arguments, instance or result
    // through: immutable values (an argument or __result of one of these types is a copy) and the
    // __originalMethod it is given. Anything else (a reference type, a struct that may hold references,
    // an array, a pointer, a by-reference parameter, __args) can change what the member works on.
    static readonly HashSet<string> InertPatchParameters = [
        "System.String", "System.Boolean", "System.Char", "System.SByte", "System.Byte", "System.Int16", "System.UInt16",
        "System.Int32", "System.UInt32", "System.Int64", "System.UInt64", "System.Single", "System.Double", "System.Decimal",
        "System.Reflection.MethodBase", "System.Reflection.MethodInfo",
    ];

    // The Harmony patch kind of a method ("Prefix", "Transpiler", ...), or null when Harmony would not
    // use it as a patch method.
    string? PatchKind(MethodDefinition m) {
        var md = Metadata;
        var simple = md.GetString(m.Name);
        if (simple is "Prefix" or "Postfix" or "Transpiler" or "Finalizer") return simple;
        foreach (var ah in m.GetCustomAttributes())
            if (PatchKindAttributes.TryGetValue(AttributeTypeName(md.GetCustomAttribute(ah)), out var kind)) return kind;
        return null;
    }

    // What one patch method can do to the member it patches. Only a prefix, postfix or finalizer that
    // returns nothing (a prefix returning bool can skip the original; a postfix or finalizer returning
    // a value replaces the result or the exception) and takes only inert parameters (or __state, the
    // patch's own storage) observes. A method Harmony would not use as a patch is counted as changing
    // the member (what it is for is not known).
    PatchEffect MethodEffect(MethodDefinition m) {
        var kind = PatchKind(m);
        if (kind == "Transpiler") return PatchEffect.Rewrites;
        if (kind is not ("Prefix" or "Postfix" or "Finalizer")) return PatchEffect.Changes;
        return PatchMethodObserves(m) ? PatchEffect.Observes : PatchEffect.Changes;
    }

    bool PatchMethodObserves(MethodDefinition m) {
        var md = Metadata;
        MethodSignature<string> sig;
        try { sig = m.DecodeSignature(new FrameworkTypeNames(this), null); } catch (BadImageFormatException) { return false; }
        if (sig.ReturnType != "System.Void") return false;
        var names = new string?[sig.ParameterTypes.Length];
        foreach (var ph in m.GetParameters()) {
            var p = md.GetParameter(ph);
            if (p.SequenceNumber >= 1 && p.SequenceNumber <= names.Length) names[p.SequenceNumber - 1] = md.GetString(p.Name);
        }
        for (int i = 0; i < sig.ParameterTypes.Length; i++)
            if (names[i] != "__state" && !InertPatchParameters.Contains(sig.ParameterTypes[i])) return false;
        return true;
    }

    // Signature type names in which a named type keeps its name only when it lives in the shared
    // framework: a type defined here, or in any other assembly, that is named like an inert framework
    // type (see InertPatchParameters) is not one (see Models). Primitive types are always the runtime's.
    sealed class FrameworkTypeNames(AssemblyWalker walker) : ISignatureTypeProvider<string, object?> {
        static readonly SignatureNames Names = SignatureNames.Instance;
        public string GetArrayType(string elementType, ArrayShape shape) => Names.GetArrayType(elementType, shape);
        public string GetByReferenceType(string elementType) => Names.GetByReferenceType(elementType);
        public string GetFunctionPointerType(MethodSignature<string> signature) => Names.GetFunctionPointerType(signature);
        public string GetGenericInstantiation(string genericType, ImmutableArray<string> typeArguments) => Names.GetGenericInstantiation(genericType, typeArguments);
        public string GetGenericMethodParameter(object? genericContext, int index) => Names.GetGenericMethodParameter(genericContext, index);
        public string GetGenericTypeParameter(object? genericContext, int index) => Names.GetGenericTypeParameter(genericContext, index);
        public string GetModifiedType(string modifier, string unmodifiedType, bool isRequired) => Names.GetModifiedType(modifier, unmodifiedType, isRequired);
        public string GetPinnedType(string elementType) => Names.GetPinnedType(elementType);
        public string GetPointerType(string elementType) => Names.GetPointerType(elementType);
        public string GetPrimitiveType(PrimitiveTypeCode typeCode) => Names.GetPrimitiveType(typeCode);
        public string GetSZArrayType(string elementType) => Names.GetSZArrayType(elementType);
        public string GetTypeFromDefinition(MetadataReader reader, TypeDefinitionHandle handle, byte rawTypeKind) => "?" + Il.TypeName(reader, handle);
        public string GetTypeFromReference(MetadataReader reader, TypeReferenceHandle handle, byte rawTypeKind) =>
            walker.framework.Contains(walker.AsmOfType(handle)) ? Il.TypeName(reader, handle) : "?" + Il.TypeName(reader, handle);
        public string GetTypeFromSpecification(MetadataReader reader, object? genericContext, TypeSpecificationHandle handle, byte rawTypeKind) => "?" + Il.TypeName(reader, handle);
    }

    /// <summary>
    /// What the patch methods of a patch class (declared in it, as Harmony collects them) can do to
    /// the member a [HarmonyPatch] on the class or its TargetMethod(s) names: a transpiler rewrites it;
    /// only observing patch methods observe; anything else, or no patch method the check recognizes,
    /// changes it.
    /// </summary>
    public PatchEffect PatchClassEffect(string typeName) {
        if (patchClassEffects.TryGetValue(typeName, out var cached)) return cached;
        var effect = PatchEffect.Changes;
        if (typeHandles.TryGetValue(typeName, out var th)) {
            var md = Metadata;
            var kinds = md.GetTypeDefinition(th).GetMethods().Select(mh => md.GetMethodDefinition(mh))
                .Where(m => PatchKind(m) != null).Select(MethodEffect).ToList();
            effect = kinds.Contains(PatchEffect.Rewrites) ? PatchEffect.Rewrites
                : kinds.Count > 0 && kinds.All(k => k == PatchEffect.Observes) ? PatchEffect.Observes : PatchEffect.Changes;
        }
        patchClassEffects[typeName] = effect;
        return effect;
    }

    // The member a name and Harmony MethodType patch (Normal 0, Getter 1, Setter 2, Constructor 3,
    // StaticConstructor 4), or false if they name none (every kind but the constructors needs a
    // name). Enumerator, Async and later kinds patch a compiler-generated method whose name is not
    // known here: member null, so the whole type counts.
    static bool PatchedMember(string? name, int? kind, out string? member) {
        member = kind switch {
            3 => ".ctor",
            4 => ".cctor",
            null or 0 => name,
            1 => "get_" + name,
            2 => "set_" + name,
            _ => null,
        };
        return kind is 3 or 4 || name != null;
    }

    List<PatchSpec> PatchSpecs(CustomAttributeHandleCollection attrs, string where) {
        var md = Metadata;
        var result = new List<PatchSpec>();
        foreach (var ah in attrs) {
            var a = md.GetCustomAttribute(ah);
            var type = AttributeTypeName(a);
            if (type is not (HarmonyPatchAttribute or HarmonyDelegateAttribute)) continue;
            if (DecodePatch(a, type == HarmonyDelegateAttribute, out var spec) is { } problem)
                facts.UndecodedPatches.Add($"[{type}] on {where}: {problem}");
            else
                result.Add(spec);
        }
        return result;
    }

    // Decodes the value of a [HarmonyPatch] or [HarmonyDelegate] by its constructor's parameter
    // types; the meaning of each is that of Harmony's own constructors (a type, a method name, a
    // type name and a method name, a MethodType). Returns why it cannot be decoded, or null.
    string? DecodePatch(CustomAttribute a, bool isDelegate, out PatchSpec spec) {
        var md = Metadata;
        spec = default;
        try {
            var sig = a.Constructor.Kind switch {
                HandleKind.MemberReference => md.GetMemberReference((MemberReferenceHandle)a.Constructor).DecodeMethodSignature(SignatureNames.Instance, null),
                HandleKind.MethodDefinition => md.GetMethodDefinition((MethodDefinitionHandle)a.Constructor).DecodeSignature(SignatureNames.Instance, null),
                _ => default(MethodSignature<string>?),
            };
            if (sig is not { } s) return "unexpected constructor";
            var b = md.GetBlobReader(a.Value);
            if (b.ReadUInt16() != 1) return "malformed attribute value";
            string? typeArg = null;
            int? kind = null;
            var strings = new List<string?>();
            foreach (var p in s.ParameterTypes) {
                switch (p) {
                    case "System.Type": typeArg = b.ReadSerializedString(); break;
                    case "System.String": strings.Add(b.ReadSerializedString()); break;
                    case "HarmonyLib.MethodType": kind = b.ReadInt32(); break;
                    case "HarmonyLib.MethodDispatchType": b.ReadInt32(); break;
                    case "System.Type[]": SkipArray(ref b, strings: true); break;
                    case "HarmonyLib.ArgumentType[]": SkipArray(ref b, strings: false); break;
                    default: return $"constructor parameter of type {p} is not one of Harmony's";
                }
            }
            // Harmony's attributes have no settable members a value could name; anything else
            // means the attribute is not the one whose constructors are modelled here.
            if (b.ReadUInt16() != 0) return "named arguments";
            string? typeName = typeArg, name = strings.Count > 0 ? strings[^1] : null;
            bool byName = false;
            // (string typeName, string methodName, MethodType): Harmony resolves the type with
            // AccessTools.TypeByName, which searches every loaded assembly.
            if (typeArg == null && strings.Count == 2) { typeName = strings[0]; byName = true; }
            string? target = null, where = null;
            if (typeName != null) {
                var (n, qualifier) = SplitTypeName(typeName);
                target = Policy.NormalizeTypeName(n);
                if (target.Length == 0) return "empty type name";
                // An unqualified typeof names a type of this assembly, else of the core library.
                where = qualifier ?? (!byName && facts.Types.ContainsKey(target) ? asm : null);
            }
            spec = new(target, where, name, kind, isDelegate);
            return null;
        } catch (BadImageFormatException) {
            return "attribute value does not decode";
        }
    }

    static void SkipArray(ref BlobReader b, bool strings) {
        int n = b.ReadInt32();
        for (int i = 0; i < n; i++) {  // -1 (null) skips nothing
            if (strings) b.ReadSerializedString();
            else b.ReadInt32();
        }
    }

    /// <summary>"Ns.Type+Nested`1[[Arg, ArgAsm]], Asm, Version=..." -> ("Ns.Type+Nested`1[[Arg, ArgAsm]]", "Asm").</summary>
    public static (string Name, string? Assembly) SplitTypeName(string s) {
        int depth = 0;
        for (int i = 0; i < s.Length; i++) {
            switch (s[i]) {
                case '[': depth++; break;
                case ']': depth--; break;
                case ',' when depth == 0: {
                    var rest = s[(i + 1)..];
                    int comma = rest.IndexOf(',', StringComparison.Ordinal);
                    var asmName = (comma >= 0 ? rest[..comma] : rest).Trim();
                    return (s[..i], asmName.Length > 0 ? asmName : null);
                }
            }
        }
        return (s, null);
    }

    // The type hierarchy and forwarders, which a library profile needs to find the code a call
    // reaches: overrides of a virtual method, and members inherited from a base type.
    void RecordTypes() {
        var md = Metadata;
        foreach (var th in md.TypeDefinitions) {
            var t = md.GetTypeDefinition(th);
            var supers = new List<string>();
            if (!t.BaseType.IsNil) supers.Add(Il.TypeName(md, t.BaseType));
            foreach (var ih in t.GetInterfaceImplementations()) supers.Add(Il.TypeName(md, md.GetInterfaceImplementation(ih).Interface));
            facts.Types[Il.TypeName(md, th)] = supers;
            typeHandles.TryAdd(Il.TypeName(md, th), th);
            // A transpiler's instructions are followed through Harmony's own CodeInstruction members; a
            // subclass can set an instruction's operand where the check does not look for it.
            if (supers.Count > 0 && supers[0] == HarmonyInstructionType)
                facts.UndecodedPatches.Add($"{Il.TypeName(md, th)} derives from Harmony's {HarmonyInstructionType}, whose operand the check follows only through Harmony's own members");
        }
        foreach (var eh in md.ExportedTypes)
            if (md.GetExportedType(eh).IsForwarder) facts.ForwardedTypes.Add(ExportedTypeName(eh, 0));
    }

    string ExportedTypeName(ExportedTypeHandle h, int depth) {
        var md = Metadata;
        var e = md.GetExportedType(h);
        var n = md.GetString(e.Name);
        if (e.Implementation.Kind == HandleKind.ExportedType && depth < 32) return ExportedTypeName((ExportedTypeHandle)e.Implementation, depth + 1) + "/" + n;
        var ns = md.GetString(e.Namespace);
        return ns.Length > 0 ? ns + "." + n : n;
    }

    public static bool IsPointer(string typeName) => typeName.Contains('*', StringComparison.Ordinal);

    public bool IsCompilerHelper(MethodDefinitionHandle h) => helpers.Contains(h);

    CustomAttribute? FindAttribute(CustomAttributeHandleCollection attrs, string typeName) {
        var md = Metadata;
        foreach (var ah in attrs) {
            var a = md.GetCustomAttribute(ah);
            if (AttributeTypeName(a) == typeName) return a;
        }
        return null;
    }

    string AttributeTypeName(CustomAttribute a) {
        var md = Metadata;
        return a.Constructor.Kind switch {
            HandleKind.MemberReference => Il.TypeName(md, Il.ParentType(md, md.GetMemberReference((MemberReferenceHandle)a.Constructor).Parent)),
            HandleKind.MethodDefinition => Il.TypeName(md, md.GetMethodDefinition((MethodDefinitionHandle)a.Constructor).GetDeclaringType()),
            _ => "?",
        };
    }

    // ── node keys ────────────────────────────────────────────────────────────────────────

    // The assembly a type token ultimately lives in (its AssemblyReference), else this one.
    string AsmOfType(EntityHandle h, int depth = 0) {
        var md = Metadata;
        if (depth > 32) return asm;
        if (h.Kind == HandleKind.TypeReference) {
            var rs = md.GetTypeReference((TypeReferenceHandle)h).ResolutionScope;
            if (rs.Kind == HandleKind.AssemblyReference) return md.GetString(md.GetAssemblyReference((AssemblyReferenceHandle)rs).Name);
            if (rs.Kind == HandleKind.TypeReference) return AsmOfType(rs, depth + 1);
        } else if (h.Kind == HandleKind.TypeSpecification) {
            var b = md.GetBlobReader(md.GetTypeSpecification((TypeSpecificationHandle)h).Signature);
            if (b.ReadSignatureTypeCode() == SignatureTypeCode.GenericTypeInstance) { b.ReadByte(); return AsmOfType(b.ReadTypeHandle(), depth + 1); }
        }
        return asm;
    }

    /// <summary>
    /// The assembly a referenced method or field lives in, or null if it is defined in this
    /// module. "" means the reference names no assembly the check can determine; the Evaluator
    /// counts that as code that was not analyzed.
    /// </summary>
    public string? ExternalAssemblyOf(EntityHandle h) {
        var md = Metadata;
        if (h.Kind == HandleKind.MethodSpecification) h = md.GetMethodSpecification((MethodSpecificationHandle)h).Method;
        return h.Kind switch {
            // Defined here: analyzed as part of this assembly.
            HandleKind.MethodDefinition or HandleKind.FieldDefinition => null,
            HandleKind.MemberReference => ParentAssembly(md.GetMemberReference((MemberReferenceHandle)h).Parent, 0),
            // A type token alone runs no code. Its assembly is still in the AssemblyRef table,
            // which the Evaluator checks as a whole.
            HandleKind.TypeReference or HandleKind.TypeDefinition or HandleKind.TypeSpecification => null,
            _ => "",
        };
    }

    // The assembly of a member reference's parent: a type, or a method of this module (vararg call site).
    string? ParentAssembly(EntityHandle parent, int depth) {
        var md = Metadata;
        if (depth > 32) return "";
        switch (parent.Kind) {
            case HandleKind.MethodDefinition:
            case HandleKind.TypeDefinition:
                return null;  // defined here: analyzed as part of this assembly
            case HandleKind.TypeReference: {
                var rs = md.GetTypeReference((TypeReferenceHandle)parent).ResolutionScope;
                return rs.Kind switch {
                    HandleKind.AssemblyReference => md.GetString(md.GetAssemblyReference((AssemblyReferenceHandle)rs).Name),
                    HandleKind.TypeReference => ParentAssembly(rs, depth + 1),
                    HandleKind.ModuleDefinition => null,  // this module
                    // Another module of a multi-file assembly, or a type forwarded through this
                    // assembly's exported types: neither is followed, so it counts as not analyzed.
                    _ => "",
                };
            }
            case HandleKind.TypeSpecification: {
                var b = md.GetBlobReader(md.GetTypeSpecification((TypeSpecificationHandle)parent).Signature);
                var code = b.ReadSignatureTypeCode();
                if (code == SignatureTypeCode.GenericTypeInstance) { b.ReadByte(); return ParentAssembly(b.ReadTypeHandle(), depth + 1); }
                // Members of array types (Get, Set, Address, .ctor) are provided by the runtime itself.
                if (code is SignatureTypeCode.Array or SignatureTypeCode.SZArray) return null;
                return "";
            }
        }
        // A global member of another module: not part of what was read.
        return "";
    }

    /// <summary>The declared type of a field token, or null if the token is not a field.</summary>
    public string? FieldType(EntityHandle h) {
        var md = Metadata;
        switch (h.Kind) {
            case HandleKind.FieldDefinition:
                return md.GetFieldDefinition((FieldDefinitionHandle)h).DecodeSignature(SignatureNames.Instance, null);
            case HandleKind.MemberReference: {
                var mr = md.GetMemberReference((MemberReferenceHandle)h);
                return mr.GetKind() == MemberReferenceKind.Field ? mr.DecodeFieldSignature(SignatureNames.Instance, null) : null;
            }
        }
        return null;
    }

    /// <summary>
    /// Node key of the Type or member field a method of this module returns unchanged (an
    /// auto-property or "=> field" getter), or null. Virtual methods do not qualify: the call can
    /// reach an override.
    /// </summary>
    public string? GetterField(EntityHandle h) {
        if (h.Kind != HandleKind.MethodDefinition) return null;
        var mh = (MethodDefinitionHandle)h;
        if (getters.TryGetValue(mh, out var cached)) return cached;
        string? result = null;
        var m = Metadata.GetMethodDefinition(mh);
        if ((m.Attributes & MethodAttributes.Virtual) == 0 && m.RelativeVirtualAddress != 0) {
            var il = pe.GetMethodBody(m.RelativeVirtualAddress).GetILBytes() ?? [];
            // ldsfld F; ret   or   ldarg.0; ldfld F; ret
            int at = il.Length == 6 && il[0] == 0x7E && il[5] == 0x2A ? 1
                : il.Length == 7 && il[0] == 0x02 && il[1] == 0x7B && il[6] == 0x2A ? 2 : -1;
            if (at > 0) {
                var f = MetadataTokens.EntityHandle(Il.ReadInt32(il, at));
                if (f.Kind is HandleKind.FieldDefinition or HandleKind.MemberReference && FieldType(f) is { } t && ReflectionApis.IsReflectionType(t))
                    result = KeyOf(f);
            }
        }
        getters[mh] = result;
        return result;
    }

    /// <summary>Whether a type token is a bare generic parameter (T in typeof(T)).</summary>
    public bool IsGenericParameter(EntityHandle h) {
        if (h.Kind != HandleKind.TypeSpecification) return false;
        var b = Metadata.GetBlobReader(Metadata.GetTypeSpecification((TypeSpecificationHandle)h).Signature);
        return b.ReadSignatureTypeCode() is SignatureTypeCode.GenericTypeParameter or SignatureTypeCode.GenericMethodParameter;
    }

    /// <summary>Type arguments of a generic method instantiation (MethodSpecification), or empty.</summary>
    public ImmutableArray<string> MethodTypeArguments(EntityHandle h) =>
        h.Kind == HandleKind.MethodSpecification
            ? Metadata.GetMethodSpecification((MethodSpecificationHandle)h).DecodeSignature(SignatureNames.Instance, null)
            : [];

    /// <summary>
    /// Type arguments of a generic method instantiation with the assembly each lives in (see
    /// <see cref="TypeAssembly"/>; null for a primitive type, found by name in the core library), or empty.
    /// </summary>
    public IReadOnlyList<(string Name, string? Assembly)> MethodTypeArgumentTypes(EntityHandle h) {
        if (h.Kind != HandleKind.MethodSpecification) return [];
        try {
            return [.. Metadata.GetMethodSpecification((MethodSpecificationHandle)h).DecodeSignature(TypeShapes.Instance, null)
                .Select(t => (t.Name, t.Definition.IsNil ? null : TypeAssembly(t.Definition)))];
        } catch (BadImageFormatException) {
            return [("?", "")];  // undecodable: an assembly the check cannot determine
        }
    }

    /// <summary>
    /// The assembly a type token lives in: the assembly it references, this one for a type defined
    /// here (and for arrays and pointers, whose members the runtime provides), "" when that cannot be
    /// determined (another module, an exported type).
    /// </summary>
    public string TypeAssembly(EntityHandle h, int depth = 0) {
        var md = Metadata;
        if (depth > 32) return "";
        switch (h.Kind) {
            case HandleKind.TypeDefinition:
                return asm;
            case HandleKind.TypeReference: {
                var rs = md.GetTypeReference((TypeReferenceHandle)h).ResolutionScope;
                return rs.Kind switch {
                    HandleKind.AssemblyReference => md.GetString(md.GetAssemblyReference((AssemblyReferenceHandle)rs).Name),
                    HandleKind.TypeReference => TypeAssembly(rs, depth + 1),
                    HandleKind.ModuleDefinition => asm,
                    _ => "",
                };
            }
            case HandleKind.TypeSpecification: {
                var b = md.GetBlobReader(md.GetTypeSpecification((TypeSpecificationHandle)h).Signature);
                if (b.ReadSignatureTypeCode() != SignatureTypeCode.GenericTypeInstance) return asm;
                b.ReadByte();
                return TypeAssembly(b.ReadTypeHandle(), depth + 1);
            }
        }
        return "";
    }

    /// <summary>Node key ("Assembly|Type::Member") of a method or field token, or null.</summary>
    public string? KeyOf(EntityHandle h) {
        var md = Metadata;
        if (h.Kind == HandleKind.MethodSpecification) h = md.GetMethodSpecification((MethodSpecificationHandle)h).Method;
        switch (h.Kind) {
            case HandleKind.MethodDefinition:
            case HandleKind.FieldDefinition:
                return asm + "|" + Il.MemberName(md, h);
            case HandleKind.MemberReference: {
                var mr = md.GetMemberReference((MemberReferenceHandle)h);
                var type = Il.ParentType(md, mr.Parent);
                return AsmOfType(type) + "|" + Il.TypeName(md, type) + "::" + md.GetString(mr.Name);
            }
        }
        return null;
    }

    // ── compiler inline-array helpers ────────────────────────────────────────────────────

    void FindCompilerHelpers() {
        var md = Metadata;
        foreach (var th in md.TypeDefinitions) {
            var t = md.GetTypeDefinition(th);
            if (t.IsNested || md.GetString(t.Namespace).Length > 0 || md.GetString(t.Name) != HelperType) continue;
            foreach (var mh in t.GetMethods()) {
                var m = md.GetMethodDefinition(mh);
                if (!HelperNames.Contains(md.GetString(m.Name)) || m.GetGenericParameters().Count != 2 || m.RelativeVirtualAddress == 0) continue;
                if (MatchesHelperTemplate(m)) helpers.Add(mh);
            }
        }
    }

    // A helper body may only load its two arguments, call the expected Unsafe/MemoryMarshal
    // members, and return.
    bool MatchesHelperTemplate(MethodDefinition m) {
        try {
            var il = pe.GetMethodBody(m.RelativeVirtualAddress).GetILBytes() ?? [];
            if (il.Length > 32) return false;
            foreach (var ins in Il.Decode(il)) {
                short v = ins.OpCode.Value;
                if (v == OpCodes.Ldarg_0.Value || v == OpCodes.Ldarg_1.Value || v == OpCodes.Ret.Value) continue;
                if (v == OpCodes.Call.Value && HelperCalls.Contains(Il.MemberName(Metadata, MetadataTokens.EntityHandle(Il.Token(il, ins))))) continue;
                return false;
            }
            return true;
        } catch (Exception e) when (e is InvalidDataException or BadImageFormatException or ArgumentException) {
            return false;  // not a valid helper: analyzed like any other method
        }
    }

    /// <summary>Null if a call to a validated helper uses it as the compiler does; otherwise why not.</summary>
    public string? HelperCallProblem(MethodSpecificationHandle spec, string helper, Slot[] args) {
        var md = Metadata;
        ImmutableArray<TypeShape> targs;
        try { targs = md.GetMethodSpecification(spec).DecodeSignature(TypeShapes.Instance, null); } catch (BadImageFormatException) { return "undecodable type arguments"; }
        if (targs.Length != 2) return "unexpected type arguments";
        int length;
        TypeShape element;
        if (FrameworkInlineArrayLength(targs[0]) is int n0) {
            if (targs[0].Args.IsDefaultOrEmpty || targs[0].Args.Length != 1) return "buffer type arguments do not match";
            length = n0;
            element = targs[0].Args[0];
        } else if (targs[0].Definition.Kind == HandleKind.TypeDefinition) {
            var buffer = md.GetTypeDefinition((TypeDefinitionHandle)targs[0].Definition);
            var attr = FindAttribute(buffer.GetCustomAttributes(), InlineArrayAttribute);
            if (attr == null) return "buffer type is not an inline array";
            var blob = md.GetBlobReader(attr.Value.Value);
            if (blob.Length < 6 || blob.ReadUInt16() != 1) return "malformed InlineArray attribute";
            length = blob.ReadInt32();
            var instanceFields = buffer.GetFields().Select(md.GetFieldDefinition)
                .Where(f => (f.Attributes & FieldAttributes.Static) == 0).ToList();
            if (instanceFields.Count != 1) return "buffer type does not have exactly one field";
            element = instanceFields[0].DecodeSignature(TypeShapes.Instance, null);
            if (element.Name.StartsWith('!') && int.TryParse(element.Name.AsSpan(1), NumberStyles.None, CultureInfo.InvariantCulture, out var gi)) {
                if (targs[0].Args.IsDefaultOrEmpty || gi >= targs[0].Args.Length) return "buffer type arguments do not match";
                element = targs[0].Args[gi];
            }
        } else {
            return "buffer type is neither a framework inline array nor defined in this assembly";
        }
        if (element.ToString() != targs[1].ToString()) return $"element type {targs[1]} does not match buffer element {element}";

        if (helper.StartsWith("InlineArrayFirstElementRef", StringComparison.Ordinal)) return null;
        if (args.Length < 2 || args[1].Tag != Tag.Int) return "index or length is not a constant";
        int n = args[1].Number;
        bool ok = helper.StartsWith("InlineArrayElementRef", StringComparison.Ordinal) ? n >= 0 && n < length : n >= 0 && n <= length;
        return ok ? null : $"constant {n} is outside the buffer length {length}";
    }

    // Length of System.Runtime.CompilerServices.InlineArrayN<T> from the base class library
    // (InlineArray2 to InlineArray16), or null if the type is not one of them.
    int? FrameworkInlineArrayLength(TypeShape type) {
        if (type.Definition.Kind != HandleKind.TypeReference) return null;
        var m = FrameworkInlineArray().Match(type.Name);
        if (!m.Success || !int.TryParse(m.Groups[1].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var n) || n < 2 || n > 16) return null;
        var scope = Metadata.GetTypeReference((TypeReferenceHandle)type.Definition).ResolutionScope;
        if (scope.Kind != HandleKind.AssemblyReference) return null;
        var asmName = Metadata.GetString(Metadata.GetAssemblyReference((AssemblyReferenceHandle)scope).Name);
        return asmName is "System.Runtime" or "System.Private.CoreLib" ? n : null;
    }

    // ── managed references and static data ───────────────────────────────────────────────

    // Argument indices that hold managed references (ref, out and in parameters, and this in an
    // instance method of a value type) or paths, and what the method returns.
    MethodShape Shape(MethodDefinition m, MethodSignature<string> sig) {
        var md = Metadata;
        var byref = new HashSet<int>();
        var paths = new HashSet<int>();
        var reflection = new HashSet<int>();
        var declared = new List<DeclaredType?>();
        int self = sig.Header.IsInstance ? 1 : 0;
        if (self == 1) {
            var baseType = md.GetTypeDefinition(m.GetDeclaringType()).BaseType;
            if (!baseType.IsNil && Il.TypeName(md, baseType) is "System.ValueType" or "System.Enum") byref.Add(0);
            // this: an instance of the declaring type or of a type derived from it
            declared.Add(new(Il.TypeName(md, m.GetDeclaringType()), asm, false));
        }
        ImmutableArray<TypeShape> shapes = [];
        try { shapes = m.DecodeSignature(TypeShapes.Instance, null).ParameterTypes; } catch (BadImageFormatException) { /* no declared types: values stay unknown */ }
        for (int i = 0; i < sig.ParameterTypes.Length; i++) {
            if (sig.ParameterTypes[i].EndsWith('&')) byref.Add(i + self);
            if (PathAtoms.IsPathType(sig.ParameterTypes[i])) paths.Add(i + self);
            if (ReflectionApis.IsReflectionType(sig.ParameterTypes[i])) reflection.Add(i + self);
            declared.Add(i < shapes.Length ? Declared(shapes[i]) : null);
        }
        return new(byref, paths, sig.ReturnType.EndsWith('&'), PathAtoms.IsPathType(sig.ReturnType)) {
            ReflectionArgs = reflection,
            ReflectionReturn = ReflectionApis.IsReflectionType(sig.ReturnType),
            ArgTypes = declared,
        };
    }

    // ── declared types ───────────────────────────────────────────────────────────────────

    /// <summary>
    /// The class or struct a signature type names, with the assembly it lives in; null for anything
    /// else (primitives, arrays, pointers, references, generic parameters), whose run-time type the
    /// walker does not use.
    /// </summary>
    public DeclaredType? Declared(TypeShape t) {
        if (t.Definition.IsNil || t.Name.StartsWith('!')) return null;
        return new(t.Name, TypeAssembly(t.Definition), false);
    }

    /// <summary>The type a type token names (castclass, isinst, box, newobj's type), or null as in <see cref="Declared(TypeShape)"/>.</summary>
    public DeclaredType? DeclaredOfToken(EntityHandle h, bool exact) {
        var md = Metadata;
        switch (h.Kind) {
            case HandleKind.TypeDefinition or HandleKind.TypeReference:
                return new(Il.TypeName(md, h), TypeAssembly(h), exact);
            case HandleKind.TypeSpecification: {
                var b = md.GetBlobReader(md.GetTypeSpecification((TypeSpecificationHandle)h).Signature);
                if (b.ReadSignatureTypeCode() != SignatureTypeCode.GenericTypeInstance) return null;  // arrays, pointers, generic parameters
                b.ReadByte();
                var g = b.ReadTypeHandle();
                return new(Il.TypeName(md, g), TypeAssembly(g), exact);
            }
        }
        return null;
    }

    /// <summary>The declared return type of a method token, or null (see <see cref="Declared(TypeShape)"/>).</summary>
    public DeclaredType? ReturnDeclared(EntityHandle h) {
        var md = Metadata;
        try {
            if (h.Kind == HandleKind.MethodSpecification) return null;  // a generic method's return type is often its type argument
            var sig = h.Kind switch {
                HandleKind.MethodDefinition => md.GetMethodDefinition((MethodDefinitionHandle)h).DecodeSignature(TypeShapes.Instance, null),
                HandleKind.MemberReference when md.GetMemberReference((MemberReferenceHandle)h).GetKind() == MemberReferenceKind.Method
                    => md.GetMemberReference((MemberReferenceHandle)h).DecodeMethodSignature(TypeShapes.Instance, null),
                _ => default(MethodSignature<TypeShape>?),
            };
            return sig is { } s ? Declared(s.ReturnType) : null;
        } catch (BadImageFormatException) {
            return null;  // undecodable: nothing is known about the value
        }
    }

    /// <summary>The declared type of a field token, or null (see <see cref="Declared(TypeShape)"/>).</summary>
    public DeclaredType? FieldDeclared(EntityHandle h) {
        var md = Metadata;
        try {
            return h.Kind switch {
                HandleKind.FieldDefinition => Declared(md.GetFieldDefinition((FieldDefinitionHandle)h).DecodeSignature(TypeShapes.Instance, null)),
                HandleKind.MemberReference when md.GetMemberReference((MemberReferenceHandle)h).GetKind() == MemberReferenceKind.Field
                    => Declared(md.GetMemberReference((MemberReferenceHandle)h).DecodeFieldSignature(TypeShapes.Instance, null)),
                _ => null,
            };
        } catch (BadImageFormatException) {
            return null;  // undecodable: nothing is known about the value
        }
    }

    /// <summary>The declared types of a method body's locals, or empty if they do not decode.</summary>
    public IReadOnlyList<DeclaredType?> LocalDeclared(MethodBodyBlock body) {
        if (body.LocalSignature.IsNil) return [];
        try {
            return [.. Metadata.GetStandaloneSignature(body.LocalSignature).DecodeLocalSignature(TypeShapes.Instance, null).Select(Declared)];
        } catch (BadImageFormatException) {
            return [];  // no declared types: loads stay unknown
        }
    }

    // A type that code in another assembly can name: public, or nested public or protected in such a type.
    bool TypeVisible(TypeDefinitionHandle h) {
        var md = Metadata;
        for (int depth = 0; depth < 32 && !h.IsNil; depth++) {
            var t = md.GetTypeDefinition(h);
            var v = t.Attributes & TypeAttributes.VisibilityMask;
            if (!t.IsNested) return v == TypeAttributes.Public;
            if (v is not (TypeAttributes.NestedPublic or TypeAttributes.NestedFamily or TypeAttributes.NestedFamORAssem)) return false;
            h = t.GetDeclaringType();
        }
        return true;  // nested too deep to follow: counts as visible (fails closed)
    }

    // ── predicates ───────────────────────────────────────────────────────────────────────

    readonly Dictionary<MethodDefinitionHandle, string?> nameFilters = [];

    // Member types whose Name a predicate may test (MemberInfo.Name, as the compiler references it).
    static readonly HashSet<string> NameGetters = [
        "System.Reflection.MemberInfo::get_Name", "System.Reflection.MethodBase::get_Name", "System.Reflection.MethodInfo::get_Name",
        "System.Reflection.PropertyInfo::get_Name", "System.Reflection.FieldInfo::get_Name", "System.Reflection.EventInfo::get_Name",
    ];

    /// <summary>
    /// For a predicate method of this assembly (a lambda given to LINQ's First, Any, ...): the constant
    /// member name it requires of its argument, or null. Proved from the IL, as the compiler emits
    /// <c>m =&gt; m.Name == "C" &amp;&amp; ...</c>: one parameter (besides <c>this</c>), returns bool, no
    /// exception handlers; it begins by loading that parameter's Name and comparing it with a constant
    /// (string equality), and then either returns the comparison or branches on false to a block that
    /// returns false; nothing branches into the test. So it returns true only for a member of that name.
    /// </summary>
    public string? ConstantNameFilter(MethodDefinitionHandle h) {
        if (nameFilters.TryGetValue(h, out var cached)) return cached;
        string? result = null;
        try { result = NameFilterOf(h); } catch (Exception e) when (e is BadImageFormatException or InvalidOperationException or ArgumentException) { result = null; }
        nameFilters[h] = result;
        return result;
    }

    string? NameFilterOf(MethodDefinitionHandle h) {
        var md = Metadata;
        var m = md.GetMethodDefinition(h);
        if (m.RelativeVirtualAddress == 0) return null;
        var sig = m.DecodeSignature(SignatureNames.Instance, null);
        if (sig.ParameterTypes.Length != 1 || sig.ReturnType != "System.Boolean") return null;
        int arg = sig.Header.IsInstance ? 1 : 0;
        var body = pe.GetMethodBody(m.RelativeVirtualAddress);
        if (body.ExceptionRegions.Length > 0) return null;
        var il = body.GetILBytes() ?? [];
        var code = Il.Decode(il);
        if (code.Count < 5) return null;
        short Op(int i) => code[i].OpCode.Value;
        // A callee named like the framework member but defined elsewhere is not that member (see Models).
        string Callee(int i) {
            var callee = MetadataTokens.EntityHandle(Il.Token(il, code[i]));
            var name = Il.MemberName(md, callee);
            return Models(callee, name) ? name : "?";
        }
        bool loadsArg = arg == 0 ? Op(0) == OpCodes.Ldarg_0.Value : Op(0) == OpCodes.Ldarg_1.Value || (Op(0) == OpCodes.Ldarg_S.Value && il[code[0].OperandOffset] == arg);
        if (!loadsArg) return null;
        if (Op(1) != OpCodes.Callvirt.Value && Op(1) != OpCodes.Call.Value || !NameGetters.Contains(Callee(1))) return null;
        if (Op(2) != OpCodes.Ldstr.Value) return null;
        var name = md.GetUserString(MetadataTokens.UserStringHandle(Il.Token(il, code[2]) & 0xFFFFFF));
        if (Op(3) != OpCodes.Call.Value && Op(3) != OpCodes.Callvirt.Value) return null;
        var compare = Callee(3);
        var cps = Il.Signature(md, MetadataTokens.EntityHandle(Il.Token(il, code[3])))?.ParameterTypes ?? [];
        bool equality = compare == "System.String::op_Equality" || (compare == "System.String::Equals" && cps.All(p => p == "System.String")
            && cps.Length == (Op(3) == OpCodes.Call.Value && cps.Length == 2 ? 2 : 1));
        if (!equality) return null;
        // Nothing may enter the test anywhere but at its start.
        foreach (var ins in code)
            foreach (var t in Il.BranchTargets(il, ins))
                if (t > code[0].Offset && t <= code[4].Offset) return null;
        if (Op(4) == OpCodes.Ret.Value) return name;
        if (Op(4) != OpCodes.Brfalse.Value && Op(4) != OpCodes.Brfalse_S.Value) return null;
        var targets = Il.BranchTargets(il, code[4]);
        if (targets.Count != 1) return null;
        int k = code.FindIndex(i => i.Offset == targets[0]);
        // The false branch returns false.
        return k > 4 && k + 1 < code.Count && Op(k) == OpCodes.Ldc_I4_0.Value && Op(k + 1) == OpCodes.Ret.Value ? name : null;
    }

    // ── iterators ────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// For a compiler-generated iterator class of this assembly (what a method with yield return
    /// creates): the node key of the field its enumerator's Current returns, or null when the class
    /// does not have exactly that shape. Checked: a sealed class nested in another, deriving from
    /// System.Object and implementing only the iterator interfaces (no ICollection, whose CopyTo a
    /// caller may use instead); every get_Current returns the Type or member field "&lt;&gt;2__current";
    /// every GetEnumerator returns the object itself or a new instance of the class.
    /// </summary>
    public string? IteratorElementField(string typeName) {
        if (iterators.TryGetValue(typeName, out var cached)) return cached;
        string? result = null;
        try { result = CheckIterator(typeName); } catch (Exception e) when (e is BadImageFormatException or InvalidOperationException or ArgumentException) { result = null; }
        iterators[typeName] = result;
        return result;
    }

    static readonly HashSet<string> IteratorInterfaces = [
        "System.Collections.Generic.IEnumerable`1", "System.Collections.IEnumerable", "System.Collections.Generic.IEnumerator`1",
        "System.Collections.IEnumerator", "System.IDisposable",
    ];

    string? CheckIterator(string typeName) {
        var md = Metadata;
        if (!typeHandles.TryGetValue(typeName, out var th)) return null;
        var t = md.GetTypeDefinition(th);
        if (!t.IsNested || (t.Attributes & TypeAttributes.Sealed) == 0 || t.BaseType.IsNil || Il.TypeName(md, t.BaseType) != "System.Object") return null;
        foreach (var ih in t.GetInterfaceImplementations())
            if (!IteratorInterfaces.Contains(Il.TypeName(md, md.GetInterfaceImplementation(ih).Interface))) return null;
        FieldDefinitionHandle current = default;
        foreach (var fh in t.GetFields()) {
            var f = md.GetFieldDefinition(fh);
            if (md.GetString(f.Name) == "<>2__current" && ReflectionApis.IsReflectionType(f.DecodeSignature(SignatureNames.Instance, null))) current = fh;
        }
        if (current.IsNil) return null;
        bool sawCurrent = false;
        foreach (var mh in t.GetMethods()) {
            var m = md.GetMethodDefinition(mh);
            var name = md.GetString(m.Name);
            if (name.EndsWith("get_Current", StringComparison.Ordinal)) {
                if (m.RelativeVirtualAddress == 0) return null;
                var il = pe.GetMethodBody(m.RelativeVirtualAddress).GetILBytes() ?? [];
                // ldarg.0; ldfld <>2__current; ret
                if (il.Length != 7 || il[0] != 0x02 || il[1] != 0x7B || il[6] != 0x2A
                    || MetadataTokens.EntityHandle(Il.ReadInt32(il, 2)) != (EntityHandle)current) return null;
                sawCurrent = true;
            } else if (name.EndsWith("GetEnumerator", StringComparison.Ordinal)) {
                if (m.RelativeVirtualAddress == 0 || !ReturnsSelf(pe.GetMethodBody(m.RelativeVirtualAddress), th)) return null;
            }
        }
        return sawCurrent ? asm + "|" + Il.MemberName(md, current) : null;
    }

    // Whether every ret of a GetEnumerator body returns the object itself (ldarg.0), a new instance
    // of the class, or another of the class's GetEnumerator methods (checked the same way). Only the
    // instructions the compiler emits there are accepted; anything else fails.
    bool ReturnsSelf(MethodBodyBlock body, TypeDefinitionHandle type) {
        var md = Metadata;
        var il = body.GetILBytes() ?? [];
        var code = Il.Decode(il);
        bool OwnMember(EntityHandle h) => h.Kind switch {
            HandleKind.MethodDefinition => md.GetMethodDefinition((MethodDefinitionHandle)h).GetDeclaringType() == type,
            HandleKind.FieldDefinition => md.GetFieldDefinition((FieldDefinitionHandle)h).GetDeclaringType() == type,
            _ => false,
        };
        var localSelf = new Dictionary<int, bool>();
        for (int round = 0; round < 4; round++) {
            var stack = new List<bool>();
            var stored = new Dictionary<int, bool>();
            bool Pop() { if (stack.Count == 0) throw new InvalidOperationException("stack underflow"); var x = stack[^1]; stack.RemoveAt(stack.Count - 1); return x; }
            foreach (var ins in code) {
                short v = ins.OpCode.Value;
                int op = ins.OperandOffset;
                if (v == OpCodes.Nop.Value) continue;
                if (v == OpCodes.Ldarg_0.Value) { stack.Add(true); continue; }
                if (v is var a && (a == OpCodes.Ldarg_1.Value || a == OpCodes.Ldarg_2.Value || a == OpCodes.Ldarg_3.Value || a == OpCodes.Ldarg_S.Value)) { stack.Add(false); continue; }
                if ((v >= OpCodes.Ldc_I4_M1.Value && v <= OpCodes.Ldc_I4_8.Value) || v == OpCodes.Ldc_I4_S.Value || v == OpCodes.Ldc_I4.Value) { stack.Add(false); continue; }
                int local = v >= OpCodes.Stloc_0.Value && v <= OpCodes.Stloc_3.Value ? v - OpCodes.Stloc_0.Value : v == OpCodes.Stloc_S.Value ? il[op] : -1;
                if (local >= 0) { bool x = Pop(); stored[local] = (stored.TryGetValue(local, out var p) ? p : true) && x; continue; }
                local = v >= OpCodes.Ldloc_0.Value && v <= OpCodes.Ldloc_3.Value ? v - OpCodes.Ldloc_0.Value : v == OpCodes.Ldloc_S.Value ? il[op] : -1;
                if (local >= 0) { stack.Add(localSelf.TryGetValue(local, out var l) ? l : true); continue; }
                if (v == OpCodes.Dup.Value) { var x = Pop(); stack.Add(x); stack.Add(x); continue; }
                if (v == OpCodes.Pop.Value) { Pop(); continue; }
                if (v == OpCodes.Br.Value || v == OpCodes.Br_S.Value) { stack.Clear(); continue; }
                if (v == OpCodes.Brtrue.Value || v == OpCodes.Brtrue_S.Value || v == OpCodes.Brfalse.Value || v == OpCodes.Brfalse_S.Value) { Pop(); continue; }
                if (v == OpCodes.Beq.Value || v == OpCodes.Beq_S.Value || v == OpCodes.Bne_Un.Value || v == OpCodes.Bne_Un_S.Value) { Pop(); Pop(); continue; }
                if (v == OpCodes.Ret.Value) { if (!Pop()) return false; stack.Clear(); continue; }
                if (ins.OpCode.OperandType is not (OperandType.InlineMethod or OperandType.InlineField)) return false;
                var h = MetadataTokens.EntityHandle(Il.Token(il, ins));
                if (v == OpCodes.Ldfld.Value && OwnMember(h)) { Pop(); stack.Add(false); continue; }
                if (v == OpCodes.Stfld.Value && OwnMember(h)) { Pop(); Pop(); continue; }
                if (v == OpCodes.Call.Value && Il.MemberName(md, h) == "System.Environment::get_CurrentManagedThreadId") { stack.Add(false); continue; }
                if ((v == OpCodes.Call.Value || v == OpCodes.Callvirt.Value) && OwnMember(h)
                    && md.GetString(md.GetMethodDefinition((MethodDefinitionHandle)h).Name).EndsWith("GetEnumerator", StringComparison.Ordinal)) { Pop(); stack.Add(true); continue; }
                if (v == OpCodes.Newobj.Value && OwnMember(h)) {
                    int n = md.GetMethodDefinition((MethodDefinitionHandle)h).DecodeSignature(SignatureNames.Instance, null).ParameterTypes.Length;
                    for (int i = 0; i < n; i++) Pop();
                    stack.Add(true);
                    continue;
                }
                return false;
            }
            if (stored.Count == localSelf.Count && stored.All(kv => localSelf.TryGetValue(kv.Key, out var c) && c == kv.Value)) return true;
            localSelf = stored;
        }
        return false;  // did not settle
    }

    /// <summary>
    /// Size in bytes of a compiler-emitted static data field (an RVA field of
    /// &lt;PrivateImplementationDetails&gt;), or null if the field is anything else.
    /// </summary>
    public int? StaticDataSize(EntityHandle h) {
        var md = Metadata;
        if (h.Kind != HandleKind.FieldDefinition) return null;
        var f = md.GetFieldDefinition((FieldDefinitionHandle)h);
        if ((f.Attributes & FieldAttributes.HasFieldRVA) == 0 || (f.Attributes & FieldAttributes.Static) == 0) return null;
        var owner = md.GetTypeDefinition(f.GetDeclaringType());
        if (owner.IsNested || md.GetString(owner.Namespace).Length > 0 || md.GetString(owner.Name) != HelperType) return null;
        var type = f.DecodeSignature(TypeShapes.Instance, null);
        if (type.Definition.Kind == HandleKind.TypeDefinition) {
            int size = md.GetTypeDefinition((TypeDefinitionHandle)type.Definition).GetLayout().Size;
            return size > 0 ? size : null;
        }
        return type.Name switch {
            "System.Byte" or "System.SByte" => 1,
            "System.Int16" or "System.UInt16" or "System.Char" => 2,
            "System.Int32" or "System.UInt32" or "System.Single" => 4,
            "System.Int64" or "System.UInt64" or "System.Double" => 8,
            _ => null,
        };
    }

    /// <summary>A type token rendered as a <see cref="TypeShape"/> (generic arguments included), or null.</summary>
    public string? TypeShapeName(EntityHandle h) {
        if (h.Kind != HandleKind.TypeSpecification) return null;
        try {
            return Metadata.GetTypeSpecification((TypeSpecificationHandle)h).DecodeSignature(TypeShapes.Instance, null).ToString();
        } catch (BadImageFormatException) {
            return null;
        }
    }

    /// <summary>The element type of the Span or ReadOnlySpan a constructor reference belongs to (or of any
    /// generic type with one type argument a member reference belongs to, List&lt;T&gt;), or null.</summary>
    public string? SpanElementType(EntityHandle h) {
        var md = Metadata;
        if (h.Kind != HandleKind.MemberReference) return null;
        var parent = md.GetMemberReference((MemberReferenceHandle)h).Parent;
        if (parent.Kind != HandleKind.TypeSpecification) return null;
        try {
            var shape = md.GetTypeSpecification((TypeSpecificationHandle)parent).DecodeSignature(TypeShapes.Instance, null);
            return shape.Args.IsDefaultOrEmpty || shape.Args.Length != 1 ? null : shape.Args[0].ToString();
        } catch (BadImageFormatException) {
            return null;
        }
    }

    // ── methods ──────────────────────────────────────────────────────────────────────────

    // Attributes the compiler, the debugger and analyzers put on methods: nothing calls a method because of them.
    static bool IsCompilerAttribute(string type) =>
        type.StartsWith("System.Runtime.CompilerServices.", StringComparison.Ordinal) || type.StartsWith("System.Diagnostics.", StringComparison.Ordinal)
        || type.StartsWith("System.Runtime.Versioning.", StringComparison.Ordinal) || type is "System.ObsoleteAttribute" or "System.CLSCompliantAttribute";

    // Why code that is not analyzed with the mod may call a method with arguments of its choosing: a
    // virtual method can be called through its base or interface, a public member of a visible type
    // by any assembly, a Harmony method by Harmony, a method with other attributes by whatever looks
    // for them (a loader). Null when only the analyzed code can call it (directly, or through a
    // delegate or reflection, which the Evaluator accounts for).
    string? CalledFromOutside(MethodDefinitionHandle mh, MethodDefinition m) {
        var md = Metadata;
        if ((m.Attributes & MethodAttributes.Virtual) != 0) return "is virtual (an override is called through its base)";
        var simple = md.GetString(m.Name);
        if (HarmonyMethodNames.Contains(simple) || targetMethods.ContainsKey(mh)) return "is a Harmony patch method (Harmony calls it)";
        var access = m.Attributes & MethodAttributes.MemberAccessMask;
        if (access is MethodAttributes.Public or MethodAttributes.Family or MethodAttributes.FamORAssem && TypeVisible(m.GetDeclaringType()))
            return "is public";
        foreach (var ah in m.GetCustomAttributes()) {
            var type = AttributeTypeName(md.GetCustomAttribute(ah));
            if (!IsCompilerAttribute(type)) return $"has the attribute {type}, by which a loader or library can call it";
        }
        return null;
    }

    // Abstract methods have no body, and delegate members (Invoke, BeginInvoke, ...) are
    // provided by the runtime; neither runs code of the assembly's choosing.
    static bool IsBodilessByDesign(MethodDefinition m) =>
        (m.Attributes & MethodAttributes.Abstract) != 0
        || ((m.ImplAttributes & MethodImplAttributes.CodeTypeMask) == MethodImplAttributes.Runtime
            && (m.ImplAttributes & MethodImplAttributes.InternalCall) == 0);

    void AnalyzeMethod(MethodDefinitionHandle mh) {
        var md = Metadata;
        var m = md.GetMethodDefinition(mh);
        var name = Il.TypeName(md, m.GetDeclaringType()) + "::" + md.GetString(m.Name);
        var mf = new MethodFacts {
            Key = asm + "|" + name,
            Name = name,
            IsPublic = (m.Attributes & MethodAttributes.MemberAccessMask) == MethodAttributes.Public,
            IsVirtual = (m.Attributes & MethodAttributes.Virtual) != 0,
            CalledFromOutside = CalledFromOutside(mh, m),
            Bodiless = m.RelativeVirtualAddress == 0,
        };
        facts.Methods.Add(mf);

        var imp = m.GetImport();
        if (!imp.Module.IsNil) {
            var lib = md.GetString(md.GetModuleReference(imp.Module).Name);
            var entry = md.GetString(imp.Name);
            if (entry.Length == 0) entry = md.GetString(m.Name);
            facts.PInvokes.Add(lib + "!" + entry);
            mf.Caps.Add(new("native-code", $"{name}  ->  {lib}!{entry}  (P/Invoke)", Origin.Structure));
            return;
        }
        try {
            var sig = m.DecodeSignature(SignatureNames.Instance, null);
            if (IsPointer(sig.ReturnType) || sig.ParameterTypes.Any(IsPointer))
                mf.Caps.Add(new("raw-memory", $"pointer parameter or return type in {name}", Origin.Structure));
            if (m.RelativeVirtualAddress != 0)
                new MethodWalker(this, mf, helpers.Contains(mh), Shape(m, sig), TargetMethodOf(mh)).Walk(pe.GetMethodBody(m.RelativeVirtualAddress));
            else if (!IsBodilessByDesign(m))
                // An extern method that is neither P/Invoke nor runtime-provided: an
                // [UnsafeAccessor] (reaches a member of any type by name, private ones included,
                // without referencing it) or an internal call. Nothing of what it reaches is visible.
                mf.UnresolvedReflection.Add($"{name} has no body (UnsafeAccessor or internal call): reaches members the check cannot see");
        } catch (Exception) {
            // Deliberately broad: a method whose signature or body cannot be decoded is
            // unanalyzable, which is a finding (Full access), not a crash.
            mf.DecodeFailed = true;
        }
    }
}
