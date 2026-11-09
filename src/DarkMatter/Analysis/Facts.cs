// SPDX-License-Identifier: MIT
namespace DarkMatter.Analysis;

/// <summary>What an input file turned out to be.</summary>
internal enum FileClass {
    /// <summary>Managed code, analyzed as part of the mod.</summary>
    Mod,
    /// <summary>On the allowlist by hash; not analyzed (its library profile applies).</summary>
    LibraryKnown,
    /// <summary>Carries a trusted library's name with an unknown hash; analyzed as mod code.</summary>
    LibraryImpersonation,
    /// <summary>A binary without .NET metadata.</summary>
    Native,
    /// <summary>Could not be read.</summary>
    Error,
}

/// <summary>How a capability was found.</summary>
internal enum Origin {
    /// <summary>A direct reference in the IL; file operations of this kind are path-traced.</summary>
    Reference,
    /// <summary>A type or member reached by reflection from a constant.</summary>
    Reflection,
    /// <summary>A call to a game method in the game-API map.</summary>
    GameApi,
    /// <summary>A call into a trusted library, from its library profile.</summary>
    Library,
    /// <summary>A property of the assembly or method as a whole.</summary>
    Structure,
}

internal sealed record Evidence(string Cap, string Detail, Origin Origin);

/// <summary>
/// A method or field this assembly references in another assembly. The Evaluator decides what
/// the assembly is: mod code, a trusted library, the game, the framework, or code that was not
/// analyzed. A framework member must be <see cref="Classified"/> by the policy.
/// </summary>
/// <param name="Assembly">Name of the assembly the member's type lives in; "" if it cannot be determined.</param>
/// <param name="Member">"Namespace.Type::Member".</param>
/// <param name="Classified">A capability or safe rule matched it.</param>
/// <param name="Signature">A method's parameter types, joined by <see cref="SignatureSeparator"/>; null for a
/// field or a member whose signature cannot be decoded. Classifies a game member the runtime finds on a
/// framework base type (see Boundary.GameTarget) as a direct reference to it would be.</param>
internal sealed record ExternalRef(string Assembly, string Member, bool Classified, string? Signature = null) {
    public const char SignatureSeparator = '\u001f';

    /// <summary>The parameter types of <see cref="Signature"/>, or null.</summary>
    public IReadOnlyList<string>? Parameters => Signature == null ? null : Signature.Length == 0 ? [] : Signature.Split(SignatureSeparator);
}

/// <summary>
/// A reflection operation on a value the walker traced to a node (see <see cref="Nodes"/>): a Type or
/// member field, a parameter, or what a method returns. Resolved per mod from every value the node
/// is given (see <c>Evaluation.ReflectionProvenance</c>).
/// </summary>
/// <param name="Node">The node id.</param>
/// <param name="Detail">Evidence text.</param>
/// <param name="Invokes">The operation runs or instantiates code (Invoke, SetValue, CreateInstance), not just a lookup.</param>
/// <param name="WritesFields">The operation writes fields of the types the node holds (FieldInfo.SetValue).</param>
/// <param name="Members">For a lookup on a type the node holds: the members reached, null for any member.</param>
/// <param name="NameNode">For a lookup whose member name is a string parameter of the method: that
/// parameter's node, whose values (from every call) name the members reached (see <see cref="MethodFacts.StringArguments"/>).</param>
/// <param name="Lookup">The lookup method ("GetField", "Property", ...) for <paramref name="NameNode"/>.</param>
internal sealed record FieldReflection(string Node, string Detail, bool Invokes, bool WritesFields = false, IReadOnlyList<string>? Members = null,
    string? NameNode = null, string? Lookup = null);

/// <summary>
/// Reflection whose target the walker could not trace to one member, but only to a type or any type
/// derived from it (the run-time type of an object of that declared type), or to any type of one
/// assembly (Assembly.GetType of a name built at run time). The Evaluator decides by where the type
/// lives: the game's or the mod's code is bounded (deep game access), anything else is unresolved.
/// </summary>
/// <param name="Type">"Namespace.Type", or "*" for any type of <paramref name="Assembly"/>.</param>
/// <param name="Assembly">As in <see cref="ReflectedType.Assembly"/>.</param>
/// <param name="Detail">Evidence text.</param>
internal sealed record BoundedReflection(string Type, string? Assembly, string Detail);

/// <summary>
/// Node ids for values the walker traces across methods: "field:KEY" (a Type or member field),
/// "arg:KEY#N" (argument N of method KEY, counting <c>this</c>; "#*" for every argument), "ret:KEY"
/// (what method KEY returns). KEY is a node key ("Assembly|Namespace.Type::Member").
/// </summary>
/// A source "member:NODE" stands for the members of the types NODE holds, which were looked up
/// (and their capabilities granted) where the lookup was.
internal static class Nodes {
    public const string FieldPrefix = "field:", ArgPrefix = "arg:", ReturnPrefix = "ret:", MemberPrefix = "member:", InstancePrefix = "inst:";
    public static string MemberOf(string node) => node.StartsWith(MemberPrefix, StringComparison.Ordinal) ? node : MemberPrefix + node;
    public static string Field(string key) => FieldPrefix + key;
    public static string Arg(string key, int index) => index < 0 ? $"{ArgPrefix}{key}#*" : $"{ArgPrefix}{key}#{index}";
    public static string Return(string key) => ReturnPrefix + key;
    /// <summary>The run-time types of the instance Harmony passes as <c>__instance</c> to patch method KEY (D7).</summary>
    public static string Instance(string key) => InstancePrefix + key;

    /// <summary>
    /// Type nodes made from the members another node holds (D5, D6): the declared types of those members
    /// (FieldType, PropertyType, ReturnType: exactly those types), or the run-time types of the values read
    /// through them (FieldInfo.GetValue, PropertyInfo.GetValue: those types or types derived from them).
    /// "how:NODE"; each holds a type only for a member whose declared type is known and of the matching kind.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, (MemberKind Kind, bool Value)> TypeOf = new Dictionary<string, (MemberKind, bool)>(StringComparer.Ordinal) {
        ["fieldtype:"] = (MemberKind.Field, false),
        ["propertytype:"] = (MemberKind.Property, false),
        ["returntype:"] = (MemberKind.Method, false),
        ["fieldvalue:"] = (MemberKind.Field, true),
        ["propertyvalue:"] = (MemberKind.Property, true),
    };

    /// <summary>The type node for <paramref name="kind"/> and <paramref name="value"/> made from the members <paramref name="node"/> holds (see <see cref="TypeOf"/>).</summary>
    public static string TypeOfNode(MemberKind kind, bool value, string node) =>
        TypeOf.First(kv => kv.Value == (kind, value)).Key + node;

    /// <summary>For a node made by <see cref="TypeOfNode"/>: its kind, whether it is of values, and the node it is made from; null otherwise.</summary>
    public static (MemberKind Kind, bool Value, string Source)? TypeOfParts(string node) {
        foreach (var (prefix, how) in TypeOf)
            if (node.StartsWith(prefix, StringComparison.Ordinal)) return (how.Kind, how.Value, node[prefix.Length..]);
        return null;
    }

    /// <summary>The node key of the field, method or method whose argument the node is.</summary>
    public static string Key(string node) {
        for (bool stripped = true; stripped;) {
            stripped = false;
            if (TypeOfParts(node) is { } parts) { node = parts.Source; stripped = true; }
            if (node.StartsWith(MemberPrefix, StringComparison.Ordinal)) { node = node[MemberPrefix.Length..]; stripped = true; }
        }
        if (node.StartsWith(InstancePrefix, StringComparison.Ordinal)) return node[InstancePrefix.Length..];
        if (node.StartsWith(ArgPrefix, StringComparison.Ordinal)) {
            int hash = node.LastIndexOf('#');
            return node[ArgPrefix.Length..(hash > 0 ? hash : node.Length)];
        }
        return node.StartsWith(FieldPrefix, StringComparison.Ordinal) ? node[FieldPrefix.Length..]
            : node.StartsWith(ReturnPrefix, StringComparison.Ordinal) ? node[ReturnPrefix.Length..] : node;
    }

    /// <summary>Evidence text for a node: "Type::field", "argument 1 of Type::Method", "what Type::Method returns".</summary>
    public static string Describe(string node) {
        if (node.StartsWith(MemberPrefix, StringComparison.Ordinal)) return "a member of the types of " + Describe(node[MemberPrefix.Length..]);
        if (TypeOfParts(node) is var (kind, value, source))
            return value ? $"the run-time type of a value read through {Describe(source)}" : $"the declared {kind switch { MemberKind.Field => "field", MemberKind.Property => "property", _ => "return" }} type of {Describe(source)}";
        var key = Key(node);
        var name = key[(key.IndexOf('|', StringComparison.Ordinal) + 1)..];
        if (node.StartsWith(InstancePrefix, StringComparison.Ordinal)) return $"the run-time type of the __instance Harmony passes to {name}";
        if (node.StartsWith(ArgPrefix, StringComparison.Ordinal)) return $"argument {node[(node.LastIndexOf('#') + 1)..]} of {name}";
        if (node.StartsWith(ReturnPrefix, StringComparison.Ordinal)) return $"what {name} returns";
        return name;
    }
}

/// <summary>
/// A type reached by reflection: looked up by a constant name, or a typeof (or a type argument)
/// whose members are looked up or which is instantiated. The Evaluator decides, by where the type
/// lives, what reaching it can do (see <c>Evaluation.TypeAccess</c>).
/// </summary>
/// <param name="Type">"Namespace.Type", nested types as "Outer/Inner".</param>
/// <param name="Assembly">The assembly the type lives in; null when it is found by name in whatever
/// loaded assembly has it (a type name without an assembly qualifier), "" when it cannot be determined.</param>
/// <param name="Members">The members reached ("Run", "get_Value", ".ctor"), or null for any member of the type.</param>
/// <param name="Detail">Evidence text.</param>
/// <param name="PatchTarget">Looked up in a Harmony TargetMethod(s): the member found is patched, not run.</param>
/// <param name="NameNode">As in <see cref="FieldReflection.NameNode"/>: the members are named by a string parameter.</param>
/// <param name="Lookup">The lookup method for <paramref name="NameNode"/>.</param>
/// <param name="Patch">For a <paramref name="PatchTarget"/>: what the patch class's patch methods can do to it.</param>
/// <param name="NullTestOnly">Found by a name with no assembly part, and the result is only tested for null
/// (see <c>MethodWalker.OnlyNullTested</c>): a name nothing has finds no type and runs nothing (H9).</param>
/// <param name="Derived">The type is known only up to its derived types (the run-time type of a value of that
/// declared type): the members of the game's types that derive from it are reached too (D9).</param>
internal sealed record ReflectedType(string Type, string? Assembly, IReadOnlyList<string>? Members, string Detail, bool PatchTarget = false,
    string? NameNode = null, string? Lookup = null, PatchEffect Patch = PatchEffect.Changes, bool NullTestOnly = false, bool Derived = false);

/// <summary>What the patch methods of a Harmony patch can do to the member they patch.</summary>
internal enum PatchEffect {
    /// <summary>Change its arguments, its result or whether it runs, or the check cannot tell (the default).</summary>
    Changes,
    /// <summary>Only observe: every patch method is a prefix, postfix or finalizer that returns nothing
    /// and takes only values it cannot change the member through (see <c>AssemblyWalker.PatchMethodObserves</c>).</summary>
    Observes,
    /// <summary>Rewrite its instructions: a transpiler (which can also change everything).</summary>
    Rewrites,
}

/// <summary>A type or member a node (see <see cref="Nodes"/>) can hold, from one value given to it.</summary>
/// <param name="Type">"Namespace.Type" of the type, or of the member's declaring type; "*" for any type of
/// <paramref name="Assembly"/> (with <paramref name="Bounded"/>).</param>
/// <param name="Assembly">As in <see cref="ReflectedType.Assembly"/>.</param>
/// <param name="Member">A member (MethodInfo, FieldInfo, ...) of the type, whose capabilities were
/// granted where it was looked up; false for the Type itself, which grants them where it is used.</param>
/// <param name="Bounded">The type or any type derived from it (see <see cref="BoundedReflection"/>).</param>
/// <param name="Value">For a member found by a constant name on exactly <paramref name="Type"/>: its kind and
/// declared type (see <see cref="MemberValue"/>); null when that is not known. Cleared whenever the entry stops
/// standing for that one member (a member looked up on it, a member known only up to its type).</param>
internal readonly record struct HeldType(string Type, string? Assembly, bool Member, bool Bounded = false, MemberValue? Value = null);

/// <summary>What a member a lookup finds is: a field, a property or a method (D2).</summary>
internal enum MemberKind { Field, Property, Method }

/// <summary>
/// The declared type of the member a lookup by a constant name finds on exactly one type (D2, D5, D6): a field's
/// type, a property's type (its getter returns the same), a method's return type. Known only when every member
/// of that kind the name can find on the type and its base types (in any casing, see
/// <c>ReflectionApis.MemberMatches</c>) has the same declared type, a class or struct (not a generic parameter,
/// an array, a pointer or a primitive), and every one of those types is the mod's own (in the assembly walked)
/// or the game's (from the game-API map).
/// </summary>
/// <param name="Kind">The kind of member the lookup finds.</param>
/// <param name="Type">"Namespace.Type" of the declared type (a generic instantiation as its definition).</param>
/// <param name="Asm">The assembly it lives in ("" when that cannot be determined).</param>
internal readonly record struct MemberValue(MemberKind Kind, string Type, string Asm);

/// <summary>
/// A file operation and where its path comes from, as a set of path atoms: an origin ("own",
/// "game", "saves", "temp", "documents", "documents-folder" for the Documents folder itself,
/// "user-folder", "environment", "absolute"), "untraced", or a reference the Evaluator resolves
/// across the mod: "arg:KEY#N" (argument N of method KEY, from its callers), "field:KEY" (from every
/// store to the field), "ret:KEY" (from what the method returns), "game:ATOM" (ATOM followed directly
/// by the game's folder names, so the Documents folder itself is the game's folder), and "tail:",
/// "mid:" and "in:" ATOM (appended, followed by more, made into something else; see PathAtoms).
/// See <c>Evaluation.FileAccess</c>. A path literal that is a web address is "url".
/// </summary>
/// <param name="Kind">Whether it reads or writes.</param>
/// <param name="Member">The file API called.</param>
/// <param name="Path">Path atoms of its path operand.</param>
/// <param name="Url">The operation also accepts a web address in place of a path (see the policy's
/// <c>fileAccess.urls</c>): one whose path is untraced or a web address connects to the internet.</param>
internal sealed record FileOp(FileOpKind Kind, string Member, IReadOnlySet<string> Path, bool Url);

/// <summary>
/// What the walker needs to know about the game's types from the game-API map (D2): the declared types of every
/// game type's members (see <see cref="AssemblyFacts.MemberTypes"/>; every game type has an entry) and each game
/// type's base type other than System.Object.
/// </summary>
internal sealed record GameTypes(IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>> Members, IReadOnlyDictionary<string, string> Bases);

/// <summary>An [InlineArray] type: how many times its one field repeats, and that field's type (see <see cref="AssemblyWalker.ElementKey"/>).</summary>
internal sealed record InlineArrayShape(int Length, string Element);

/// <summary>A Harmony patch target declared by attribute ([HarmonyPatch], [HarmonyDelegate]).</summary>
/// <param name="Type">"Namespace.Type" of the patched type, or null if no attribute names one (the
/// target then comes from a TargetMethod, which the walker checks, or there is none).</param>
/// <param name="Assembly">Assembly the type lives in: the attribute's assembly qualifier, or this
/// assembly for an unqualified typeof of a type defined here; null when the type is found by
/// name in whatever assembly has it (a string type name, or an unqualified name of a type not
/// defined here, which the runtime looks up in the core library).</param>
/// <param name="Member">Patched member ("Method", "get_Property", ".ctor"), or null when the
/// attributes do not determine it (the whole type then counts).</param>
/// <param name="Detail">Evidence text.</param>
/// <param name="Runs">The mod runs the target's own code: a reverse patch or a Harmony delegate,
/// not only a patch around it.</param>
/// <param name="Effect">What the patch methods can do to the target (see <see cref="PatchEffect"/>).</param>
internal sealed record PatchTarget(string? Type, string? Assembly, string? Member, string Detail, bool Runs, PatchEffect Effect = PatchEffect.Changes);

/// <summary>
/// Process.Start of a folder the method has just created (Directory.CreateDirectory on the same value):
/// it opens the folder in the file manager, provided the path is in the mod's or the game's folders
/// (see <c>Evaluation.FileAccess</c>).
/// </summary>
/// <param name="Member">The start API called.</param>
/// <param name="Path">Path atoms of the folder (see <see cref="FileOp"/>).</param>
internal sealed record FolderOpen(string Member, IReadOnlySet<string> Path);

/// <summary>
/// A member a Harmony transpiler rewrites, as the walker found it: the value given as a manual patch's
/// original, or returned by the TargetMethod(s) of a patch class with a transpiler. Deep game access covers
/// a rewrite only of the game's code (see the policy's "code-rewrite"); the Evaluator places the target
/// and counts anything else, or a target it cannot place, as system access ("rewrite-outside-game").
/// </summary>
/// <param name="Type">"Namespace.Type" of the member's declaring type ("*" for any type of
/// <paramref name="Assembly"/>), or null when the target is held in <paramref name="Node"/> or cannot be placed.</param>
/// <param name="Assembly">As in <see cref="ReflectedType.Assembly"/>.</param>
/// <param name="Node">A node (see <see cref="Nodes"/>) whose values are the target.</param>
/// <param name="Derived">The member is known only up to <paramref name="Type"/> and the types derived from it.</param>
/// <param name="Detail">Evidence text.</param>
/// <param name="IfRewrites">A reverse patch, whose stand-in may carry a transpiler the check does not
/// see: counts only when the mod rewrites code ("code-rewrite").</param>
internal sealed record RewriteTarget(string? Type, string? Assembly, string? Node, bool Derived, string Detail, bool IfRewrites = false);

/// <summary>How Harmony uses a method of a patch class.</summary>
internal enum TargetMethodKind {
    None,
    /// <summary>TargetMethod or [HarmonyTargetMethod]: returns the one method to patch.</summary>
    Single,
    /// <summary>TargetMethods or [HarmonyTargetMethods]: returns the methods to patch.</summary>
    Multiple,
}

/// <summary>Everything the analyzer learns about one method, in a single pass over its IL.</summary>
internal sealed class MethodFacts {
    /// <summary>"Assembly|Namespace.Type::Method". Overloads share a key.</summary>
    public required string Key { get; init; }
    /// <summary>"Namespace.Type::Method".</summary>
    public required string Name { get; init; }
    public bool IsPublic { get; init; }
    /// <summary>A call can dispatch to an override (virtual, abstract or interface method).</summary>
    public bool IsVirtual { get; init; }
    public bool DecodeFailed { get; set; }
    public List<Evidence> Caps { get; } = [];
    /// <summary>
    /// Why code outside the analysis may call this method with any arguments (virtual, public on a
    /// visible type, a Harmony patch method, attributes a loader may look for), or null. Its Type and
    /// member parameters are then not traced (see <see cref="Nodes"/>).
    /// </summary>
    public string? CalledFromOutside { get; init; }
    /// <summary>The method has no IL body here (abstract, extern, runtime-provided): it returns nothing the check sees.</summary>
    public bool Bodiless { get; set; }
    public List<string> UnresolvedReflection { get; } = [];
    /// <summary>Reflection traced only to a type or its derived types, or to an assembly (see <see cref="BoundedReflection"/>).</summary>
    public List<BoundedReflection> BoundedReflection { get; } = [];
    /// <summary>
    /// Members typed (see <see cref="MemberValue"/>) on a game type found by name (AccessTools.TypeByName and the
    /// like, D5): the type name and evidence text. The walker types them from the game-API map; the Evaluator
    /// counts each as unresolved reflection unless the game alone has a type of that name (the mod, the framework,
    /// a policy rule or a trusted library having one too means the lookup can find that one instead).
    /// </summary>
    public List<(string Type, string Detail)> TypedByName { get; } = [];
    public List<string> ComActivation { get; } = [];
    public HashSet<string> Callees { get; } = [];
    public HashSet<string> FieldLoads { get; } = [];
    public HashSet<string> FieldStores { get; } = [];
    /// <summary>
    /// Nodes (see <see cref="Nodes"/>) this method gives a resolved Type or member: a field it stores,
    /// an argument it passes, a value it returns. Node -> what is given.
    /// </summary>
    public Dictionary<string, HashSet<HeldType>> ReflectionStores { get; } = [];
    /// <summary>
    /// Strings this method passes to a string parameter of a method of this assembly ("arg:KEY#N"),
    /// for parameters that name a member to look up: "=text" for a constant, "@NODE" for this method's
    /// own string parameter, "?" for anything else.
    /// </summary>
    public Dictionary<string, HashSet<string>> StringArguments { get; } = [];
    /// <summary>Nodes this method gives the value of another node: node -> source nodes.</summary>
    public Dictionary<string, HashSet<string>> FieldCopies { get; } = [];
    /// <summary>Nodes this method gives an untraced value, or whose value it can change through an address or a delegate.</summary>
    public HashSet<string> UntrackedStores { get; } = [];
    public List<FieldReflection> FieldReflection { get; } = [];
    /// <summary>Types whose fields this method writes through reflection; "*" when the type is not known,
    /// "Namespace.Type+" for that type or any type derived from it.</summary>
    public HashSet<string> ReflectionFieldWrites { get; } = [];
    /// <summary>Members and types of other assemblies this method references.</summary>
    public HashSet<ExternalRef> ExternalRefs { get; } = [];
    /// <summary>Types reached by reflection, resolved by the Evaluator by where they live.</summary>
    public List<ReflectedType> ReflectedTypes { get; } = [];
    /// <summary>Members Harmony transpilers rewrite, placed by the Evaluator (see <see cref="RewriteTarget"/>).</summary>
    public List<RewriteTarget> RewriteTargets { get; } = [];
    /// <summary>File operations, with the path atoms of each (see <see cref="FileOp"/>).</summary>
    public List<FileOp> FileOps { get; } = [];
    /// <summary>Folders this method opens in the file manager (see <see cref="FolderOpen"/>).</summary>
    public List<FolderOpen> FolderOpens { get; } = [];
    /// <summary>
    /// Path atoms of the values this method passes as path-typed arguments, keyed "CALLEE#N" (N
    /// counts <c>this</c>); "CALLEE#*" when a method is taken as a delegate, so its arguments come
    /// from calls the check does not see. A store to one of its own arguments counts as a call to itself.
    /// </summary>
    public Dictionary<string, HashSet<string>> PathArguments { get; } = [];
    /// <summary>Path atoms of the values this method stores into path-typed fields, by field node key.</summary>
    public Dictionary<string, HashSet<string>> PathStores { get; } = [];
    /// <summary>Path atoms of the values this method returns, if it returns a path-typed value.</summary>
    public HashSet<string> PathReturns { get; } = [];
}

/// <summary>One input file and what was found in it.</summary>
internal sealed class AssemblyFacts {
    public required string Path { get; init; }
    public string? Sha256 { get; init; }
    public required string Name { get; set; }
    public FileClass Classification { get; set; } = FileClass.Error;
    public string? Error { get; set; }
    public List<MethodFacts> Methods { get; } = [];
    /// <summary>Assembly-level findings.</summary>
    public List<Evidence> Caps { get; } = [];
    public List<string> PInvokes { get; } = [];
    /// <summary>Names of every assembly this one references (its AssemblyRef table), used or not.</summary>
    public List<string> AssemblyRefs { get; } = [];
    /// <summary>
    /// Manifest resources that hold a program, a library or an archive, are named like one, or
    /// cannot be read here: "resource: what".
    /// </summary>
    public List<string> EmbeddedBinaries { get; } = [];
    /// <summary>Harmony patch targets declared by attributes on this assembly's types and methods.</summary>
    public List<PatchTarget> PatchTargets { get; } = [];
    /// <summary>
    /// Harmony patch declarations whose target cannot be read from the metadata: an attribute
    /// type of this assembly that Harmony reads patch information from (its constructor is code
    /// that sets the target), or an attribute value that does not decode.
    /// </summary>
    public List<string> UndecodedPatches { get; } = [];
    /// <summary>Attributes on this assembly's types and methods whose constructor is in another assembly, with what they are on.</summary>
    public List<(ExternalRef Ref, string Owner)> AttributeRefs { get; } = [];
    /// <summary>
    /// Node keys of Type and member fields defined here that code in another assembly can assign
    /// directly: public or protected, and not readonly.
    /// </summary>
    public HashSet<string> OpenFields { get; } = [];
    /// <summary>Node keys of path-typed fields (strings, FileInfo, ...) defined here that code in another assembly can assign directly.</summary>
    public HashSet<string> OpenPathFields { get; } = [];
    /// <summary>Every type defined here ("Namespace.Outer/Inner"), with its base type and interfaces.</summary>
    public Dictionary<string, List<string>> Types { get; } = [];
    /// <summary>The base type of each type defined here that has one (not an interface, not System.Object itself).</summary>
    public Dictionary<string, string> BaseTypes { get; } = [];
    /// <summary>
    /// The [InlineArray] types defined here (the framework's attribute), by name: the length and the
    /// element type as <see cref="AssemblyWalker.ElementKey"/> writes it. The game-API map carries
    /// the game's, so a mod's compiler-generated helper over a game inline array can be checked (C5).
    /// </summary>
    public Dictionary<string, InlineArrayShape> InlineArrays { get; } = [];
    /// <summary>
    /// The assembly each base type in <see cref="BaseTypes"/> lives in: this assembly's name for one defined
    /// here, "" when it cannot be determined. Reflection on a type finds what it inherits (H7b).
    /// </summary>
    public Dictionary<string, string> BaseTypeAssemblies { get; } = [];
    /// <summary>
    /// The methods of properties and events defined here, by the metadata: per method
    /// ("Namespace.Type::Method"), the properties and events it belongs to ("Namespace.Type::Name"; an
    /// indexed property also as "Namespace.Type::Item"). A lookup by a property's or event's name reaches
    /// them whatever they are called (see Evaluation.FieldProvenance).
    /// </summary>
    public Dictionary<string, List<string>> Accessors { get; } = [];
    /// <summary>Types defined here whose properties or events cannot be read (see <see cref="Accessors"/>).</summary>
    public HashSet<string> AccessorsUnread { get; } = [];
    /// <summary>Every field defined here, "Namespace.Type::Field".</summary>
    public List<string> Fields { get; } = [];
    /// <summary>Node keys of the pointer-typed fields defined here.</summary>
    public HashSet<string> PointerFields { get; } = [];
    /// <summary>Types this assembly forwards to another assembly (exported type forwarders).</summary>
    public List<string> ForwardedTypes { get; } = [];
    /// <summary>
    /// The declared types of the members of each type defined here (D2), for a lookup by name to type what it
    /// finds: per type ("Namespace.Outer/Inner"), per member ("field:Name", "property:Name", "method:Name"), the
    /// declared type as "Namespace.Type|Assembly", or <see cref="MemberTypes.Unknown"/> when it is not a class or
    /// struct, or when members of that kind and name disagree (overloads, a property whose getter returns
    /// another type). The game-API map carries the game's (profile format 7).
    /// </summary>
    public Dictionary<string, Dictionary<string, string>> MemberTypes { get; } = [];

    public bool IsAnalyzed => Classification is FileClass.Mod or FileClass.LibraryImpersonation;
}


/// <summary>The encoding of <see cref="AssemblyFacts.MemberTypes"/> and of the game-API map's "memberTypes" (D2).</summary>
internal static class MemberTypes {
    /// <summary>A member whose declared type is not a class or struct, or not one type.</summary>
    public const string Unknown = "?";

    public static string Key(MemberKind kind, string name) => kind switch {
        MemberKind.Field => "field:",
        MemberKind.Property => "property:",
        _ => "method:",
    } + name;

    /// <summary>The kind and name of a member key, or null for one that is not of this form.</summary>
    public static (MemberKind Kind, string Name)? ParseKey(string key) {
        int colon = key.IndexOf(':', StringComparison.Ordinal);
        if (colon <= 0) return null;
        MemberKind? kind = key[..colon] switch { "field" => MemberKind.Field, "property" => MemberKind.Property, "method" => MemberKind.Method, _ => null };
        return kind is { } k ? (k, key[(colon + 1)..]) : null;
    }

    public static string Encode(string type, string asm) => type + "|" + asm;

    /// <summary>The type and assembly of an encoded declared type, or null for <see cref="Unknown"/> or anything malformed.</summary>
    public static (string Type, string Asm)? Decode(string value) {
        int bar = value.LastIndexOf('|');
        return bar > 0 ? (value[..bar], value[(bar + 1)..]) : null;
    }

    /// <summary>Adds a member's declared type; a second, different one for the same kind and name makes it unknown.</summary>
    public static void Add(Dictionary<string, Dictionary<string, string>> into, string type, string key, string value) {
        if (!into.TryGetValue(type, out var members)) into[type] = members = new(StringComparer.Ordinal);
        members[key] = members.TryGetValue(key, out var before) && before != value ? Unknown : value;
    }
}
