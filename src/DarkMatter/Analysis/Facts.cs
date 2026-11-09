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
internal sealed record ExternalRef(string Assembly, string Member, bool Classified);

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
    public const string FieldPrefix = "field:", ArgPrefix = "arg:", ReturnPrefix = "ret:", MemberPrefix = "member:";
    public static string MemberOf(string node) => node.StartsWith(MemberPrefix, StringComparison.Ordinal) ? node : MemberPrefix + node;
    public static string Field(string key) => FieldPrefix + key;
    public static string Arg(string key, int index) => index < 0 ? $"{ArgPrefix}{key}#*" : $"{ArgPrefix}{key}#{index}";
    public static string Return(string key) => ReturnPrefix + key;

    /// <summary>The node key of the field, method or method whose argument the node is.</summary>
    public static string Key(string node) {
        if (node.StartsWith(MemberPrefix, StringComparison.Ordinal)) node = node[MemberPrefix.Length..];
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
        var key = Key(node);
        var name = key[(key.IndexOf('|', StringComparison.Ordinal) + 1)..];
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
internal sealed record ReflectedType(string Type, string? Assembly, IReadOnlyList<string>? Members, string Detail, bool PatchTarget = false,
    string? NameNode = null, string? Lookup = null, PatchEffect Patch = PatchEffect.Changes);

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
internal readonly record struct HeldType(string Type, string? Assembly, bool Member, bool Bounded = false);

/// <summary>
/// A file operation and where its path comes from, as a set of path atoms: an origin ("own",
/// "game", "saves", "temp", "documents", "user-folder", "environment", "absolute"), "untraced", or a
/// reference the Evaluator resolves across the mod: "arg:KEY#N" (argument N of method KEY, from
/// its callers), "field:KEY" (from every store to the field), "ret:KEY" (from what the method
/// returns), "game:ATOM" (ATOM combined with a literal naming the game's folder, so its Documents
/// or environment origins are the game's folder). See <c>Evaluation.FileAccess</c>. A path literal
/// that is a web address is "url".
/// </summary>
/// <param name="Kind">Whether it reads or writes.</param>
/// <param name="Member">The file API called.</param>
/// <param name="Path">Path atoms of its path operand.</param>
/// <param name="Url">The operation also accepts a web address in place of a path (see the policy's
/// <c>fileAccess.urls</c>): one whose path is untraced or a web address connects to the internet.</param>
internal sealed record FileOp(FileOpKind Kind, string Member, IReadOnlySet<string> Path, bool Url);

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
    /// <summary>Every field defined here, "Namespace.Type::Field".</summary>
    public List<string> Fields { get; } = [];
    /// <summary>Node keys of the pointer-typed fields defined here.</summary>
    public HashSet<string> PointerFields { get; } = [];
    /// <summary>Types this assembly forwards to another assembly (exported type forwarders).</summary>
    public List<string> ForwardedTypes { get; } = [];

    public bool IsAnalyzed => Classification is FileClass.Mod or FileClass.LibraryImpersonation;
}

