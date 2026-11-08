// SPDX-License-Identifier: MIT
using System.Collections.Immutable;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Text.RegularExpressions;

namespace DarkMatter.Analysis;

/// <summary>What the walker knows about a stack slot or local.</summary>
internal enum Tag {
    Unknown,
    /// <summary>A constant string (<see cref="Slot.Text"/>).</summary>
    String,
    /// <summary>A resolved type (<see cref="Slot.Text"/> is its name).</summary>
    Type,
    /// <summary>A constant 32-bit integer (<see cref="Slot.Number"/>).</summary>
    Int,
    /// <summary>A managed address (ldloca, ldflda, ldelema, ...).</summary>
    Address,
    /// <summary>A ProcessStartInfo created in this method (<see cref="Slot.Number"/> is its id).</summary>
    StartInfo,
    /// <summary>A localloc buffer. Without <see cref="Slot.Text"/>: <see cref="Slot.Number"/> is its
    /// size in bytes (-2 if unknown). With an element size in Text: a count of elements, either
    /// a local (<see cref="Slot.Store"/>) or a constant (Number).</summary>
    Stackalloc,
    /// <summary>Address of compiler-emitted static data (<see cref="Slot.Number"/> is its size in bytes).</summary>
    StaticData,
    /// <summary>A count times an element size (<see cref="Slot.Text"/>): the count is a local (<see cref="Slot.Store"/>) or a constant (<see cref="Slot.Number"/>).</summary>
    Count,
    /// <summary>The result of sizeof (<see cref="Slot.Text"/> is the type).</summary>
    SizeOf,
    /// <summary>
    /// A member of a resolved type: a MethodInfo, FieldInfo, PropertyInfo, ..., or a Harmony
    /// Traverse on that type (<see cref="Slot.Text"/> is the type's name). <see cref="Slot.Number"/>
    /// holds flags: <see cref="Slot.Moved"/> marks a Traverse moved to a field or property, whose
    /// further steps leave that type; <see cref="Slot.OrDerived"/> (also on a Type) means the type
    /// or any type derived from it ("*" with an assembly: any type of that assembly).
    /// </summary>
    Member,
    /// <summary>A Type or member traced to a node (<see cref="Slot.Text"/> is its id, see <see cref="Nodes"/>):
    /// a field, a parameter, or what a method returns; resolved per mod from what the node is given.
    /// <see cref="Slot.Number"/> 1: a member looked up on the types the node holds (see <see cref="Nodes.MemberOf"/>).</summary>
    Node,
    /// <summary>The null reference.</summary>
    Null,
    /// <summary>A file path, or a string or file-system object that may be one: <see cref="Slot.Text"/>
    /// holds its path atoms (<see cref="PathAtoms"/>).</summary>
    Path,
    /// <summary>An Assembly object: <see cref="Slot.Asm"/> is its name ("" if not known).</summary>
    Assembly,
    /// <summary>An object of a class or struct the code declares (<see cref="Slot.Text"/>, in
    /// <see cref="Slot.Asm"/>): the declared type of a parameter, local, field or result, or the type a
    /// cast checks. Its run-time type is that type or one derived from it; <see cref="Slot.Number"/> 1
    /// when it is exactly that type (newobj, box).</summary>
    Object,
    /// <summary>An array or list of members, types or expressions this method created (<see cref="Slot.Number"/>
    /// is its id, see <see cref="MethodWalker"/>'s collections).</summary>
    Collection,
    /// <summary>An element of collection <see cref="Slot.Number"/>, or (negative) one of the types and members
    /// of a set (see <see cref="AssemblyWalker.Union"/>). <see cref="Slot.Text"/> "member": a member looked
    /// up on such an element.</summary>
    Element,
    /// <summary>An enumerator over collection <see cref="Slot.Number"/>.</summary>
    Enumerator,
    /// <summary>An expression tree built only from expressions the check follows (see <see cref="ReflectionApis.IsCleanExpressionFactory"/>).</summary>
    Expr,
    /// <summary>A delegate to (or a function pointer of) a method of this assembly (<see cref="Slot.Number"/> is its metadata token).</summary>
    Delegate,
}

/// <summary>A tracked value on the stack or in a local.</summary>
/// <param name="Tag">What is known about the value.</param>
/// <param name="Text">A string, type name or element size, depending on the tag.</param>
/// <param name="Number">An integer, id or size, depending on the tag.</param>
/// <param name="Store">Which store to a local this value was loaded from (-1 if none), so two
/// loads can be told to hold the same value.</param>
/// <param name="Asm">For a Type or member: the assembly its type lives in, null when it was found by
/// name in whatever assembly has it, "" when that cannot be determined (see <see cref="ReflectedType"/>).</param>
internal readonly record struct Slot(Tag Tag, string? Text = null, int Number = 0, int Store = -1, string? Asm = null) {
    public static readonly Slot Unknown = new(Tag.Unknown);
    /// <summary>Flag on a Member: a Traverse moved to a field or property.</summary>
    public const int Moved = 1;
    /// <summary>Flag on a Type or Member: that type or any type derived from it.</summary>
    public const int OrDerived = 2;
}

/// <summary>A class or struct a signature or token names, with the assembly it lives in.</summary>
/// <param name="Type">"Namespace.Type", nested types as "Outer/Inner".</param>
/// <param name="Asm">The assembly it lives in ("" when that cannot be determined).</param>
/// <param name="Exact">The value is of exactly this type (a new object, a boxed value), not of a derived one.</param>
internal readonly record struct DeclaredType(string Type, string Asm, bool Exact);

/// <summary>The shape of the method a <see cref="MethodWalker"/> walks.</summary>
/// <param name="ByrefArgs">Arguments that are managed references (ref/out/in, or this in a struct).</param>
/// <param name="PathArgs">Arguments of a path type (<see cref="PathAtoms.IsPathType"/>).</param>
/// <param name="RefReturn">The method returns a managed reference.</param>
/// <param name="PathReturn">The method returns a value of a path type.</param>
internal sealed record MethodShape(IReadOnlySet<int> ByrefArgs, IReadOnlySet<int> PathArgs, bool RefReturn, bool PathReturn) {
    public static readonly MethodShape None = new(new HashSet<int>(), new HashSet<int>(), false, false);
    /// <summary>Arguments of a Type or member type, traced to their node (see <see cref="Nodes"/>).</summary>
    public IReadOnlySet<int> ReflectionArgs { get; init; } = new HashSet<int>();
    /// <summary>The method returns a Type or member.</summary>
    public bool ReflectionReturn { get; init; }
    /// <summary>Declared type of each argument (counting this), null where it is not a class or struct.</summary>
    public IReadOnlyList<DeclaredType?> ArgTypes { get; init; } = [];
}

/// <summary>
/// Walks one method body. Constant strings, integers, types, members, addresses, file paths and
/// ProcessStartInfo objects are tracked through the stack and locals. Tracking resets at every
/// block start, so control flow never produces a false constant. Some things are carried across
/// a forward join: whether a stack slot holds a managed address and which type a stack slot's
/// Type or member comes from, only when every way into the block agrees; a constant string when
/// every way agrees on it; and the union of where a path can come from. A local holding a Type,
/// member or path is traced across blocks from every store to it in the method (see
/// <see cref="Summaries"/>).
/// </summary>
internal sealed partial class MethodWalker {
    const string StartInfoType = "System.Diagnostics.ProcessStartInfo";
    const string ProcessStart = "System.Diagnostics.Process::Start";
    // The operand of a Harmony instruction: what the instruction a transpiler returns refers to.
    const string InstructionOperand = "HarmonyLib.CodeInstruction::operand";

    static readonly HashSet<string> TypeNameHandlingSetters = [
        "Newtonsoft.Json.JsonSerializerSettings::set_TypeNameHandling", "Newtonsoft.Json.JsonSerializer::set_TypeNameHandling",
    ];
    static readonly HashSet<string> UrlOpeners = new(StringComparer.OrdinalIgnoreCase) { "explorer.exe", "explorer", "xdg-open", "open" };
    static readonly HashSet<short> FieldLoadOps = [OpCodes.Ldfld.Value, OpCodes.Ldsfld.Value];
    static readonly HashSet<short> FieldStoreOps = [OpCodes.Stfld.Value, OpCodes.Stsfld.Value];
    static readonly HashSet<short> FieldAddressOps = [OpCodes.Ldflda.Value, OpCodes.Ldsflda.Value];
    static readonly HashSet<short> StoreIndirectOps = [
        OpCodes.Stind_I.Value, OpCodes.Stind_I1.Value, OpCodes.Stind_I2.Value, OpCodes.Stind_I4.Value, OpCodes.Stind_I8.Value,
        OpCodes.Stind_R4.Value, OpCodes.Stind_R8.Value, OpCodes.Stind_Ref.Value, OpCodes.Stobj.Value,
    ];
    static readonly HashSet<short> LoadIndirectOps = [
        OpCodes.Ldind_I.Value, OpCodes.Ldind_I1.Value, OpCodes.Ldind_I2.Value, OpCodes.Ldind_I4.Value, OpCodes.Ldind_I8.Value,
        OpCodes.Ldind_U1.Value, OpCodes.Ldind_U2.Value, OpCodes.Ldind_U4.Value, OpCodes.Ldind_R4.Value, OpCodes.Ldind_R8.Value,
        OpCodes.Ldind_Ref.Value, OpCodes.Ldobj.Value,
    ];
    static readonly HashSet<short> MulOps = [OpCodes.Mul.Value, OpCodes.Mul_Ovf.Value, OpCodes.Mul_Ovf_Un.Value];
    static readonly HashSet<string> SpanPointerCtors = ["System.Span`1::.ctor", "System.ReadOnlySpan`1::.ctor"];
    static readonly Dictionary<string, int> PrimitiveSizes = new(StringComparer.Ordinal) {
        ["System.Byte"] = 1,
        ["System.SByte"] = 1,
        ["System.Boolean"] = 1,
        ["System.Char"] = 2,
        ["System.Int16"] = 2,
        ["System.UInt16"] = 2,
        ["System.Int32"] = 4,
        ["System.UInt32"] = 4,
        ["System.Single"] = 4,
        ["System.Int64"] = 8,
        ["System.UInt64"] = 8,
        ["System.Double"] = 8,
    };

    // A web address safe to hand to the shell: http(s), no spaces or quotes.
    [GeneratedRegex(@"^https?://[A-Za-z0-9\-._~:/?#\[\]@!$&()*+,;=%]+$", RegexOptions.IgnoreCase)]
    private static partial Regex Url();

    readonly AssemblyWalker assembly;
    readonly MethodFacts mf;
    readonly bool isHelper;
    readonly MetadataReader md;
    readonly Policy policy;
    readonly List<Slot> stack = [];
    readonly Dictionary<int, Slot> locals = [];
    // ProcessStartInfo objects created in this method: id -> what it opens (nothing yet, a fixed web
    // address, a folder the method created), or null (anything else).
    readonly Dictionary<int, StartTarget?> startInfos = [];
    sealed record StartTarget(string? Url = null, IReadOnlySet<string>? Folder = null) {
        public bool Empty => Url == null && Folder == null;
    }
    // Values passed to Directory.CreateDirectory in the current block (see Identity): a folder the
    // method has just created, until the value can change.
    readonly HashSet<string> createdDirs = [];
    // Arguments the method stores to or takes the address of: two loads of one may differ.
    readonly HashSet<int> changedArgs = [];
    bool untrackedStartInfo;  // a ProcessStartInfo member was used on an object the walker cannot follow
    readonly MethodShape shape;
    // Arguments that are managed references (ref/out/in, or this in a struct) and that the method
    // never takes the address of: what they hold is checked at every call and store (see Step).
    readonly HashSet<int> byrefArgs;
    readonly TargetMethodKind targetMethod;  // Harmony takes the patch target from what this method returns
    // By-reference locals whose address is never taken: every store to them is checked.
    readonly HashSet<int> byrefLocals = [];
    readonly Dictionary<int, int> storeIds = [];
    int stores;
    // Per local, the join of every value stored to it anywhere in the method, used when a block
    // starts with nothing known about locals. Only traced reflection values are used from it.
    Dictionary<int, Slot> summaries = [];
    // A summary round (see Summaries): a local with no store seen yet holds only its default, null.
    bool optimistic;
    // This pass: the join of the values stored to each local.
    readonly Dictionary<int, Slot> stored = [];
    const int SummaryRounds = 8;
    // Declared types of the locals (null where not a class or struct).
    IReadOnlyList<DeclaredType?> localDeclared = [];
    int offset;  // of the instruction being walked: a collection's id is where it is created

    // Arrays and lists of members, types or expressions created in this method, by id. Every slot
    // that holds one refers to it by id, so a change through one alias is seen through all. Any use
    // the walker does not follow (passed to other code, stored in a field, merged with another value)
    // means other code may change it: its elements are then no longer traced.
    sealed class Collection {
        public readonly HashSet<HeldType> Held = [];
        public readonly List<(int Id, bool AsMembers)> Includes = [];
        public string? Node;  // also members of the types this node holds
        public string? Tainted;  // why: something untraced was put into it
        public string? Escaped;  // why: code the walker does not follow may change it
        public bool Lookup;  // made by a member lookup (GetMethods, ...): its elements are members of the types it was made from
        public bool Expressions;  // holds expressions, not members
        public string? LoadedFrom;  // an array read from this Type or member array field: a change to it changes what the field holds
        public bool Exposed;  // an element was taken out of it, or code the walker does not follow had it
        public readonly HashSet<string> Names = [];  // names of the members taken out of it by a filter that requires one (see NameFilter)
    }
    readonly Dictionary<int, Collection> collections = [];
    // What each collection holds once the whole method has run (from a first pass, see Walk): a
    // change made later in the code, or in a later loop iteration, is then already counted.
    Dictionary<int, CollectionState>? final;
    internal sealed record CollectionState(IReadOnlySet<HeldType> Held, string? Node, string? Tainted, string? Escaped, bool Lookup) {
        /// <summary>Elements were taken out of it only by filters that require a constant name: those names; null otherwise.</summary>
        public IReadOnlySet<string>? OnlyNamed { get; init; }
    }

    public MethodWalker(AssemblyWalker assembly, MethodFacts mf, bool isHelper, MethodShape shape, TargetMethodKind targetMethod = TargetMethodKind.None) {
        this.assembly = assembly;
        this.mf = mf;
        this.isHelper = isHelper;
        this.shape = shape;
        byrefArgs = [.. shape.ByrefArgs];
        this.targetMethod = targetMethod;
        md = assembly.Metadata;
        policy = assembly.Policy;
    }

    static bool IsUrl(Slot s) => s.Tag == Tag.String && s.Text != null && Url().IsMatch(s.Text);

    /// <summary>A value whose reflection provenance is known: a resolved type or member, a node's value, an element of a collection, or null.</summary>
    static bool Traced(Slot s) => s.Tag is Tag.Type or Tag.Member or Tag.Node or Tag.Null or Tag.Element;

    // Values a local keeps across blocks and a branch carries (see Load and Carried).
    static bool Kept(Slot s) => Traced(s) || s.Tag is Tag.Path or Tag.Collection or Tag.Enumerator or Tag.Expr or Tag.Object || IsOperand(s);

    // The operand of an existing Harmony instruction (see OperandTarget).
    static bool IsOperand(Slot s) => s is { Tag: Tag.Unknown, Text: InstructionOperand };

    // The value at a join of two paths. Managed addresses and traced reflection values are carried
    // when both agree; null joins with anything traced (invoking null throws). A string constant is
    // carried when both have it; otherwise strings and paths join to a path that can come from
    // wherever either does (an untraced side adds "untraced"). A collection merged with anything
    // but itself (or null) is lost: an alias the walker cannot name may change it.
    Slot Join(Slot a, Slot b) {
        // The address of an instruction's operand stays one (see OperandTarget) when either side is.
        if (a.Tag == Tag.Address && b.Tag == Tag.Address) return new(Tag.Address, a.Text ?? b.Text);
        if (a.Tag == Tag.String && b.Tag == Tag.String && a.Text == b.Text) return a with { Store = -1 };
        if (a.Tag is Tag.Path or Tag.String || b.Tag is Tag.Path or Tag.String)
            return a.Tag is Tag.Path or Tag.String or Tag.Null or Tag.Unknown or Tag.Object && b.Tag is Tag.Path or Tag.String or Tag.Null or Tag.Unknown or Tag.Object
                ? PathSlot(Atoms(a, true).Concat(Atoms(b, true)))
                : Slot.Unknown;
        if (a.Tag is Tag.Collection or Tag.Enumerator || b.Tag is Tag.Collection or Tag.Enumerator) {
            if (a.Tag == b.Tag && a.Number == b.Number) return a with { Store = -1 };
            if (a.Tag == Tag.Null) return b with { Store = -1 };
            if (b.Tag == Tag.Null) return a with { Store = -1 };
            Lose(a, "merged with another value");
            Lose(b, "merged with another value");
            return Slot.Unknown;
        }
        if (a.Tag == Tag.Expr && b.Tag == Tag.Expr) return a with { Store = -1 };
        // Objects of one declared type stay of that type; whether it is exact holds only if both are.
        if (a.Tag == Tag.Object && b.Tag == Tag.Object && a.Text == b.Text && a.Asm == b.Asm)
            return a with { Number = Math.Min(a.Number, b.Number), Store = -1 };
        if (a.Tag == Tag.Object && b.Tag == Tag.Null) return a with { Store = -1 };
        if (b.Tag == Tag.Object && a.Tag == Tag.Null) return b with { Store = -1 };
        if (IsOperand(a) && (IsOperand(b) || b.Tag == Tag.Null)) return a with { Store = -1 };
        if (IsOperand(b) && a.Tag == Tag.Null) return b with { Store = -1 };
        if (!Traced(a) || !Traced(b)) return Slot.Unknown;
        if (a.Tag == Tag.Null) return b with { Store = -1 };
        if (b.Tag == Tag.Null) return a with { Store = -1 };
        if (a.Tag == b.Tag && a.Text == b.Text && a.Number == b.Number && a.Asm == b.Asm) return a with { Store = -1 };
        // Two different traced types or members: one of them (the compiler reuses a local for both).
        return HeldOf(a) is { } ha && HeldOf(b) is { } hb && ha.Count + hb.Count <= MaxUnion
            ? new(Tag.Element, Number: assembly.Union(ha.Concat(hb))) : Slot.Unknown;
    }

    const int MaxUnion = 32;

    // The traced types and members a value is one of: a type or member, or a set of them; null for anything else.
    IReadOnlySet<HeldType>? HeldOf(Slot s) => s.Tag switch {
        Tag.Type or Tag.Member when s.Text != null && (s.Number & Slot.Moved) == 0
            => new HashSet<HeldType> { new(s.Text, s.Asm, s.Tag == Tag.Member, (s.Number & Slot.OrDerived) != 0) },
        Tag.Element when s.Number < 0 => s.Text == "member" ? assembly.UnionOf(s.Number).Select(h => h with { Member = true }).ToHashSet() : assembly.UnionOf(s.Number),
        _ => null,
    };

    // What a stack slot carries into a forward branch target.
    static Slot Carried(Slot s) => s.Tag == Tag.Address ? new(Tag.Address, s.Text)
        : Kept(s) || s.Tag is Tag.String ? s with { Store = -1 } : Slot.Unknown;

    static Slot PathSlot(IEnumerable<string> atoms) => new(Tag.Path, PathAtoms.Encode(atoms));

    // Where a value used as a path comes from. whole: a rooted literal is an absolute path (see
    // PathAtoms.OfLiteral). start and last (whole by default): the value begins (ends) the path, so
    // where its beginning (end) comes from is the path's (see PathAtoms.Head, End); otherwise more of
    // the path comes before (after) it.
    IEnumerable<string> Atoms(Slot s, bool whole, bool? start = null, bool? last = null) {
        IEnumerable<string> atoms = s.Tag switch {
            Tag.Path => PathAtoms.Decode(s.Text),
            Tag.String => PathAtoms.OfLiteral(s.Text ?? "", whole, policy),
            Tag.Null => [],
            _ => [PathAtoms.Untraced],
        };
        bool begins = start ?? whole, ends = last ?? whole;
        if (!begins) atoms = PathAtoms.Tail(atoms);
        if (!ends) atoms = PathAtoms.Mid(atoms);
        // A value the check cannot follow, or a literal that is not rooted, can begin anything; one
        // the check cannot follow, or a literal whose last name has a dot, can end with any name.
        bool open = s.Tag is not (Tag.Path or Tag.Null or Tag.String);
        if (begins && (open || (s.Tag == Tag.String && PathAtoms.LooseStart(s.Text ?? "", policy)))) atoms = atoms.Append(PathAtoms.Head);
        if (ends && (open || (s.Tag == Tag.String && PathAtoms.LooseEnd(s.Text ?? "")))) atoms = atoms.Append(PathAtoms.End);
        return atoms;
    }

    // The atoms of an operand of a path made of several: a null first or last one is left out of the
    // result, so the path begins (ends) with what is next to it.
    IEnumerable<string> PartAtoms(Slot s, bool whole, bool start, bool last) {
        if (s.Tag != Tag.Null) return Atoms(s, whole, start, last);
        var markers = new List<string>();
        if (start) markers.Add(PathAtoms.Head);
        if (last) markers.Add(PathAtoms.End);
        return markers;
    }

    void Note(string cap, string detail, Origin origin = Origin.Reference) => mf.Caps.Add(new(cap, detail, origin));

    // Records a reference into another assembly; the Evaluator decides whether that code was analyzed.
    void External(EntityHandle h, string name, Policy.Classification c) {
        if (assembly.ExternalAssemblyOf(h) is { } asm) mf.ExternalRefs.Add(new(asm, name, c.Matched));
    }

    Slot Pop() {
        if (stack.Count == 0) return Slot.Unknown;
        var t = stack[^1];
        stack.RemoveAt(stack.Count - 1);
        return t;
    }

    // A tracked ProcessStartInfo or collection that leaves the walker's sight can be changed elsewhere.
    void Escape(Slot s) {
        EscapeStartInfo(s);
        Lose(s, "passed to code the check does not follow there");
    }

    void EscapeStartInfo(Slot s) { if (s.Tag == Tag.StartInfo) startInfos[s.Number] = null; }

    // A collection (or an enumerator over it, or the address of a local holding one) that other code
    // may now change: its elements are no longer traced.
    void Lose(Slot s, string why) {
        if (s.Tag is Tag.Collection or Tag.Enumerator) {
            Coll(s.Number).Escaped ??= why;
            Coll(s.Number).Exposed = true;
        } else if (s is { Tag: Tag.Address, Number: > 0 } && LocalValue(s.Number - 1) is { Tag: Tag.Enumerator or Tag.Collection } held) Lose(held, why);
    }

    // What a local holds, without the side effects of a load.
    Slot LocalValue(int i) => locals.TryGetValue(i, out var l) ? l : summaries.TryGetValue(i, out var s) ? s : Slot.Unknown;

    // Creates the collection made at this instruction (one per instruction: every collection made
    // there, in any iteration, shares it).
    Slot NewCollection(Action<Collection>? fill = null) {
        fill?.Invoke(Coll(offset));
        return new(Tag.Collection, Number: offset);
    }

    // A collection's entry, created on first use: a slot from a local's summary can name a
    // collection whose creating instruction comes later in the code (a loop).
    Collection Coll(int id) {
        if (!collections.TryGetValue(id, out var c)) collections[id] = c = new();
        return c;
    }

    // Puts a value into a collection: a traced type or member, another collection's element or a
    // node's value is recorded; for expressions, a clean expression; null adds nothing; anything else taints it.
    void AddTo(int id, Slot v) {
        var c = Coll(id);
        if (c.Expressions) {
            if (v.Tag is not (Tag.Expr or Tag.Null)) c.Tainted ??= "holds an expression the check does not follow";
            return;
        }
        switch (v.Tag) {
            case Tag.Null:
                break;
            case Tag.Type or Tag.Member when v.Text != null && (v.Number & Slot.Moved) == 0:
                c.Held.Add(new(v.Text, v.Asm, v.Tag == Tag.Member, (v.Number & Slot.OrDerived) != 0));
                break;
            case Tag.Element when v.Number < 0:
                c.Held.UnionWith(HeldOf(v)!);
                break;
            case Tag.Element:
                c.Includes.Add((v.Number, v.Text == "member"));
                break;
            case Tag.Node when v.Text != null && (c.Node == null || c.Node == NodeSource(v)):
                c.Node = NodeSource(v);
                break;
            default:
                c.Tainted ??= "holds a value the check cannot trace";
                Lose(v, "put into a collection");
                break;
        }
    }

    /// <summary>What each collection holds at the end of the method, with what it includes from other collections.</summary>
    internal Dictionary<int, CollectionState> FinalCollections() {
        const string Mixed = "holds members from more than one place the check follows";
        var result = new Dictionary<int, CollectionState>();
        foreach (var (id, c) in collections) {
            var held = new HashSet<HeldType>();
            string? node = null, tainted = null, escaped = null;
            var seen = new HashSet<(int, bool)>();
            var todo = new Stack<(int Id, bool AsMembers)>([(id, false)]);
            while (todo.Count > 0) {
                var (x, asMembers) = todo.Pop();
                if (!seen.Add((x, asMembers))) continue;  // a cycle adds nothing new
                if (!collections.TryGetValue(x, out var cx)) { tainted ??= "holds elements of a collection the check does not follow"; continue; }
                held.UnionWith(asMembers ? cx.Held.Select(h => h with { Member = true }) : cx.Held);
                tainted ??= cx.Tainted;
                escaped ??= cx.Escaped;
                if (cx.Node != null) {
                    if (node != null && node != cx.Node) tainted ??= Mixed;
                    node = cx.Node;
                }
                foreach (var (inc, m) in cx.Includes) todo.Push((inc, asMembers || m));
            }
            if (node != null && held.Count > 0) tainted ??= Mixed;
            result[id] = new(held, node, tainted, escaped, c.Lookup && c.Includes.Count == 0) { OnlyNamed = c.Exposed ? null : c.Names };
        }
        return result;
    }

    // The final state of a collection: in the first pass (no final states yet) nothing is decided from it.
    CollectionState? StateOf(int id) => id < 0 ? new(assembly.UnionOf(id), null, null, null, false)
        : final == null ? null : final.TryGetValue(id, out var s) ? s : new(new HashSet<HeldType>(), null, "is not one the check follows", null, false);

    // What an element is one of: its collection's state, as members when it was looked up on one.
    CollectionState? StateOf(Slot element) {
        if (StateOf(element.Number) is not { } state || element.Text != "member") return StateOf(element.Number);
        return state with { Held = state.Held.Select(h => h with { Member = true }).ToHashSet(), Node = state.Node is { } n ? Nodes.MemberOf(n) : null };
    }

    void ClearStack() {
        foreach (var s in stack) Escape(s);
        stack.Clear();
    }

    Slot Load(int i) {
        Slot t;
        if (byrefLocals.Contains(i)) t = new(Tag.Address);
        else if (locals.TryGetValue(i, out var l)) t = l;
        // Nothing is known at a block start, but a Type or member can still be traced from every
        // store to the local in the method.
        else if (summaries.TryGetValue(i, out var s)) t = Kept(s) ? s : Slot.Unknown;
        else t = optimistic ? new(Tag.Null) : Slot.Unknown;
        // Otherwise it holds an object of the local's declared type.
        if (t.Tag == Tag.Unknown && t.Text == null && i < localDeclared.Count && localDeclared[i] is { } d) t = ObjectOf(d);
        return t with { Store = storeIds.TryGetValue(i, out var id) ? id : -1 };
    }

    static Slot ObjectOf(DeclaredType d) => new(Tag.Object, d.Type, d.Exact ? 1 : 0, Asm: d.Asm);

    void StoreLocal(int i, Slot value) {
        locals[i] = value with { Store = -1 };
        storeIds[i] = ++stores;
        stored[i] = Join(stored.TryGetValue(i, out var prev) ? prev : new(Tag.Null), value);
    }

    Slot Peek(int depth) => stack.Count > depth ? stack[^(depth + 1)] : Slot.Unknown;

    // A write through an address is only accounted for when the address is a managed one.
    void RequireAddress(Slot address, string op) {
        if (address.Tag != Tag.Address)
            Note("raw-memory", $"{op} through an address that is not a managed reference in {mf.Name}", Origin.Structure);
    }

    // A read through an address: a managed one, or the address of compiler-emitted static data.
    void RequireReadable(Slot address, string op) {
        if (address.Tag is not (Tag.Address or Tag.StaticData))
            Note("raw-memory", $"{op} reads through an address that is not a managed reference in {mf.Name}", Origin.Structure);
    }

    // A value that becomes a managed reference the method or its callee trusts (a by-reference
    // argument or local, a ref return): an address that is not a managed one would let the code
    // that trusts it read or write any memory. Null throws where it is used.
    void RequireReference(Slot value, string what) {
        if (value.Tag is not (Tag.Address or Tag.Null))
            Note("raw-memory", $"{what} is not a managed reference in {mf.Name}", Origin.Structure);
    }

    public void Walk(MethodBodyBlock body) {
        ImmutableArray<string> localTypes = [];
        if (!body.LocalSignature.IsNil) {
            localTypes = md.GetStandaloneSignature(body.LocalSignature).DecodeLocalSignature(SignatureNames.Instance, null);
            if (localTypes.Any(AssemblyWalker.IsPointer)) Note("raw-memory", $"pointer local variable in {mf.Name}", Origin.Structure);
            for (int i = 0; i < localTypes.Length; i++) if (localTypes[i].EndsWith('&')) byrefLocals.Add(i);
            localDeclared = assembly.LocalDeclared(body);
        }
        var il = body.GetILBytes() ?? [];
        var code = Il.Decode(il);
        // A by-reference argument or local whose own address is taken can be overwritten through
        // that address with any value: it is not trusted to hold a managed reference.
        bool makesCollections = false;
        foreach (var ins in code) {
            short op = ins.OpCode.Value;
            if (op == OpCodes.Starg_S.Value || op == OpCodes.Starg.Value)
                changedArgs.Add(op == OpCodes.Starg_S.Value ? il[ins.OperandOffset] : Il.ReadUInt16(il, ins.OperandOffset));
            if (op == OpCodes.Ldarga_S.Value || op == OpCodes.Ldarga.Value) {
                int a = op == OpCodes.Ldarga_S.Value ? il[ins.OperandOffset] : Il.ReadUInt16(il, ins.OperandOffset);
                changedArgs.Add(a);
                byrefArgs.Remove(a);
                // A path argument can be overwritten through its address with anything.
                if (shape.PathArgs.Contains(a)) Set(mf.PathArguments, PathKey(mf.Key, a)).Add(PathAtoms.Untraced);
                // So can a Type or member argument, or a member name.
                if (shape.ReflectionArgs.Contains(a)) mf.UntrackedStores.Add(Nodes.Arg(mf.Key, a));
                if (shape.PathArgs.Contains(a)) Set(mf.StringArguments, Nodes.Arg(mf.Key, a)).Add("?");
            } else if (op == OpCodes.Ldloca_S.Value || op == OpCodes.Ldloca.Value) {
                byrefLocals.Remove(op == OpCodes.Ldloca_S.Value ? il[ins.OperandOffset] : Il.ReadUInt16(il, ins.OperandOffset));
            } else if (op == OpCodes.Newarr.Value || ins.OpCode.OperandType == OperandType.InlineMethod) {
                makesCollections |= MakesCollection(Il.MemberName(md, MetadataTokens.EntityHandle(Il.Token(il, ins))), op);
            } else if (ins.OpCode.OperandType == OperandType.InlineField) {
                var fh = MetadataTokens.EntityHandle(Il.Token(il, ins));
                makesCollections |= fh.Kind == HandleKind.FieldDefinition && assembly.FieldType(fh) is { } ft && ReflectionApis.IsReflectionArray(ft);
            }
        }
        var starts = Il.BlockStarts(il, code, body);
        // Blocks whose entry state cannot be known in one forward pass: loop heads (targets of a
        // backward branch) and handlers. They start with nothing known.
        var fresh = Il.HandlerStarts(body);
        foreach (var ins in code)
            foreach (var t in Il.BranchTargets(il, ins)) if (t <= ins.Offset) fresh.Add(t);
        // A Type, member, path, collection or expression is usually kept in a local across a branch
        // (if (m != null) ..., foreach).
        if (localTypes.Any(t => ReflectionApis.IsReflectionType(t) || ReflectionApis.IsReflectionType(t.TrimEnd('[', ']'))
            || t.StartsWith("HarmonyLib.Traverse", StringComparison.Ordinal) || PathAtoms.IsPathType(t) || ReflectionApis.IsExpressionType(t)
            || t.StartsWith("System.Collections.Generic.", StringComparison.Ordinal) || t.StartsWith("System.Collections.IEnumerator", StringComparison.Ordinal)))
            summaries = Summaries(il, code, starts, fresh);
        // What the method's collections hold once it has run, so that a change later in the code
        // (or in a later iteration) counts where an element is used.
        if (makesCollections) {
            var probe = new MethodWalker(assembly, new MethodFacts { Key = mf.Key, Name = mf.Name }, isHelper, shape, targetMethod) { summaries = summaries, localDeclared = localDeclared };
            probe.changedArgs.UnionWith(changedArgs);
            probe.byrefArgs.IntersectWith(byrefArgs);
            probe.byrefLocals.UnionWith(byrefLocals);
            probe.Pass(il, code, starts, fresh);
            final = probe.FinalCollections();
        }
        Pass(il, code, starts, fresh);
        // An array read from a Type or member array field that this method changes, or passes to
        // code it does not follow, may no longer hold what the field's stores put there.
        if (final != null)
            foreach (var (id, c) in collections)
                if (c.LoadedFrom != null && final.TryGetValue(id, out var state) && (state.Tainted ?? state.Escaped) != null) mf.UntrackedStores.Add(c.LoadedFrom);
    }

    // Whether an instruction can create a collection the walker follows (see NewCollection).
    static bool MakesCollection(string name, short op) =>
        op == OpCodes.Newarr.Value ? ReflectionApis.IsReflectionType(name) || ReflectionApis.IsExpressionType(name)
        : name is "System.Collections.Generic.List`1::.ctor" or "System.Array::Empty" or "System.Reflection.Assembly::GetTypes"
            or "System.Reflection.Assembly::GetExportedTypes" or "System.Reflection.Assembly::get_DefinedTypes" or "System.Reflection.Assembly::get_ExportedTypes"
          || ReflectionApis.IsPluralLookup(name);

    // Per local, the join of every value stored to it in the method. A local holds its default
    // (null) or one of those values at any point, so the join is what it holds after any branch.
    // Stores depend on loads, so this iterates from "no store seen" until nothing changes, using
    // throwaway walkers whose facts are discarded.
    Dictionary<int, Slot> Summaries(byte[] il, List<Instruction> code, HashSet<int> starts, HashSet<int> fresh) {
        var current = new Dictionary<int, Slot>();
        for (int round = 0; round < SummaryRounds; round++) {
            var probe = new MethodWalker(assembly, new MethodFacts { Key = mf.Key, Name = mf.Name }, isHelper, shape, targetMethod) { summaries = current, optimistic = true, localDeclared = localDeclared };
            probe.changedArgs.UnionWith(changedArgs);
            probe.byrefArgs.IntersectWith(byrefArgs);
            probe.byrefLocals.UnionWith(byrefLocals);
            probe.Pass(il, code, starts, fresh);
            if (probe.stored.Count == current.Count && probe.stored.All(kv => current.TryGetValue(kv.Key, out var c) && c == kv.Value))
                return current;
            current = probe.stored;
        }
        return [];  // did not settle: nothing is traced across blocks, every such load is unknown (fails closed)
    }

    void Pass(byte[] il, List<Instruction> code, HashSet<int> starts, HashSet<int> fresh) {
        // Per forward branch target: what each stack slot holds on every branch to it (null: depths differ).
        var incoming = new Dictionary<int, Slot[]?>();
        bool fallsThrough = false;
        Slot[]? fallThrough = null;
        foreach (var ins in code) {
            if (starts.Contains(ins.Offset)) {
                var preds = new List<Slot[]?>();
                if (fallsThrough) preds.Add(fallThrough);
                if (incoming.TryGetValue(ins.Offset, out var branched)) preds.Add(branched);
                // A collection on the stack into a block that starts with nothing known is lost.
                if (fresh.Contains(ins.Offset)) foreach (var p in preds) foreach (var x in p ?? []) Lose(x, "kept on the stack into a loop");
                var entry = fresh.Contains(ins.Offset) || preds.Count == 0 ? null : preds.Aggregate(Merge);
                ClearStack();
                locals.Clear();
                createdDirs.Clear();
                if (entry != null) stack.AddRange(entry);
            }
            offset = ins.Offset;
            Step(il, ins);
            var shape = stack.Select(Carried).ToArray();
            foreach (var t in Il.BranchTargets(il, ins)) {
                if (t <= ins.Offset) continue;
                Slot[]? leave = ins.OpCode.Value is var lv && (lv == OpCodes.Leave.Value || lv == OpCodes.Leave_S.Value) ? [] : shape;
                incoming[t] = incoming.TryGetValue(t, out var prev) ? Merge(prev, leave) : leave;
            }
            fallsThrough = Il.FallsThrough(ins);
            fallThrough = shape;
        }
    }

    // What each slot holds on both paths. Null means "nothing known": the depths differ, or one
    // side was already unknown. A collection on a side that is dropped is lost.
    Slot[]? Merge(Slot[]? a, Slot[]? b) {
        if (a != null && b != null && a.Length == b.Length) return [.. a.Zip(b, Join)];
        foreach (var x in (a ?? []).Concat(b ?? [])) Lose(x, "merged with another value");
        return null;
    }

    void Step(byte[] il, Instruction ins) {
        var oc = ins.OpCode;
        short v = oc.Value;
        int op = ins.OperandOffset;

        // writes and reads through an address
        if (StoreIndirectOps.Contains(v)) {
            RequireAddress(Peek(1), oc.Name ?? "store");
            if (Peek(1) is { Tag: Tag.Address, Text: InstructionOperand }) OperandTarget(Peek(0), "a Harmony instruction's operand (through CodeMatcher.Operand)");
        } else if (LoadIndirectOps.Contains(v)) {
            RequireReadable(Peek(0), oc.Name ?? "load");
            if (v == OpCodes.Ldind_Ref.Value && Peek(0) is { Tag: Tag.Address, Text: InstructionOperand }) {
                Pop();
                stack.Add(new(Tag.Unknown, InstructionOperand));
                return;
            }
        } else if (v == OpCodes.Cpblk.Value) {
            RequireAddress(Peek(2), "cpblk");
            RequireReadable(Peek(1), "cpblk");
        } else if (v == OpCodes.Initblk.Value) {
            RequireAddress(Peek(2), "initblk");
        } else if (v == OpCodes.Initobj.Value) {
            RequireAddress(Peek(0), "initobj");
        } else if (v == OpCodes.Cpobj.Value) {
            RequireAddress(Peek(1), "cpobj");
            RequireReadable(Peek(0), "cpobj");
        } else if (v == OpCodes.Mkrefany.Value) {
            // A TypedReference made from an address can be written through (__refvalue, SetValueDirect).
            RequireAddress(Peek(0), "mkrefany");
        }

        // arguments: ref, out and in parameters (and this in a struct) are managed references
        if (v >= OpCodes.Ldarg_0.Value && v <= OpCodes.Ldarg_3.Value) { stack.Add(Arg(v - OpCodes.Ldarg_0.Value)); return; }
        if (v == OpCodes.Ldarg_S.Value) { stack.Add(Arg(il[op])); return; }
        if (v == OpCodes.Ldarg.Value) { stack.Add(Arg(Il.ReadUInt16(il, op))); return; }
        if (v == OpCodes.Starg_S.Value || v == OpCodes.Starg.Value) { StoreArg(v == OpCodes.Starg_S.Value ? il[op] : Il.ReadUInt16(il, op), Pop()); return; }

        // locals: a tracked value stored and reloaded keeps its tag
        if (v >= OpCodes.Ldloc_0.Value && v <= OpCodes.Ldloc_3.Value) { stack.Add(Load(v - OpCodes.Ldloc_0.Value)); return; }
        if (v >= OpCodes.Stloc_0.Value && v <= OpCodes.Stloc_3.Value) { Stloc(v - OpCodes.Stloc_0.Value, Pop()); return; }
        if (v == OpCodes.Ldloc_S.Value) { stack.Add(Load(il[op])); return; }
        if (v == OpCodes.Stloc_S.Value) { Stloc(il[op], Pop()); return; }
        if (v == OpCodes.Ldloc.Value) { stack.Add(Load(Il.ReadUInt16(il, op))); return; }
        if (v == OpCodes.Stloc.Value) { Stloc(Il.ReadUInt16(il, op), Pop()); return; }
        if (v == OpCodes.Ldloca_S.Value || v == OpCodes.Ldloca.Value) {
            int i = v == OpCodes.Ldloca_S.Value ? il[op] : Il.ReadUInt16(il, op);
            // A List<T>.Enumerator struct is used through its address (foreach): the local keeps it,
            // and any use of the address other than the enumerator's own members loses the collection.
            if (Load(i).Tag == Tag.Enumerator) { stack.Add(new(Tag.Address, Number: i + 1)); return; }
            Escape(Load(i));
            StoreLocal(i, Slot.Unknown);  // can be written through the address
            stack.Add(new(Tag.Address, Number: i + 1));  // which local, for interpolated strings (see Interpolate)
            return;
        }
        if (v == OpCodes.Ldarga_S.Value || v == OpCodes.Ldarga.Value) { stack.Add(new(Tag.Address)); return; }
        if (v == OpCodes.Dup.Value) { var t = Pop(); stack.Add(t); stack.Add(t); return; }
        if (v == OpCodes.Ldnull.Value) { stack.Add(new(Tag.Null)); return; }
        if (v >= OpCodes.Ldc_I4_M1.Value && v <= OpCodes.Ldc_I4_8.Value) { stack.Add(new(Tag.Int, Number: v - OpCodes.Ldc_I4_0.Value)); return; }
        if (v == OpCodes.Ldc_I4_S.Value) { stack.Add(new(Tag.Int, Number: (sbyte)il[op])); return; }
        if (v == OpCodes.Ldc_I4.Value) { stack.Add(new(Tag.Int, Number: Il.ReadInt32(il, op))); return; }
        if (v == OpCodes.Ldstr.Value) {
            stack.Add(new(Tag.String, md.GetUserString(MetadataTokens.UserStringHandle(Il.Token(il, ins) & 0xFFFFFF))));
            return;
        }
        if (v == OpCodes.Conv_U.Value || v == OpCodes.Conv_I.Value) {
            // Converting a managed address to a native integer is how C# takes a raw pointer (&x).
            var x = Pop();
            if (x.Tag == Tag.Address) Note("raw-memory", $"address converted to a native pointer in {mf.Name}", Origin.Structure);
            stack.Add(x.Tag == Tag.Int ? x : Slot.Unknown with { Store = x.Store });
            return;
        }
        // stackalloc T[n] compiles to localloc of n * sizeof(T); the result may only feed a span of n elements
        if (MulOps.Contains(v)) {
            var b = Pop();
            var a = Pop();
            string? scale = b.Tag == Tag.Int ? b.Number.ToString(System.Globalization.CultureInfo.InvariantCulture) : b.Tag == Tag.SizeOf ? "sizeof:" + b.Text : null;
            if (scale != null && a.Tag == Tag.Unknown && a.Store >= 0) stack.Add(new(Tag.Count, scale, -1, a.Store));       // local * size
            else if (b.Tag == Tag.SizeOf && a.Tag == Tag.Int && a.Number >= 0) stack.Add(new(Tag.Count, scale, a.Number));  // constant * sizeof(T)
            else stack.Add(Slot.Unknown);
            return;
        }
        if (v == OpCodes.Localloc.Value) {
            var n = Pop();
            stack.Add(n.Tag == Tag.Int ? new(Tag.Stackalloc, Number: n.Number)
                : n.Tag == Tag.Count ? new(Tag.Stackalloc, n.Text, n.Number, n.Store)
                : new(Tag.Stackalloc, Number: -2));
            return;
        }
        if (v == OpCodes.Ret.Value && stack.Count > 0) {
            // A returned collection's elements are the caller's to take.
            Expose(Peek(0));
            // A returned reference is trusted by every caller (see Call).
            if (shape.RefReturn) RequireReference(Peek(0), "a returned reference");
            if (shape.PathReturn) mf.PathReturns.UnionWith(PathAtoms.Combine(Atoms(Peek(0), true)));
            // A returned Type or member is what a call to this method yields (see Call).
            if (shape.ReflectionReturn) StoreNode(Nodes.Return(mf.Key), Peek(0));
            // A patch class with a transpiler rewrites what its TargetMethod(s) return (see RewriteTarget).
            if (targetMethod != TargetMethodKind.None && assembly.PatchClassEffect(DeclaringType(mf.Name)) == PatchEffect.Rewrites)
                RewriteTarget(Peek(0), $"a member a transpiler rewrites, returned by {mf.Name},");
            // The method a TargetMethod returns is patched: like a reflection sink, it must be traced.
            if (targetMethod == TargetMethodKind.Single) {
                PatchTarget(Pop());
                return;
            }
            // So is every method a TargetMethods returns.
            if (targetMethod == TargetMethodKind.Multiple) PatchTargets(Peek(0));
        }
        // An element of an array of paths comes from where the array does; of a collection, is its element.
        if (v == OpCodes.Ldelem_Ref.Value) {
            Pop();
            var array = Pop();
            stack.Add(array.Tag == Tag.Path ? array with { Store = -1 } : array.Tag == Tag.Collection ? Taken(array.Number) : Slot.Unknown);
            return;
        }
        // Storing into a collection's element: what is stored is recorded (see AddTo).
        if (v == OpCodes.Stelem_Ref.Value || v == OpCodes.Stelem.Value) {
            var value = Pop();
            Pop();
            var array = Pop();
            if (array.Tag == Tag.Collection) AddTo(array.Number, value);
            else { Escape(array); Escape(value); }
            return;
        }
        // The length of a collection uses it without changing it.
        if (v == OpCodes.Ldlen.Value && Peek(0).Tag == Tag.Collection) { Pop(); stack.Add(Slot.Unknown); return; }
        if (v == OpCodes.Calli.Value) {
            Note("native-code", $"calli (indirect call through a function pointer)  <-  {mf.Name}", Origin.Structure);
            ClearStack();
            return;
        }

        if (oc.OperandType is OperandType.InlineMethod or OperandType.InlineField or OperandType.InlineType or OperandType.InlineTok) {
            var h = MetadataTokens.EntityHandle(Il.Token(il, ins));
            string name = Il.MemberName(md, h);

            if (v == OpCodes.Call.Value || v == OpCodes.Callvirt.Value || v == OpCodes.Newobj.Value) { Call(h, name, v == OpCodes.Newobj.Value); return; }

            IReadOnlyList<string>? sigParams = null;
            bool ftn = false;
            if (oc.OperandType == OperandType.InlineMethod) {
                if (Il.Signature(md, h) is { } sig) sigParams = sig.ParameterTypes;
                if (assembly.KeyOf(h) is { } key) {
                    mf.Callees.Add(key);  // ldftn / ldvirtftn: a delegate can call it
                    // ... with arguments from calls through the delegate, which are not traced.
                    Set(mf.PathArguments, PathKey(key, -1)).Add(PathAtoms.Untraced);
                    mf.UntrackedStores.Add(Nodes.Arg(key, -1));
                }
                ftn = v == OpCodes.Ldftn.Value && h.Kind == HandleKind.MethodDefinition;
            }
            var classification = policy.Classify(name, sigParams);
            // A file method taken as a delegate (ldftn, ldvirtftn) or jumped to (jmp) runs with a
            // path this method's own file-operation tracing does not see: it counts as outside the
            // game. Type tokens (typeof, casts) run no file code.
            foreach (var cap in classification.Caps)
                Note(cap, name + "  <-  " + mf.Name, sigParams != null && policy.FileKinds.ContainsKey(cap) ? Origin.Structure : Origin.Reference);
            External(h, name, classification);
            // A game method taken as a delegate (or as a method handle, which can be invoked) does
            // what the game-API map says, as a call does.
            if (oc.OperandType is OperandType.InlineMethod or OperandType.InlineTok && assembly.GameApi.TryGetValue(name, out var gameCaps))
                foreach (var cap in gameCaps) Note(cap, $"{name} (game API, taken as a delegate or handle)  <-  {mf.Name}", Origin.GameApi);
            // A pointer to a method of this assembly, for a delegate (see NameFilter).
            if (ftn) {
                stack.Add(new(Tag.Delegate, Number: MetadataTokens.GetToken(h)));
                return;
            }

            // A Harmony instruction's operand is what the instruction refers to once Harmony compiles
            // the transpiler's result: a value stored there must be traced like a reflection target.
            if (name == InstructionOperand) {
                if (FieldStoreOps.Contains(v)) OperandTarget(Peek(0), "a Harmony instruction's operand");
                else if (FieldAddressOps.Contains(v)) mf.UnresolvedReflection.Add($"the address of a Harmony instruction's operand is taken, so anything can be stored there  <-  {mf.Name}");
                // (Only Harmony's own field holds an existing instruction's operand, see AssemblyWalker.Models.)
                else if (FieldLoadOps.Contains(v) && assembly.Models(h, name)) {
                    for (int i = 0; i < StackEffect.Pops(oc.StackBehaviourPop); i++) Escape(Pop());
                    stack.Add(new(Tag.Unknown, InstructionOperand));
                    return;
                }
            }

            if (FieldLoadOps.Contains(v) || FieldStoreOps.Contains(v) || FieldAddressOps.Contains(v)) {
                if (assembly.KeyOf(h) is { } key) {
                    if (!FieldStoreOps.Contains(v)) mf.FieldLoads.Add(key);
                    if (!FieldLoadOps.Contains(v)) mf.FieldStores.Add(key);  // a field address can be written through
                    // Type and member fields: what is stored is recorded, and a load is resolved from the writers.
                    var fieldType = assembly.FieldType(h);
                    if (fieldType != null && ReflectionApis.IsReflectionType(fieldType)) {
                        if (FieldStoreOps.Contains(v)) {
                            StoreNode(Nodes.Field(key), Peek(0));
                        } else if (FieldAddressOps.Contains(v)) {
                            mf.UntrackedStores.Add(Nodes.Field(key));  // can be written through the address
                        } else {
                            for (int i = 0; i < StackEffect.Pops(oc.StackBehaviourPop); i++) Escape(Pop());
                            stack.Add(new(Tag.Node, Nodes.Field(key)));
                            return;
                        }
                    } else if (fieldType != null && ReflectionApis.IsReflectionArray(fieldType) && h.Kind == HandleKind.FieldDefinition) {
                        // An array of types or members in a field of this assembly: what its arrays
                        // hold, from every store (see StoreNode); a load is a collection that reports
                        // changes to the field. (Another assembly's array field, Type.EmptyTypes or a
                        // game field, holds what that code put there: its elements are not traced.)
                        var node = Nodes.Field(key);
                        if (FieldStoreOps.Contains(v)) {
                            var stored = Pop();
                            if (v == OpCodes.Stfld.Value) Escape(Pop());
                            StoreArray(node, stored);
                            return;
                        }
                        if (FieldAddressOps.Contains(v)) {
                            mf.UntrackedStores.Add(node);  // can be written through the address
                        } else {
                            for (int i = 0; i < StackEffect.Pops(oc.StackBehaviourPop); i++) Escape(Pop());
                            stack.Add(NewCollection(c => c.LoadedFrom = c.Node = node));
                            return;
                        }
                    } else if (fieldType != null && PathAtoms.IsPathType(fieldType)) {
                        // Path fields likewise: a load comes from wherever the field's stores do.
                        if (FieldStoreOps.Contains(v)) {
                            Set(mf.PathStores, key).UnionWith(PathAtoms.Combine(Atoms(Peek(0), true)));
                        } else if (FieldAddressOps.Contains(v)) {
                            Set(mf.PathStores, key).Add(PathAtoms.Untraced);  // can be written through the address
                        } else {
                            for (int i = 0; i < StackEffect.Pops(oc.StackBehaviourPop); i++) Escape(Pop());
                            // string.Empty is the empty literal.
                            stack.Add(name == "System.String::Empty" && assembly.Models(h, name) ? new(Tag.String, "") : PathSlot([PathAtoms.Field(key)]));
                            return;
                        }
                    }
                }
                // Any other field holds an object of its declared type.
                if (FieldLoadOps.Contains(v) && assembly.FieldDeclared(h) is { } declared) {
                    for (int i = 0; i < StackEffect.Pops(oc.StackBehaviourPop); i++) Escape(Pop());
                    stack.Add(ObjectOf(declared));
                    return;
                }
            }
            if (v == OpCodes.Castclass.Value || v == OpCodes.Isinst.Value) {
                // A cast yields the same object or null: a traced value stays traced, a collection or an
                // expression stays itself, anything else is an object of the type the cast checks.
                var x = Pop();
                if (Traced(x) || x.Tag is Tag.Path or Tag.Collection or Tag.Enumerator or Tag.Expr || IsOperand(x)) { stack.Add(x); return; }
                EscapeStartInfo(x);
                stack.Add(assembly.IsGenericParameter(h) ? Slot.Unknown : assembly.DeclaredOfToken(h, false) is { } cast ? ObjectOf(cast) : Slot.Unknown);
                return;
            }
            // A boxed value is exactly of the type it was boxed as.
            if (v == OpCodes.Box.Value) {
                Escape(Pop());
                stack.Add(assembly.IsGenericParameter(h) ? Slot.Unknown : assembly.DeclaredOfToken(h, true) is { } boxed ? ObjectOf(boxed) : Slot.Unknown);
                return;
            }
            // unbox yields a managed reference into the boxed value.
            if (v == OpCodes.Unbox.Value) { Escape(Pop()); stack.Add(new(Tag.Address)); return; }
            if (v == OpCodes.Ldelem.Value) {
                Pop();
                var array = Pop();
                stack.Add(array.Tag == Tag.Path ? array with { Store = -1 } : array.Tag == Tag.Collection ? Taken(array.Number) : Slot.Unknown);
                return;
            }
            // An array of members, types or expressions starts empty (see NewCollection).
            if (v == OpCodes.Newarr.Value && MakesCollection(name, v)) {
                Pop();
                bool expressions = ReflectionApis.IsExpressionType(name);
                stack.Add(NewCollection(c => c.Expressions = expressions));
                return;
            }
            if (v == OpCodes.Sizeof.Value) { stack.Add(new(Tag.SizeOf, assembly.TypeShapeName(h) ?? name)); return; }
            if (v == OpCodes.Ldsflda.Value && assembly.StaticDataSize(h) is int size) { stack.Add(new(Tag.StaticData, Number: size)); return; }
            if (v == OpCodes.Ldtoken.Value) {
                bool isType = h.Kind is HandleKind.TypeReference or HandleKind.TypeDefinition or HandleKind.TypeSpecification;
                int sep = name.IndexOf("::", StringComparison.Ordinal);
                // typeof(T) of a generic parameter is whatever type the caller picks: not traced.
                // A method or field handle names its member, and with it the declaring type.
                stack.Add(isType ? (assembly.IsGenericParameter(h) ? Slot.Unknown : new(Tag.Type, name, Asm: assembly.TypeAssembly(h)))
                    : sep > 0 ? new(Tag.Member, name[..sep], Asm: assembly.ExternalAssemblyOf(h) ?? assembly.Name) : Slot.Unknown);
                return;
            }
            if (FieldAddressOps.Contains(v) || v == OpCodes.Ldelema.Value) {
                // An element's address can be written through: the collection is lost.
                if (v == OpCodes.Ldelema.Value && Peek(1).Tag == Tag.Collection) {
                    Coll(Peek(1).Number).Tainted ??= "an element's address is taken";
                    Coll(Peek(1).Number).Exposed = true;
                }
                for (int i = 0; i < StackEffect.Pops(oc.StackBehaviourPop); i++) Escape(Pop());
                stack.Add(new(Tag.Address));
                return;
            }
        }

        // everything else: generic stack effect; values become unknown
        for (int i = 0; i < StackEffect.Pops(oc.StackBehaviourPop); i++) Escape(Pop());
        for (int i = 0; i < StackEffect.Pushes(oc.StackBehaviourPush); i++) stack.Add(Slot.Unknown);
    }

    Slot Arg(int i) => byrefArgs.Contains(i) ? new(Tag.Address)
        : shape.ByrefArgs.Contains(i) ? Slot.Unknown  // its address is taken somewhere: not trusted
        : shape.PathArgs.Contains(i) ? PathSlot([PathAtoms.Argument(mf.Key, i)])
        // A Type or member argument is what every call passes (resolved per mod, see Nodes).
        : shape.ReflectionArgs.Contains(i) ? new(Tag.Node, Nodes.Arg(mf.Key, i))
        : i < shape.ArgTypes.Count && shape.ArgTypes[i] is { } d ? ObjectOf(d)
        : Slot.Unknown;

    // A lookup in a TargetMethod(s) finds the member Harmony patches: what it can do counts as for a
    // patch target declared by attribute.
    // What the class's patch methods can do to it decides what the patched member passes on.
    void AddReflected(ReflectedType r) => mf.ReflectedTypes.Add(targetMethod == TargetMethodKind.None ? r
        : r with { PatchTarget = true, Patch = assembly.PatchClassEffect(DeclaringType(mf.Name)) });

    static string PathKey(string methodKey, int index) => index < 0 ? methodKey + "#*" : $"{methodKey}#{index}";

    // starg: a by-reference argument must keep holding a managed reference; a path argument also
    // comes from what is stored to it, recorded as a call to this method.
    void StoreArg(int i, Slot value) {
        if (byrefArgs.Contains(i)) RequireReference(value, $"a value stored to by-reference argument {i}");
        if (shape.PathArgs.Contains(i)) Set(mf.PathArguments, PathKey(mf.Key, i)).UnionWith(PathAtoms.Combine(Atoms(value, true)));
        if (shape.ReflectionArgs.Contains(i)) StoreNode(Nodes.Arg(mf.Key, i), value);
        if (shape.PathArgs.Contains(i)) Set(mf.StringArguments, Nodes.Arg(mf.Key, i)).Add(StringValue(value));
        Escape(value);
    }

    // stloc: a by-reference local is trusted to hold a managed reference wherever it is loaded.
    void Stloc(int i, Slot value) {
        if (byrefLocals.Contains(i)) RequireReference(value, $"a value stored to by-reference local {i}");
        // A by-reference local holding an operand's address is written through where the check does not look.
        if (value is { Tag: Tag.Address, Text: InstructionOperand })
            mf.UnresolvedReflection.Add($"the address of a Harmony instruction's operand is kept in a local, through which anything can be stored  <-  {mf.Name}");
        if (value is { Tag: Tag.Unknown, Text: InterpolationHandler }) handlers[i] = new();
        StoreLocal(i, value);
    }

    // Pointer types in a referenced member's signature hand out or take raw addresses. The one
    // exception is a span over a stackalloc buffer or compiler-emitted static data, with a
    // length that fits it, which is what the compiler emits for safe code.
    bool PointerSignatureAccountedFor(EntityHandle h, string name, ImmutableArray<string> ps, Slot[] args) {
        if (!SpanPointerCtors.Contains(name) || ps.Length != 2 || ps[0] != "System.Void*" || ps[1] != "System.Int32") return false;
        if (args.Length < 2 || assembly.SpanElementType(h) is not { } element) return false;
        var buffer = args[0];
        var length = args[1];
        int? elementSize = PrimitiveSizes.TryGetValue(element, out var sz) ? sz : null;
        if (buffer.Tag == Tag.StaticData || (buffer.Tag == Tag.Stackalloc && buffer.Text == null && buffer.Number >= 0))
            return length.Tag == Tag.Int && elementSize is int es && length.Number >= 0 && (long)length.Number * es <= buffer.Number;
        if (buffer.Tag != Tag.Stackalloc || buffer.Text == null) return false;
        bool sameElement = buffer.Text == "sizeof:" + element
            || (elementSize is int es2 && buffer.Text == es2.ToString(System.Globalization.CultureInfo.InvariantCulture));
        if (!sameElement) return false;
        return buffer.Store >= 0
            ? length.Store == buffer.Store
            : length.Tag == Tag.Int && length.Number >= 0 && length.Number <= buffer.Number;
    }

    void Call(EntityHandle h, string name, bool isNewobj) {
        if (assembly.KeyOf(h) is { } key) mf.Callees.Add(key);
        if (Il.Signature(md, h) is not { } sig) {
            var unknown = policy.Classify(name);
            foreach (var cap in unknown.Caps) Note(cap, name + "  <-  " + mf.Name);
            External(h, name, unknown);
            ClearStack();
            stack.Add(Slot.Unknown);  // unknown arity: drop all tracking
            return;
        }
        var ps = sig.ParameterTypes;
        int self = sig.Header.IsInstance && !isNewobj ? 1 : 0;
        var args = new Slot[ps.Length + self];
        for (int i = args.Length - 1; i >= 0; i--) args[i] = Pop();

        var classification = policy.Classify(name, ps);
        External(h, name, classification);
        var caps = classification.Caps.ToList();
        // The semantics modelled below for framework and Harmony members, which narrow what a call
        // counts as, hold only for those members themselves, not for a type that is only named like
        // one (see AssemblyWalker.Models): that is ordinary code, or code that was not analyzed.
        bool modelled = assembly.Models(h, name);
        if (h.Kind != HandleKind.MethodDefinition && (AssemblyWalker.IsPointer(sig.ReturnType) || ps.Any(AssemblyWalker.IsPointer))
            && !(modelled && PointerSignatureAccountedFor(h, name, ps, args)))
            Note("raw-memory", $"pointer type in the signature of {name}  <-  {mf.Name}", Origin.Structure);
        if (isHelper) caps.Remove("raw-memory");
        if (h.Kind == HandleKind.MethodSpecification) {
            var target = md.GetMethodSpecification((MethodSpecificationHandle)h).Method;
            if (target.Kind == HandleKind.MethodDefinition && assembly.IsCompilerHelper((MethodDefinitionHandle)target)) {
                var helper = md.GetString(md.GetMethodDefinition((MethodDefinitionHandle)target).Name);
                if (assembly.HelperCallProblem((MethodSpecificationHandle)h, helper, args[self..]) is { } problem)
                    Note("raw-memory", $"compiler inline-array helper {helper} used outside the compiler pattern ({problem})  <-  {mf.Name}", Origin.Structure);
            }
        }
        if (modelled && name == ProcessStart) {
            var opens = StartKind(ps, args);
            if (opens?.Url != null) {
                caps.Remove("process-start");
                caps.Add("shell-open");
            }
            // A folder: what it opens is decided once its path is traced (see FileAccess).
            else if (opens?.Folder is { } folder) {
                caps.Remove("process-start");
                mf.FolderOpens.Add(new(name, folder));
            }
        }
        // A folder this method has just created: opening it starts the file manager, not a program.
        if (modelled && name == "System.IO.Directory::CreateDirectory" && ps.Length == 1 && Identity(args[0]) is { } created) createdDirs.Add(created);
        // What an instruction a transpiler makes or changes refers to (see OperandTarget).
        if (OperandArgument(name, ps, self) is int operand) OperandTarget(args[operand], $"the operand given to {name}");
        // The address of an operand handed to code that can store anything through it.
        if (args.Any(a => a is { Tag: Tag.Address, Text: InstructionOperand }))
            mf.UnresolvedReflection.Add($"the address of a Harmony instruction's operand is passed to {name}, which can store anything there  <-  {mf.Name}");
        if (name == "HarmonyLib.Transpilers::MethodReplacer" && args.Length == 3) Target(args[2], name, false);
        // The original of a manual patch with a transpiler is rewritten (see RewriteTarget).
        if (modelled) ManualRewrite(name, ps, args, self);
        // Compiling an expression tree built only from members the check traced runs those members,
        // as invoking them would: it is not code generation (see Expressions).
        if (modelled && name is "System.Linq.Expressions.LambdaExpression::Compile" or "System.Linq.Expressions.Expression`1::Compile" && self == 1 && args[0].Tag == Tag.Expr)
            caps.Remove("code-generation");
        // Newtonsoft.Json creates types named in the input unless TypeNameHandling is None (0).
        if (TypeNameHandlingSetters.Contains(name) && !(args.Length > 1 && args[1].Tag == Tag.Int && args[1].Number == 0))
            caps.Add("serialization-unsafe");

        // A by-reference argument is written or read through by the callee, which trusts it to be
        // a managed reference (see Arg). The receiver of a value type's method is not checked here:
        // a member reference does not say whether its type is a value type (see README, Known gaps).
        for (int i = 0; i < ps.Length; i++)
            if (ps[i].EndsWith('&') && !isHelper) RequireReference(args[i + self], $"by-reference argument {i} of {name}");

        HashSet<string>? opPath = null;
        foreach (var cap in caps) {
            Note(cap, name + "  <-  " + mf.Name);
            if (policy.FileKinds.TryGetValue(cap, out var kind)) mf.FileOps.Add(new(kind, name, opPath ??= OperationPath(name, ps, args, self), policy.MayBeUrl(name, ps)));
        }
        if (assembly.GameApi.TryGetValue(name, out var gameCaps))
            foreach (var cap in gameCaps) Note(cap, $"{name} (game API)  <-  {mf.Name}", Origin.GameApi);
        RecordPathArguments(h, sig, args, self);
        RecordReflectionArguments(h, sig, args, self);

        // Collections and expression trees first: they decide which arguments the call keeps in sight.
        var result = modelled ? Collections(h, name, sig, args, self, isNewobj) : null;
        bool expression = modelled && name.StartsWith("System.Linq.Expressions.Expression::", StringComparison.Ordinal) && self == 0;
        bool cleanArgs = expression && ExpressionArgumentsClean(ps, args);
        if (result == null) {
            // Every collection passed elsewhere can be changed there; an expression factory only
            // reads the expressions it is given.
            foreach (var a in args)
                if (!(expression && a.Tag == Tag.Collection && collections.TryGetValue(a.Number, out var ec) && ec.Expressions)) Lose(a, $"passed to {name}");
            int before = mf.UnresolvedReflection.Count;
            result = TrackStartInfo(name, modelled, isNewobj, ps, args)
                ?? (modelled ? Interpolate(h, name, ps, args, self) ?? Reflect(h, name, sig, args, self) : Slot.Unknown);
            // A factory whose members are all traced, given only clean expressions, builds a clean tree.
            if (expression && cleanArgs && mf.UnresolvedReflection.Count == before && ReflectionApis.IsCleanExpressionFactory(name)) result = new(Tag.Expr);
        }
        var r = result.Value;
        // A delegate made from a method pointer is a delegate to that method.
        if (isNewobj && ps is ["System.Object", "System.IntPtr"] && args[1].Tag == Tag.Delegate) r = args[1] with { Store = -1 };
        // A getter that returns a Type or member field unchanged yields that field's value.
        if (r.Tag == Tag.Unknown && !isNewobj && assembly.GetterField(h) is { } getter) r = new(Tag.Node, Nodes.Field(getter));
        // A Type or member returned by a method of the mod is what that method returns (resolved per mod).
        // (Harmony's and the framework's reflection helpers are modelled in Reflect: an unknown result there is untraced.)
        if (r.Tag == Tag.Unknown && !isNewobj && ReflectionApis.IsReflectionType(sig.ReturnType) && assembly.KeyOf(h) is { } returns && !IsFramework(h)
            && !name.StartsWith("HarmonyLib.", StringComparison.Ordinal))
            r = new(Tag.Node, Nodes.Return(returns));
        // A ref return is a managed reference; the one to the operand of the instruction a CodeMatcher
        // is at is an operand's address (what is stored through it is an operand).
        if (sig.ReturnType.EndsWith('&')) r = name == "HarmonyLib.CodeMatcher::get_Operand" ? new(Tag.Address, InstructionOperand) : new(Tag.Address);
        else if (r.Tag == Tag.Unknown) r = PathResult(h, name, sig, args, self, isNewobj, modelled) ?? r;
        // Anything else is an object of the type the method declares it returns (a new object: exactly of its type).
        if (r is { Tag: Tag.Unknown, Text: null }) {
            var declared = !isNewobj ? assembly.ReturnDeclared(h)
                : h.Kind == HandleKind.MethodDefinition ? new(Il.TypeName(md, md.GetMethodDefinition((MethodDefinitionHandle)h).GetDeclaringType()), assembly.Name, true)
                : h.Kind == HandleKind.MemberReference ? assembly.DeclaredOfToken(Il.ParentType(md, md.GetMemberReference((MemberReferenceHandle)h).Parent), true)
                : null;
            if (declared is { } d) r = ObjectOf(d);
        }
        if (isNewobj || sig.ReturnType != "System.Void") stack.Add(r);
    }

    // Framework assemblies are never analyzed with a mod: what their members return or are given is not resolved.
    bool IsFramework(EntityHandle h) => assembly.ExternalAssemblyOf(h) is { } a
        && (a.StartsWith("System", StringComparison.Ordinal) || a.StartsWith("Microsoft", StringComparison.Ordinal) || a is "mscorlib" or "netstandard");

    // The Type and member arguments of a call into code that may be analyzed with the mod: what each
    // of those parameters is given (see Nodes). Numbered as in RecordPathArguments.
    void RecordReflectionArguments(EntityHandle h, MethodSignature<string> sig, Slot[] args, int self) {
        if (assembly.KeyOf(h) is not { } key) return;  // no node: nothing can look the arguments up
        // Silence on purpose: framework methods are never analyzed, so their arguments are not needed.
        if (IsFramework(h)) return;
        var ps = sig.ParameterTypes;
        int numbered = sig.Header.IsInstance ? 1 : 0;
        for (int i = 0; i < ps.Length; i++) {
            if (ReflectionApis.IsReflectionType(ps[i])) StoreNode(Nodes.Arg(key, i + numbered), args[i + self]);
            // A string given to a method of this assembly may name a member it looks up (see NameParameter).
            else if (ps[i] == "System.String" && h.Kind is HandleKind.MethodDefinition or HandleKind.MethodSpecification)
                Set(mf.StringArguments, Nodes.Arg(key, i + numbered)).Add(StringValue(args[i + self]));
        }
    }

    // A string argument as recorded in StringArguments: a constant, one of this method's own string
    // parameters, or anything else.
    string StringValue(Slot s) => s.Tag == Tag.String && s.Text != null ? "=" + s.Text
        : NameParameter(s) is { } own ? "@" + own
        : s.Tag == Tag.Null ? "=" : "?";

    // The node of this method's string parameter a value is, unchanged; null if it is anything else.
    string? NameParameter(Slot s) {
        if (s.Tag != Tag.Path) return null;
        var atoms = PathAtoms.Decode(s.Text).ToList();
        return atoms.Count == 1 && atoms[0].StartsWith(Nodes.Arg(mf.Key, 0)[..^1], StringComparison.Ordinal) ? atoms[0] : null;
    }

    // Whether every expression an Expression factory is given is clean: an expression the walker built
    // (Tag.Expr), null, or an array or list of clean expressions that nothing else can change.
    bool ExpressionArgumentsClean(ImmutableArray<string> ps, Slot[] args) {
        for (int i = 0; i < ps.Length; i++) {
            if (ReflectionApis.IsReflectionType(ps[i]) || !ReflectionApis.IsExpressionType(ps[i])) continue;  // members are the sink's (see Reflect)
            var a = args[i];
            if (a.Tag is Tag.Expr or Tag.Null) continue;
            if (a.Tag == Tag.Collection && collections.TryGetValue(a.Number, out var c) && c.Expressions
                && StateOf(a.Number) is { Tainted: null, Escaped: null }) continue;
            return false;
        }
        return true;
    }

    // Members of arrays, lists, enumerators and LINQ the walker follows for its collections (see
    // NewCollection). Null when the call is none of them; then the caller loses every collection it is given.
    Slot? Collections(EntityHandle h, string name, MethodSignature<string> sig, Slot[] args, int self, bool isNewobj) {
        var ps = sig.ParameterTypes;
        string type = DeclaringType(name), member = name[(name.IndexOf("::", StringComparison.Ordinal) + 2)..];
        // new List<T>() and List<T>(capacity) start empty; List<T>(sequence) holds the sequence's elements.
        if (isNewobj && type == "System.Collections.Generic.List`1") {
            if (assembly.SpanElementType(h) is not { } element || !(ReflectionApis.IsReflectionType(element) || ReflectionApis.IsExpressionType(element))) return null;
            bool expressions = ReflectionApis.IsExpressionType(element);
            if (ps.Length == 0 || ps[0] == "System.Int32") return NewCollection(c => c.Expressions = expressions);
            var source = args[0];
            var made = NewCollection(c => c.Expressions = expressions);
            if (source.Tag == Tag.Collection) {
                Coll(made.Number).Includes.Add((source.Number, false));
                Expose(source);
            } else Coll(made.Number).Tainted ??= "made from a sequence the check does not follow";
            return made;
        }
        if (name == "System.Array::Empty") {
            var targs = assembly.MethodTypeArguments(h);
            if (targs.Length != 1 || !(ReflectionApis.IsReflectionType(targs[0]) || ReflectionApis.IsExpressionType(targs[0]))) return null;
            bool expressions = ReflectionApis.IsExpressionType(targs[0]);
            return NewCollection(c => c.Expressions = expressions);
        }
        // The types of an assembly whose name is known: each is a type of that assembly.
        if (name is "System.Reflection.Assembly::GetTypes" or "System.Reflection.Assembly::GetExportedTypes"
            or "System.Reflection.Assembly::get_DefinedTypes" or "System.Reflection.Assembly::get_ExportedTypes") {
            if (args.Length == 0 || args[0] is not { Tag: Tag.Assembly, Asm: { Length: > 0 } of }) return null;
            return NewCollection(c => { c.Held.Add(new("*", of, false, true)); c.Lookup = true; });
        }
        var receiver = args.Length > 0 ? args[0] : Slot.Unknown;
        // An enumerator's element; its own members do not change the collection.
        var enumerator = receiver.Tag == Tag.Enumerator ? receiver
            : receiver is { Tag: Tag.Address, Number: > 0 } && LocalValue(receiver.Number - 1) is { Tag: Tag.Enumerator } e ? e : default;
        if (self == 1 && enumerator.Tag == Tag.Enumerator
            && type is "System.Collections.Generic.IEnumerator`1" or "System.Collections.IEnumerator" or "System.Collections.Generic.List`1/Enumerator" or "System.IDisposable")
            return member == "get_Current" ? Taken(enumerator.Number) : Slot.Unknown;
        if (receiver.Tag != Tag.Collection) return null;
        int id = receiver.Number;
        Slot Same() => receiver with { Store = -1 };
        Slot Element() => Taken(id);
        // Code given a delegate sees the elements (unless the delegate is a filter by a constant name, see NameFilter).
        void Sees() => Coll(id).Exposed = true;
        // Instance members of the collection (List<T>, its interfaces, arrays).
        if (self == 1 && type is "System.Collections.Generic.List`1" or "System.Collections.Generic.IList`1" or "System.Collections.Generic.ICollection`1"
            or "System.Collections.Generic.IEnumerable`1" or "System.Collections.Generic.IReadOnlyList`1" or "System.Collections.IEnumerable" or "System.Array") {
            switch (member) {
                case "Add" or "Insert" or "set_Item":
                    AddTo(id, args[^1]);
                    return Slot.Unknown;
                case "AddRange" or "InsertRange":
                    if (args[^1].Tag == Tag.Collection) {
                        Coll(id).Includes.Add((args[^1].Number, false));
                        Expose(args[^1]);
                    } else Coll(id).Tainted ??= "holds a sequence the check does not follow";
                    return Slot.Unknown;
                case "get_Item" or "Find" or "FindLast":
                    return Element();
                case "GetEnumerator":
                    Sees();
                    return new(Tag.Enumerator, Number: id);
                case "ToArray":
                    return Same();
                case "FindAll":
                    Sees();
                    return Same();
                case "RemoveAll" or "Sort" or "Exists" or "TrueForAll" or "FindIndex" or "FindLastIndex" or "BinarySearch":
                    Sees();
                    return Slot.Unknown;
                case "get_Count" or "get_Length" or "get_LongLength" or "Contains" or "IndexOf" or "LastIndexOf" or "Remove" or "RemoveAt"
                    or "RemoveRange" or "Clear" or "Reverse":
                    return Slot.Unknown;
            }
            Lose(receiver, $"passed to {name}");
            return Slot.Unknown;
        }
        // LINQ never changes its source: elements and sequences of it are its elements.
        if (type == "System.Linq.Enumerable" && self == 0) {
            // A filter that requires a constant member name: the element it gives is a member of that name.
            string? named = args.Length == 2 && member is "First" or "FirstOrDefault" or "Single" or "SingleOrDefault" or "Last" or "LastOrDefault"
                or "Any" or "All" or "Count" or "LongCount" ? NameFilter(args[1]) : null;
            if (named != null) {
                Coll(id).Names.Add(named);
                return member is "Any" or "All" or "Count" or "LongCount" ? Slot.Unknown : new(Tag.Element, Number: id);
            }
            switch (member) {
                case "First" or "FirstOrDefault" or "Single" or "SingleOrDefault" or "Last" or "LastOrDefault" or "ElementAt" or "ElementAtOrDefault":
                    return Element();
                case "ToArray" or "ToList" or "Distinct" or "Skip" or "Take" or "Reverse" or "AsEnumerable" or "DefaultIfEmpty":
                    return Same();
                case "Where" or "OrderBy" or "OrderByDescending" or "ThenBy" or "ThenByDescending" or "SkipWhile" or "TakeWhile":
                    Sees();
                    return Same();
                case "Concat" or "Union":
                    if (args.Length > 1 && args[1].Tag == Tag.Collection) {
                        Coll(id).Includes.Add((args[1].Number, false));
                        Expose(args[1]);
                    } else Coll(id).Tainted ??= "combined with a sequence the check does not follow";
                    return Same();
                case "Append" or "Prepend":
                    if (args.Length > 1) AddTo(id, args[1]);
                    return Same();
                case "Count" or "LongCount" or "Any" when args.Length == 1:
                    return Slot.Unknown;
            }
            Sees();
            return Slot.Unknown;  // any other LINQ result is not followed; the source is unchanged
        }
        // Array's static helpers that only read the array, or return its elements.
        if (type == "System.Array" && self == 0) {
            switch (member) {
                case "Find" or "FindLast":
                    return Element();
                case "FindAll":
                    Sees();
                    return Same();
                case "Sort" or "Exists" or "TrueForAll" or "BinarySearch" or "FindIndex" or "FindLastIndex" or "ForEach":
                    Sees();
                    return Slot.Unknown;
                case "Reverse" or "IndexOf" or "LastIndexOf" or "Clear":
                    return Slot.Unknown;
            }
        }
        return null;
    }

    // Interpolated strings ($"{dir}/{name:x}.cfg") build their text in a handler local: the path atoms
    // of what is appended to it, per local, from its constructor to ToStringAndClear.
    sealed class Interpolation {
        public readonly List<string> Atoms = [];
        public List<string> Last = [];  // the atoms of the part appended last, which ends the text so far
        public bool Started;  // something was appended: what follows is a fragment, not the start of the path

        // A new part ends the text: the one before it is followed by more.
        public void Append(IEnumerable<string> part) {
            Atoms.AddRange(PathAtoms.Mid(Last));
            Last = [.. part];
        }
    }
    readonly Dictionary<int, Interpolation> handlers = [];
    const string InterpolationHandler = "System.Runtime.CompilerServices.DefaultInterpolatedStringHandler";

    Slot? Interpolate(EntityHandle h, string name, ImmutableArray<string> ps, Slot[] args, int self) {
        if (DeclaringType(name) != InterpolationHandler) return null;
        // new DefaultInterpolatedStringHandler(...) stored to a local starts that local's text (see Stloc).
        if (self == 0) return name.EndsWith("::.ctor", StringComparison.Ordinal) ? new(Tag.Unknown, InterpolationHandler) : null;
        // Silence on purpose: a handler the walker cannot place (not a local's address) yields an
        // untraced string at ToStringAndClear, through its result (see PathResult).
        if (args[0] is not { Tag: Tag.Address, Number: > 0 } receiver) return null;
        int local = receiver.Number - 1;
        string member = name[(InterpolationHandler.Length + 2)..];
        if (member == ".ctor") { handlers[local] = new(); return null; }
        if (!handlers.TryGetValue(local, out var text)) return null;
        if (member is "ToStringAndClear" or "ToString") return PathSlot(PathAtoms.Combine(text.Atoms.Concat(text.Last)));
        if (member is not ("AppendLiteral" or "AppendFormatted")) return null;
        // What is appended: a string or path value, or a value of the type argument (a number or
        // date adds no path of its own); a format string adds only what a literal fragment adds.
        var targs = assembly.MethodTypeArguments(h);
        for (int i = 0; i < ps.Length; i++) {
            var a = args[i + 1];
            if (i > 0) {
                // A format: its text is part of the value's ("F2" adds a dot); the alignment adds nothing.
                if (ps[i] == "System.String") {
                    text.Atoms.AddRange(PathAtoms.Mid(Atoms(a, false)));
                    if (a.Tag != Tag.Null) text.Last.Add(PathAtoms.End);
                }
                continue;
            }
            bool pathish = a.Tag is Tag.Path or Tag.String or Tag.Null
                || ps[0] is "System.String" or "System.Object" or "System.ReadOnlySpan`1"
                || (ps[0] == "!!0" && targs.Length == 1 && (PathAtoms.IsPathType(targs[0]) || targs[0] is "System.Object" || targs[0].StartsWith('!')));
            if (pathish) text.Append(PartAtoms(a, !text.Started, !text.Started, true));
            // A value of another type (the name of an enum value, a number): it adds no path, but the text
            // can begin (end) with it, and what follows can make it a web address (a name with a dot).
            else text.Append(text.Started ? [PathAtoms.End] : [PathAtoms.Head, PathAtoms.End]);
        }
        text.Started = true;
        return null;
    }

    // Path APIs whose operands can each be a rooted path that replaces what came before.
    static readonly HashSet<string> RootingCombiners = [
        "System.IO.Path::Combine", "System.IO.Path::GetFullPath", "System.IO.FileInfo::.ctor", "System.IO.DirectoryInfo::.ctor",
        "System.IO.FileSystemWatcher::.ctor", "System.IO.DirectoryInfo::CreateSubdirectory", "System.IO.Directory::CreateDirectory",
        "System.IO.Directory::GetParent",
    ];
    // APIs whose result is a path (or a file-system object, or a collection of them) made from their
    // operands: the receiver or first operand starts it, the others are appended to it. Members of
    // System.Linq.Enumerable that return elements of their source are in EnumerableSources.
    static readonly HashSet<string> AppendingCombiners = [
        "System.IO.Path::Join", "System.IO.Path::GetDirectoryName", "System.IO.Path::ChangeExtension", "System.IO.Path::GetFileName",
        "System.IO.Path::GetFileNameWithoutExtension", "System.IO.Path::TrimEndingDirectorySeparator", "System.IO.Path::GetPathRoot",
        "System.String::Concat", "System.String::Replace", "System.String::Trim", "System.String::TrimEnd", "System.String::TrimStart",
        "System.String::Substring", "System.String::ToLower", "System.String::ToLowerInvariant", "System.String::ToUpper",
        "System.String::ToUpperInvariant", "System.String::Normalize", "System.String::Insert", "System.String::Remove",
        "System.String::ToString", "System.String::Copy", "System.String::Intern",
        "System.IO.FileSystemInfo::get_FullName", "System.IO.FileSystemInfo::get_Name", "System.IO.FileSystemInfo::ToString",
        "System.IO.FileInfo::get_FullName", "System.IO.FileInfo::get_Name", "System.IO.FileInfo::get_DirectoryName", "System.IO.FileInfo::get_Directory",
        "System.IO.DirectoryInfo::get_FullName", "System.IO.DirectoryInfo::get_Name", "System.IO.DirectoryInfo::get_Parent", "System.IO.DirectoryInfo::get_Root",
        "System.IO.DirectoryInfo::GetFiles", "System.IO.DirectoryInfo::GetDirectories", "System.IO.DirectoryInfo::GetFileSystemInfos",
        "System.IO.DirectoryInfo::EnumerateFiles", "System.IO.DirectoryInfo::EnumerateDirectories", "System.IO.DirectoryInfo::EnumerateFileSystemInfos",
        "System.IO.Directory::GetFiles", "System.IO.Directory::GetDirectories", "System.IO.Directory::GetFileSystemEntries",
        "System.IO.Directory::EnumerateFiles", "System.IO.Directory::EnumerateDirectories", "System.IO.Directory::EnumerateFileSystemEntries",
        "System.IO.Directory::GetDirectoryRoot",
        "System.Collections.Generic.IEnumerable`1::GetEnumerator", "System.Collections.Generic.IEnumerator`1::get_Current",
        "System.Collections.IEnumerable::GetEnumerator", "System.Collections.IEnumerator::get_Current",
    ];
    // Members among the combiners whose result does not keep the end of the path they are given.
    static readonly HashSet<string> NotSuffixPreserving = [
        "System.String::Replace", "System.String::Substring", "System.String::Remove", "System.String::Insert", "System.String::Trim",
        "System.String::TrimStart", "System.String::TrimEnd", "System.IO.Path::GetDirectoryName", "System.IO.Path::ChangeExtension",
        "System.IO.Path::GetPathRoot", "System.IO.FileInfo::get_DirectoryName", "System.IO.FileInfo::get_Directory",
        "System.IO.DirectoryInfo::get_Parent", "System.IO.DirectoryInfo::get_Root", "System.IO.Directory::GetParent",
        "System.IO.Directory::GetDirectoryRoot",
    ];
    // Members among the combiners whose result does not keep the beginning of the path they are given.
    static readonly HashSet<string> NotPrefixPreserving = [
        "System.String::Replace", "System.String::Substring", "System.String::Remove", "System.String::Insert", "System.String::Trim",
        "System.String::TrimStart", "System.IO.Path::GetFileName", "System.IO.Path::GetFileNameWithoutExtension", "System.IO.Path::GetPathRoot",
        "System.IO.FileSystemInfo::get_Name", "System.IO.FileInfo::get_Name", "System.IO.DirectoryInfo::get_Name",
    ];
    static readonly HashSet<string> EnumerableSources = [
        "Where", "First", "FirstOrDefault", "Last", "LastOrDefault", "Single", "SingleOrDefault", "ElementAt", "ElementAtOrDefault",
        "ToList", "ToArray", "OrderBy", "OrderByDescending", "ThenBy", "ThenByDescending", "Distinct", "Skip", "Take", "Reverse",
        "Concat", "Union", "Intersect", "Except", "AsEnumerable", "DefaultIfEmpty", "Append", "Prepend",
    ];
    // Operand types that never carry a path: an unknown value of one of these adds nothing.
    static readonly HashSet<string> NonPathOperands = [
        "System.Char", "System.Char[]", "System.Int32", "System.Int64", "System.Boolean", "System.StringComparison",
        "System.IFormatProvider", "System.Globalization.CultureInfo", "System.Text.NormalizationForm", "System.IO.SearchOption",
        "System.IO.EnumerationOptions", "System.StringSplitOptions", "System.Globalization.CompareOptions",
        "System.Func`2", "System.Func`3", "System.Predicate`1", "System.Comparison`1", "System.Collections.Generic.IComparer`1",
        "System.Collections.Generic.IEqualityComparer`1",
    ];
    // File APIs with more than one path operand (source and destination).
    static readonly string[] MultiPathOperations = [
        "System.IO.File::Copy", "System.IO.File::Move", "System.IO.File::Replace", "System.IO.File::CreateSymbolicLink",
        "System.IO.Directory::Move", "System.IO.Directory::CreateSymbolicLink", "System.IO.FileInfo::CopyTo", "System.IO.FileInfo::MoveTo",
        "System.IO.FileInfo::Replace", "System.IO.DirectoryInfo::MoveTo", "System.IO.Compression.ZipFile::ExtractToDirectory",
        "System.IO.Compression.ZipFile::CreateFromDirectory", "System.Formats.Tar.TarFile::ExtractToDirectory",
        "System.Formats.Tar.TarFile::CreateFromDirectory", "System.Security.Cryptography.X509Certificates.X509Certificate2::CreateFromPemFile",
        "System.Security.Cryptography.X509Certificates.X509Certificate2::CreateFromEncryptedPemFile",
    ];

    static string DeclaringType(string name) => name[..Math.Max(0, name.IndexOf("::", StringComparison.Ordinal))];

    // Where the path a file operation acts on comes from: the file-system object it is called on,
    // and its first string operand (every string operand for a copy or move). An operation with
    // no path operand (a file handle, a stream) cannot be traced.
    HashSet<string> OperationPath(string name, IReadOnlyList<string> ps, Slot[] args, int self) {
        var parts = new List<string>();
        bool any = false;
        if (self == 1 && PathAtoms.IsFileSystemObject(DeclaringType(name))) { parts.AddRange(Atoms(args[0], true)); any = true; }
        bool multi = MultiPathOperations.Any(m => name.StartsWith(m, StringComparison.Ordinal));
        for (int i = 0; i < ps.Count; i++) {
            if (ps[i] != "System.String") continue;
            parts.AddRange(PathAtoms.Combine(Atoms(args[i + self], true)));
            any = true;
            if (!multi) break;
        }
        return any ? PathAtoms.Combine(parts) : [PathAtoms.Untraced];
    }

    // The path atoms of the path-typed arguments of a call into code that may be analyzed with the
    // mod, for the callee's own path operations (see FileAccess).
    // self: whether args include this (not for newobj). The callee numbers its arguments from this
    // whenever it is an instance method, constructors included.
    void RecordPathArguments(EntityHandle h, MethodSignature<string> sig, Slot[] args, int self) {
        if (assembly.KeyOf(h) is not { } key) return;  // no node: nothing can look the arguments up
        // Silence on purpose: framework methods are never analyzed, so their arguments are not needed.
        if (assembly.ExternalAssemblyOf(h) is { } a && (a.StartsWith("System", StringComparison.Ordinal) || a.StartsWith("Microsoft", StringComparison.Ordinal)
            || a is "mscorlib" or "netstandard")) return;
        var ps = sig.ParameterTypes;
        int numbered = sig.Header.IsInstance ? 1 : 0;
        for (int i = 0; i < ps.Length; i++)
            if (PathAtoms.IsPathType(ps[i])) Set(mf.PathArguments, PathKey(key, i + numbered)).UnionWith(PathAtoms.Combine(Atoms(args[i + self], true)));
    }

    // The path value a call returns, or null if it returns none: a path source, a combination of
    // its operands, or (for any other method returning a path type, and for one only named like a
    // framework path API, see AssemblyWalker.Models) whatever that method returns.
    Slot? PathResult(EntityHandle h, string name, MethodSignature<string> sig, Slot[] args, int self, bool isNewobj, bool modelled) {
        if (!modelled) return Returned(h, name, sig, isNewobj);
        if (policy.PathSources.TryGetValue(name, out var origin)) {
            if (origin == "special-folder")
                origin = args.Length > 0 && args[0].Tag == Tag.Int && args[0].Number == policy.DocumentsFolder ? "documents" : "user-folder";
            // A folder the game or the user names (the game's folder can be inside a macOS ".app"); an
            // environment variable can hold anything, a web address included.
            return PathSlot(origin == "environment" ? [origin, PathAtoms.Head, PathAtoms.End] : [origin, PathAtoms.End]);
        }
        var ps = sig.ParameterTypes;
        bool rooting = RootingCombiners.Contains(name);
        bool enumerable = name.StartsWith("System.Linq.Enumerable::", StringComparison.Ordinal) && EnumerableSources.Contains(name[24..]);
        bool collection = enumerable || name.StartsWith("System.Collections.", StringComparison.Ordinal);
        // Silence on purpose: an enumerator or sequence that holds no path yields no path.
        if (collection && !args.Any(a => a.Tag == Tag.Path)) return null;
        if (rooting || enumerable || AppendingCombiners.Contains(name)) {
            var parts = new List<string>();
            var operands = Enumerable.Range(0, args.Length)
                .Where(i => args[i].Tag is Tag.Path or Tag.String or Tag.Null || !NonPathOperands.Contains(i < self ? DeclaringType(name) : ps[i - self])).ToList();
            // The first operand begins the result and the last ends it; a later rooted Path.Combine
            // operand replaces what came before, but a rooted path is never a web address.
            foreach (var i in operands)
                parts.AddRange(PartAtoms(args[i], rooting || i == operands[0], i == operands[0], i == operands[^1]));
            // An edit that can drop the beginning or the end of a path (a name taken out of it, a
            // replacement, a parent folder): the result can begin or end with anything.
            if (NotPrefixPreserving.Contains(name)) parts.Add(PathAtoms.Head);
            if (NotSuffixPreserving.Contains(name)) parts.Add(PathAtoms.End);
            return PathSlot(operands.Count > 0 ? PathAtoms.Combine(parts) : [PathAtoms.Untraced, PathAtoms.Head, PathAtoms.End]);
        }
        // The text of a number, character or name generated by the runtime is no path of its own.
        if (ps.Length == 0 && (name == "System.IO.Path::GetRandomFileName" || (name.EndsWith("::ToString", StringComparison.Ordinal)
            && DeclaringType(name) is "System.Char" or "System.Int32" or "System.Int64" or "System.UInt32" or "System.UInt64" or "System.Int16"
                or "System.UInt16" or "System.Byte" or "System.Guid" or "System.Boolean")))
            return PathSlot([PathAtoms.End]);  // a random name has an extension
        return Returned(h, name, sig, isNewobj);
    }

    // What a method returning a path type returns, from its own returns (resolved per mod).
    Slot? Returned(EntityHandle h, string name, MethodSignature<string> sig, bool isNewobj) {
        var returns = isNewobj ? DeclaringType(name) : sig.ReturnType;
        return PathAtoms.IsPathType(returns) && assembly.KeyOf(h) is { } key ? PathSlot([PathAtoms.Return(key)]) : null;
    }

    // Follows ProcessStartInfo objects so that opening a constant web address in the browser is
    // told apart from starting a program. Any use the walker cannot follow disqualifies it.
    Slot? TrackStartInfo(string name, bool modelled, bool isNewobj, ImmutableArray<string> ps, Slot[] args) {
        if (modelled && name.StartsWith(StartInfoType + "::", StringComparison.Ordinal)) {
            if (isNewobj) {
                int id = startInfos.Count;
                startInfos[id] = ps.Length == 0 ? new() : ps.Length == 1 ? Opens(args[0]) : null;
                return new(Tag.StartInfo, Number: id);
            }
            var self = args.Length > 0 ? args[0] : Slot.Unknown;
            if (self.Tag != Tag.StartInfo) { untrackedStartInfo = true; return null; }
            string member = name[(name.IndexOf("::", StringComparison.Ordinal) + 2)..];
            if (member == "set_FileName")
                startInfos[self.Number] = startInfos[self.Number] is { Empty: true } && args.Length > 1 ? Opens(args[1]) : null;
            else if (member != "set_UseShellExecute")
                startInfos[self.Number] = null;
            foreach (var s in args.Skip(1)) EscapeStartInfo(s);
            return null;
        }
        // (Collections passed to the call are lost in Call, which knows which calls only read them.)
        bool startWithInfo = modelled && name == ProcessStart && ps.Length == 1 && ps[0] == StartInfoType;
        foreach (var s in startWithInfo ? args.Skip(1) : args) EscapeStartInfo(s);
        return null;
    }

    // What Process.Start opens, when it is a fixed web address or a folder the method has just
    // created; null for anything else (starting a program).
    StartTarget? StartKind(ImmutableArray<string> ps, Slot[] args) {
        StartTarget? found = null;
        if (ps.Length == 1 && ps[0] == "System.String") found = Opens(args[0]);
        // (A folder is not given to an opener this way: its arguments are one string that the opener
        // splits, so a folder name could carry options.)
        else if (ps.Length == 2 && ps[0] == "System.String" && ps[1] == "System.String")
            found = args[0].Tag == Tag.String && args[0].Text is { } opener && UrlOpeners.Contains(opener) && IsUrl(args[1]) ? new(Url: args[1].Text) : null;
        else if (ps.Length == 1 && ps[0] == StartInfoType && args[0].Tag == Tag.StartInfo && !untrackedStartInfo)
            found = startInfos.GetValueOrDefault(args[0].Number);
        return found is { Empty: false } ? found : null;
    }

    // What a value given as the file to start opens: a fixed web address, a folder the method has
    // just created (its path atoms), or null.
    StartTarget? Opens(Slot s) =>
        IsUrl(s) ? new(Url: s.Text)
        : Identity(s) is { } id && createdDirs.Contains(id) ? new(Folder: PathAtoms.Combine(Atoms(s, true)))
        : null;

    // Which value a path slot is, so that two uses can be told to see the same one: an argument the
    // method never changes, or one store to a local. Null when that is not known.
    string? Identity(Slot s) {
        if (s.Tag != Tag.Path) return null;
        if (s.Store >= 0) return "local store " + s.Store.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var atoms = PathAtoms.Decode(s.Text).ToList();
        for (int i = 0; atoms.Count == 1 && i < shape.ArgTypes.Count + 1; i++)
            if (atoms[0] == PathAtoms.Argument(mf.Key, i) && shape.PathArgs.Contains(i) && !changedArgs.Contains(i)) return "argument " + i.ToString(System.Globalization.CultureInfo.InvariantCulture);
        return null;
    }

    // Harmony members that set the operand of an instruction (a CodeMatch is one too, and a transpiler
    // can return it): their operand parameter is the first of type object. The policy exempts them from
    // what their own code stores (libraries.exempt); the argument is checked here instead.
    static readonly HashSet<string> OperandSetters = [
        "HarmonyLib.CodeInstruction::.ctor", "HarmonyLib.CodeInstruction::Clone", "HarmonyLib.CodeMatch::.ctor", "HarmonyLib.CodeMatch::Set",
        "HarmonyLib.CodeMatcher::Set", "HarmonyLib.CodeMatcher::SetAndAdvance", "HarmonyLib.CodeMatcher::SetOperandAndAdvance",
    ];

    // The index (counting this) of the operand argument of a call to one of OperandSetters, or null.
    static int? OperandArgument(string name, ImmutableArray<string> ps, int self) =>
        OperandSetters.Contains(name) && ps.IndexOf("System.Object") is var i and >= 0 ? i + self : null;

    // Operand values that refer to no code or memory: a number, a string, a label or a local of the method.
    static readonly HashSet<string> InertOperands = [
        "System.Boolean", "System.Char", "System.SByte", "System.Byte", "System.Int16", "System.UInt16", "System.Int32", "System.UInt32",
        "System.Int64", "System.UInt64", "System.Single", "System.Double", "System.String",
        "System.Reflection.Emit.Label", "System.Reflection.Emit.LocalBuilder",
    ];

    // The operand of an instruction Harmony compiles into the patched method: a member there is called,
    // read or written (or its address or token taken) by the game's code, so it must be traced as a
    // reflection target is; a number, string, label or local is inert; an operand taken from another
    // instruction is one the game's method (or this check, where it was set) already accounts for.
    void OperandTarget(Slot v, string what) {
        switch (v.Tag) {
            case Tag.Null or Tag.String or Tag.Int or Tag.Path:
                return;
            case Tag.Type or Tag.Member or Tag.Node or Tag.Element:
                Target(v, what, false);
                return;
            case Tag.Object when v.Text != null && InertOperands.Contains(v.Text):
                return;
        }
        if (IsOperand(v)) return;
        mf.UnresolvedReflection.Add($"{what} is not traced to a name  <-  {mf.Name}");
    }

    // An element taken out of a collection: whatever it is, code now has it.
    Slot Taken(int id) {
        if (id >= 0) Coll(id).Exposed = true;
        return new(Tag.Element, Number: id);
    }

    // A collection (or an enumerator over it) whose elements other code can take.
    void Expose(Slot s) { if (s.Tag is Tag.Collection or Tag.Enumerator) Coll(s.Number).Exposed = true; }

    // The constant member name a LINQ predicate requires of the element it accepts, or null. Only a
    // delegate to a method of this assembly whose code the check has proved begins with the test
    // (see AssemblyWalker.ConstantNameFilter).
    string? NameFilter(Slot predicate) =>
        predicate.Tag == Tag.Delegate && MetadataTokens.EntityHandle(predicate.Number) is { Kind: HandleKind.MethodDefinition } h
            ? assembly.ConstantNameFilter((MethodDefinitionHandle)h) : null;

    // Records what a node (a Type or member field, a parameter, a return value) is given: a resolved
    // type or member, another node's value, an element of a collection, null, or something the
    // walker cannot trace.
    void StoreNode(string node, Slot value) {
        switch (value.Tag) {
            case Tag.Null:
                break;  // holds no member
            case Tag.Type or Tag.Member when value.Text != null && (value.Number & Slot.Moved) == 0:
                Set(mf.ReflectionStores, node).Add(new(value.Text, value.Asm, value.Tag == Tag.Member, (value.Number & Slot.OrDerived) != 0));
                break;
            case Tag.Node when value.Text != null:
                Set(mf.FieldCopies, node).Add(NodeSource(value));
                break;
            case Tag.Element:
                // What the collection holds once the method has run (the first pass records nothing).
                if (StateOf(value) is not { } state) break;
                if (state.Tainted != null || (state.Escaped != null && !state.Lookup)) { mf.UntrackedStores.Add(node); break; }
                foreach (var held in state.Held) Set(mf.ReflectionStores, node).Add(state.Escaped != null ? held with { Bounded = true } : held);
                if (state.Node != null) Set(mf.FieldCopies, node).Add(state.Node);
                break;
            default:
                mf.UntrackedStores.Add(node);
                break;
        }
    }

    // Records what an array of types or members stored into a field holds (see StoreNode): the final
    // contents of a collection this method made, or nothing it can trace.
    void StoreArray(string node, Slot value) {
        if (value.Tag == Tag.Null) return;  // holds no array
        Expose(value);
        if (value.Tag != Tag.Collection) { mf.UntrackedStores.Add(node); return; }
        // What the collection holds once the method has run (the first pass records nothing).
        if (StateOf(value.Number) is not { } state) return;
        if (state.Tainted != null || (state.Escaped != null && !state.Lookup)) { mf.UntrackedStores.Add(node); return; }
        foreach (var held in state.Held) Set(mf.ReflectionStores, node).Add(state.Escaped != null ? held with { Bounded = true } : held);
        if (state.Node != null && state.Node != node) Set(mf.FieldCopies, node).Add(state.Node);
    }

    static HashSet<T> Set<T>(Dictionary<string, HashSet<T>> d, string key) {
        if (!d.TryGetValue(key, out var set)) d[key] = set = [];
        return set;
    }

    // How a bounded type reads in evidence.
    static string Bound(string type, string? asm) => type == "*" ? $"a type of {asm}" : $"{type} or a type derived from it";

    // The argument of a call that runs, creates, reads or writes it must be traced to a name. A type
    // or member known only up to its type's derived types (or its assembly) is bounded; a node's
    // value is resolved from what the node is given; an element from what its collection holds.
    void Target(Slot t, string name, bool writesFields) {
        switch (t.Tag) {
            case Tag.Null:
                break;  // throws
            case Tag.Type or Tag.Member:
                if (t.Text != null && (t.Number & Slot.OrDerived) != 0) {
                    mf.BoundedReflection.Add(new(t.Text, t.Asm, $"{name} on a member of {Bound(t.Text, t.Asm)}  <-  {mf.Name}"));
                    if (writesFields) mf.ReflectionFieldWrites.Add(t.Text == "*" ? "*" : t.Text + "+");
                } else if (writesFields && t.Text != null) {
                    mf.ReflectionFieldWrites.Add(t.Text);
                }
                break;
            case Tag.Node when t.Text != null:
                mf.FieldReflection.Add(new(NodeSource(t), $"{name} on the value of {Nodes.Describe(NodeSource(t))}  <-  {mf.Name}", true, writesFields));
                break;
            case Tag.Element:
                ElementTarget(t, $"{name} on {(t.Number < 0 ? "one of several traced members" : "an element of an array or list")}", writesFields);
                break;
            default:
                mf.UnresolvedReflection.Add($"{name} on a type or member not traced to a name  <-  {mf.Name}");
                break;
        }
    }

    // A sink (or a patch target) on an element of a collection: each type or member the collection
    // holds is what it acts on. Lost because something untraced was put into it: unresolved. Lost
    // because code the walker does not follow had it, when it holds what a member lookup found:
    // bounded to the types looked up (that code may reorder or filter it; putting something else into
    // it is the untraced case, seen where that code runs, see README Known gaps).
    void ElementTarget(Slot element, string what, bool writesFields) {
        if (StateOf(element) is not { } state) return;  // first pass: nothing is recorded
        if (state.Tainted != null || (state.Escaped != null && !state.Lookup)) {
            mf.UnresolvedReflection.Add($"{what} that the check cannot follow ({state.Tainted ?? state.Escaped})  <-  {mf.Name}");
            return;
        }
        foreach (var h in state.Held) {
            if (h.Bounded || state.Escaped != null)
                mf.BoundedReflection.Add(new(h.Type, h.Assembly, $"{what} {(state.Escaped != null ? $"({state.Escaped}) " : "")}holding members of {Bound(h.Type, h.Assembly)}  <-  {mf.Name}"));
            if (writesFields) mf.ReflectionFieldWrites.Add(h.Bounded || state.Escaped != null ? (h.Type == "*" ? "*" : h.Type + "+") : h.Type);
        }
        if (state.Node != null)
            mf.FieldReflection.Add(new(state.Node, $"{what} holding members of the types of {Nodes.Describe(state.Node)}  <-  {mf.Name}", true, writesFields));
    }

    // What a TargetMethod returns. A traced member was looked up on a resolved type, which already
    // granted that type's capabilities; a node's value is resolved from what it is given.
    void PatchTarget(Slot t) {
        switch (t.Tag) {
            case Tag.Null:
                break;  // patches nothing (Harmony reports an error)
            case Tag.Type or Tag.Member:
                if (t.Text != null && (t.Number & Slot.OrDerived) != 0)
                    mf.BoundedReflection.Add(new(t.Text, t.Asm, $"Harmony patch target returned by {mf.Name} is a member of {Bound(t.Text, t.Asm)}"));
                break;  // otherwise a traced member
            case Tag.Node when t.Text != null:
                mf.FieldReflection.Add(new(NodeSource(t), $"Harmony patch target returned from {Nodes.Describe(NodeSource(t))}  <-  {mf.Name}", true));
                break;
            case Tag.Element:
                ElementTarget(t, $"Harmony patch target returned by {mf.Name} is an element of an array or list", false);
                break;
            default:
                mf.UnresolvedReflection.Add($"Harmony patch target returned by {mf.Name} is not traced to a name");
                break;
        }
    }

    // A member a Harmony transpiler rewrites: where the value that names it is placed, for the Evaluator
    // to decide whether it is the game's code (see Facts.RewriteTarget). A value the check cannot place
    // counts as code outside the game.
    void RewriteTarget(Slot t, string what, bool ifRewrites = false) {
        void Add(string? type, string? asm, string? node, bool derived, string where) =>
            mf.RewriteTargets.Add(new(type, asm, node, derived, $"{what} {where}  <-  {mf.Name}", ifRewrites));
        switch (t.Tag) {
            case Tag.Null:
                return;  // rewrites nothing (Harmony reports an error)
            case Tag.Type or Tag.Member when t.Text != null && (t.Number & Slot.Moved) == 0:
                Add(t.Text, t.Asm, null, (t.Number & Slot.OrDerived) != 0, $"is a member of {t.Text}");
                return;
            case Tag.Node when t.Text != null:
                Add(null, null, NodeSource(t), false, $"comes from {Nodes.Describe(NodeSource(t))}");
                return;
            case Tag.Element or Tag.Collection: {
                if (StateOf(t) is not { } state) return;  // first pass: nothing is recorded
                if (state.Tainted != null || (state.Escaped != null && !state.Lookup)) break;
                foreach (var h in state.Held)
                    Add(h.Type, h.Assembly, null, h.Bounded || state.Escaped != null, $"is a member of {h.Type} (from an array or list)");
                if (state.Node != null) Add(null, null, state.Node, false, $"comes from an array or list holding members of the types of {Nodes.Describe(state.Node)}");
                return;
            }
            case Tag.Object when t.Number == 1 && t.Asm == assembly.Name && t.Text != null && assembly.IteratorElementField(t.Text) is { } current:
                Add(null, null, Nodes.Field(current), false, "comes from an iterator (yield return)");
                return;
        }
        Add(null, null, null, false, "is not traced to a member");
    }

    // Harmony's manual patching: Patch with a transpiler rewrites the original; a reverse patch rewrites
    // its copy with the transpiler it is given, or one its stand-in carries (counted when the mod
    // rewrites code); a transpiler added to a PatchProcessor rewrites an original the check does not
    // link to it.
    void ManualRewrite(string name, ImmutableArray<string> ps, Slot[] args, int self) {
        int original = ps.IndexOf("System.Reflection.MethodBase");
        switch (name) {
            case "HarmonyLib.Harmony::Patch" when original >= 0:
                // Patch(original, prefix, postfix, transpiler, finalizer, ...)
                if (original + 3 < ps.Length && args[original + 3 + self].Tag != Tag.Null)
                    RewriteTarget(args[original + self], "the original Harmony.Patch gives a transpiler");
                break;
            case "HarmonyLib.PatchProcessor::AddTranspiler":
                if (args.Length > 1 && args[1].Tag != Tag.Null)
                    RewriteTarget(Slot.Unknown, "the original of a PatchProcessor a transpiler is added to");
                break;
            case "HarmonyLib.Harmony::ReversePatch" or "HarmonyLib.Harmony::CreateReversePatcher" or "HarmonyLib.ReversePatcher::.ctor" when original >= 0:
                bool given = false;
                for (int i = original + 2; i < ps.Length; i++) given |= ps[i] == "System.Reflection.MethodInfo" && args[i + self].Tag != Tag.Null;
                RewriteTarget(args[original + self], "the original a reverse patch copies", ifRewrites: !given);
                break;
        }
    }

    // What a TargetMethods returns: every element must be traced. An array or list the method
    // built from traced members; the methods an iterator (yield return) gives, which are the values
    // of its Current field (see AssemblyWalker.IteratorElementField); nothing else is followed.
    void PatchTargets(Slot t) {
        switch (t.Tag) {
            case Tag.Null:
                break;  // patches nothing (Harmony reports an error)
            case Tag.Collection:
                Expose(t);
                ElementTarget(t, $"Harmony patch targets returned by {mf.Name} come from an array or list", false);
                break;
            case Tag.Object when t.Number == 1 && t.Asm == assembly.Name && t.Text != null && assembly.IteratorElementField(t.Text) is { } current:
                mf.FieldReflection.Add(new(Nodes.Field(current), $"Harmony patch targets returned by {mf.Name} (yield return)", true));
                break;
            default:
                mf.UnresolvedReflection.Add($"Harmony patch targets returned by {mf.Name} are not traced to a name");
                break;
        }
    }

    // A lookup's result from its receiver: a member (or nested type) of a resolved type, of the
    // types a node holds, or of the types a collection's element is.
    Slot Derived(Slot receiver, Tag tag) => receiver.Tag switch {
        Tag.Type or Tag.Member when receiver.Text != null && (receiver.Number & Slot.Moved) == 0
            => new(tag, receiver.Text, receiver.Number & Slot.OrDerived, Asm: receiver.Asm),
        Tag.Node when tag == Tag.Member => receiver with { Number = 1, Store = -1 },
        Tag.Element when receiver.Number < 0 => new(Tag.Element, Number: assembly.Union(HeldOf(receiver)!.Select(h => h with { Member = h.Member || tag == Tag.Member }))),
        Tag.Element when tag == Tag.Member => receiver with { Text = "member", Store = -1 },
        Tag.Node or Tag.Element => receiver with { Store = -1 },
        _ => Slot.Unknown,
    };

    // A node slot as a source id: the node, or the members of the types it holds.
    static string NodeSource(Slot s) => s.Number == 1 ? Nodes.MemberOf(s.Text!) : s.Text!;

    // Applies reflection semantics to a call and returns the tag of its result.
    Slot Reflect(EntityHandle h, string name, MethodSignature<string> sig, Slot[] args, int self) {
        Slot Arg(int i) => i >= 0 && i < args.Length ? args[i] : Slot.Unknown;
        string method = name[(name.IndexOf("::", StringComparison.Ordinal) + 2)..];

        if (ReflectionApis.IsComActivation(name)) {
            mf.ComActivation.Add($"{name}  <-  {mf.Name}");
            return Slot.Unknown;
        }

        // type by name: a constant name resolves; anything else cannot be accounted for
        int ti = ReflectionApis.TypeNameArgument(name, sig, out bool member);
        if (ti >= 0) {
            var t = Arg(ti);
            var (typePart, qualifier) = AssemblyWalker.SplitTypeName((t.Text ?? "").Trim());
            if (t.Tag == Tag.String && Policy.NormalizeTypeName(typePart) is { Length: > 0 } type) {
                // (string assemblyName, string typeName): the assembly is named by the argument before.
                if (ti > 0 && ReflectionApis.TakesAssemblyName(name)) {
                    var an = Arg(ti - 1);
                    qualifier = an.Tag == Tag.String && an.Text is { } at ? AssemblyWalker.SplitTypeName("x, " + at).Assembly ?? "" : "";
                }
                // Type.GetType without an assembly qualifier looks in the calling assembly, then in
                // the core library; Assembly.GetType in the assembly it is called on, when that is
                // known (typeof(X).Assembly). Other lookups by name search assemblies the check cannot name.
                if (qualifier == null && name is "System.Type::GetType" or "System.Type::ReflectionOnlyGetType")
                    qualifier = assembly.DefinesType(type) ? assembly.Name : "System.Private.CoreLib";
                else if (qualifier == null && name is "System.Reflection.Assembly::GetType" or "System.Reflection.Assembly::CreateInstance" && Arg(0).Tag == Tag.Assembly)
                    qualifier = Arg(0).Asm;
                foreach (var cap in policy.CapsOfType(type)) Note(cap, $"{t.Text}  ({method}, resolved)  <-  {mf.Name}", Origin.Reflection);
                // A "Type:Member" string reaches that member. A type alone reaches no member yet: its
                // members are reached where they are looked up, as for a typeof; where the type lives
                // still matters (a type of code that was not analyzed).
                int colon = typePart.LastIndexOf(':');
                IReadOnlyList<string>? members = member && colon > 0 ? ReflectionApis.MemberNames(method, typePart[(colon + 1)..].Trim()) : [];
                AddReflected(new(type, qualifier, members, $"{t.Text}  ({method}, resolved)  <-  {mf.Name}"));
                return new(member ? Tag.Member : Tag.Type, type, Asm: qualifier);
            }
            // A name built at run time in an assembly whose name is known (typeof(X).Assembly) finds
            // one of that assembly's types: bounded to it.
            if (name is "System.Reflection.Assembly::GetType" && Arg(0) is { Tag: Tag.Assembly, Asm: { Length: > 0 } inAsm }) {
                mf.BoundedReflection.Add(new("*", inAsm, $"{name}(runtime value) in {inAsm}  <-  {mf.Name}"));
                return new(Tag.Type, "*", Slot.OrDerived, Asm: inAsm);
            }
            mf.UnresolvedReflection.Add($"{name}(runtime value)  <-  {mf.Name}");
            return Slot.Unknown;
        }
        // The run-time type of an object of a declared class or struct: that type, or (unless the
        // object is known to be exactly of it) any type derived from it.
        if (name is "System.Object::GetType" or "System.Exception::GetType" && Arg(0) is { Tag: Tag.Object, Text: { } declared } o)
            return new(Tag.Type, declared, o.Number == 1 ? 0 : Slot.OrDerived, Asm: o.Asm);

        // Calls that run, create, read or write a member or type: each target must be traced.
        bool fieldTarget = false;
        if (ReflectionApis.SinkOf(name, sig, self) is { } sink) {
            if (sink.Untraceable) mf.UnresolvedReflection.Add($"{name} (member found by name on an object's run-time type)  <-  {mf.Name}");
            foreach (var i in sink.Targets) {
                Target(Arg(i), name, sink.WritesFields);
                fieldTarget |= i == 0 && Arg(i).Tag is Tag.Node or Tag.Element;
            }
            // (A by-name Expression factory is untraceable: its tree is code generation, like Emit.)
            if (sink.WritesFields && sink.Targets.Length == 0 && name.StartsWith("HarmonyLib.", StringComparison.Ordinal)) {
                // Harmony's FieldRefAccess<T, F>(name): the type is the first type argument.
                var targs = assembly.MethodTypeArguments(h);
                mf.ReflectionFieldWrites.Add(targs.Length > 0 && !targs[0].StartsWith('!') ? targs[0] : "*");
            }
        }

        // Member access or instantiation on a resolved type grants that type's capabilities. A
        // lookup on an unresolved type is not a finding by itself (Harmony targets methods this
        // way); running, creating, reading or writing what it finds is, above.
        if (ReflectionApis.UsesTypeArgument(name)) {
            var t = Arg(0);
            var memberName = ReflectionApis.MemberNameArgument(name) is int mi && Arg(mi) is { Tag: Tag.String, Text: { } mn } ? mn : null;
            var members = ReflectionApis.MemberNames(method, memberName);
            // A plural lookup whose elements are only ever taken by a filter that requires a constant
            // name reaches the members of those names (none when no element is taken).
            if (members == null && ReflectionApis.IsPluralLookup(name) && StateOf(offset) is { OnlyNamed: { } only, Escaped: null }
                && ReflectionApis.SingularLookup(method) is { } single)
                members = [.. only.SelectMany(n => ReflectionApis.MemberNames(single, n) ?? [n]).Distinct()];
            // A member named by one of this method's string parameters: by what every call passes.
            var nameNode = memberName == null && ReflectionApis.MemberNameArgument(name) is int ni ? NameParameter(Arg(ni)) : null;
            if (t.Tag == Tag.Type && t.Text != null && t.Text != "*") {
                foreach (var cap in policy.CapsOfType(t.Text)) Note(cap, $"{t.Text}  ({method})  <-  {mf.Name}", Origin.Reflection);
                // Where the type lives decides the rest (game, trusted library, ...); a member looked
                // up by a constant name narrows it to that member. A type known only up to its
                // derived types counts as that type (the finding is where its member is used).
                AddReflected(new(t.Text, t.Asm, members, $"{t.Text}{(members != null ? "::" + string.Join("/", members) : "")}  ({method})  <-  {mf.Name}",
                    NameNode: nameNode, Lookup: method));
            } else if (t.Tag == Tag.Node && t.Text != null && !fieldTarget) {
                mf.FieldReflection.Add(new(NodeSource(t), $"{name} on the value of {Nodes.Describe(NodeSource(t))}  <-  {mf.Name}", false, Members: members, NameNode: nameNode, Lookup: method));
            } else if (t.Tag == Tag.Element && !fieldTarget && StateOf(t) is { } state) {
                // A lookup on a type taken from a collection: each type it holds.
                foreach (var held in state.Held.Where(x => !x.Member && x.Type != "*"))
                    AddReflected(new(held.Type, held.Assembly, members, $"{held.Type}{(members != null ? "::" + string.Join("/", members) : "")}  ({method}, from an array or list)  <-  {mf.Name}"));
                if (state.Node != null)
                    mf.FieldReflection.Add(new(state.Node, $"{name} on an element of an array or list holding members of the types of {Nodes.Describe(state.Node)}  <-  {mf.Name}", false, Members: members));
            }
        }
        // A type named as a type argument (Activator.CreateInstance<T>(), AccessTools.CreateInstance<T>(),
        // Traverse.Create<T>()) is reached like a typeof. A generic parameter is the caller's choice:
        // new T() in generic code is not followed (see README, Known gaps).
        if (ReflectionApis.TypeArgumentTarget(name, sig) is { } targetMembers)
            foreach (var (targ, tasm) in assembly.MethodTypeArgumentTypes(h)) {
                if (targ.StartsWith('!')) continue;
                foreach (var cap in policy.CapsOfType(targ)) Note(cap, $"{targ}  ({method}<T>)  <-  {mf.Name}", Origin.Reflection);
                AddReflected(new(targ, tasm, targetMembers.Length == 0 ? null : targetMembers, $"{targ}  ({method}<T>)  <-  {mf.Name}"));
            }
        // RunClassConstructor runs the type initializer of the type it is given.
        if (name == "System.Runtime.CompilerServices.RuntimeHelpers::RunClassConstructor" && Arg(0) is { Tag: Tag.Type, Text: { } cctorType } rc)
            AddReflected(new(cctorType, rc.Asm, [".cctor"], $"{cctorType}  ({method})  <-  {mf.Name}"));

        if (ReflectionApis.PassesTypeThrough(name)) return Traced(Arg(0)) ? Arg(0) with { Store = -1 } : Slot.Unknown;
        // The assembly of a resolved type (not one known only up to its derived types, which can live
        // elsewhere), or this one.
        if (name is "System.Type::get_Assembly" or "System.Reflection.TypeInfo::get_Assembly" && Arg(0) is { Tag: Tag.Type } owner)
            return new(Tag.Assembly, Asm: (owner.Number & Slot.OrDerived) == 0 ? owner.Asm ?? "" : "");
        if (name == "System.Reflection.Assembly::GetExecutingAssembly") return new(Tag.Assembly, Asm: assembly.Name);
        switch (ReflectionApis.Lookup(name, sig)) {
            case LookupResult.Member: return Derived(Arg(0), Tag.Member);
            case LookupResult.NestedType: return Derived(Arg(0), Tag.Type);
            case LookupResult.Members: return Plural(Arg(0), true);
            case LookupResult.NestedTypes: return Plural(Arg(0), false);
        }
        return Traverse(h, name, sig, args) ?? Slot.Unknown;
    }

    // An array or list of members (or nested types) of the receiver's type, made by a lookup (see
    // NewCollection): its elements are members of the types the receiver is, or holds.
    Slot Plural(Slot receiver, bool members) {
        switch (receiver.Tag) {
            case Tag.Type or Tag.Member when receiver.Text != null && (receiver.Number & Slot.Moved) == 0:
                return NewCollection(c => { c.Held.Add(new(receiver.Text, receiver.Asm, members, (receiver.Number & Slot.OrDerived) != 0)); c.Lookup = true; });
            case Tag.Node when receiver.Text != null:
                return NewCollection(c => { c.Node = members ? Nodes.MemberOf(NodeSource(receiver)) : NodeSource(receiver); c.Lookup = true; });
            case Tag.Element when receiver.Number < 0:
                return NewCollection(c => { c.Held.UnionWith(HeldOf(receiver)!.Select(h => h with { Member = members })); c.Lookup = true; });
            case Tag.Element:
                return NewCollection(c => { c.Includes.Add((receiver.Number, members || receiver.Text == "member")); c.Lookup = true; });
        }
        return Slot.Unknown;  // on a type the walker does not know: its members are not traced
    }

    // Harmony's Traverse steps through members by name from a type or an object. Starting from
    // an object (Create(object)) means its run-time type, which is not traced.
    Slot? Traverse(EntityHandle h, string name, MethodSignature<string> sig, Slot[] args) {
        var a0 = args.Length > 0 ? args[0] : Slot.Unknown;
        switch (name) {
            case "HarmonyLib.Traverse::Create" or "HarmonyLib.Traverse::.ctor": {
                var ps = sig.ParameterTypes;
                if (ps.Length == 1 && ps[0] == "System.Type")
                    return a0.Tag == Tag.Type && a0.Text != null ? new(Tag.Member, a0.Text, a0.Number & Slot.OrDerived, Asm: a0.Asm) : Slot.Unknown;
                var targs = assembly.MethodTypeArgumentTypes(h);  // Create<T>(), reached in Reflect
                return ps.Length == 0 && targs.Count == 1 && !targs[0].Name.StartsWith('!') ? new(Tag.Member, targs[0].Name, Asm: targs[0].Assembly) : Slot.Unknown;
            }
            case "HarmonyLib.Traverse::Method":
                return a0.Tag == Tag.Member && (a0.Number & Slot.Moved) == 0 ? a0 with { Store = -1 } : Slot.Unknown;
            case "HarmonyLib.Traverse::Field" or "HarmonyLib.Traverse::Property":
                return a0.Tag == Tag.Member && (a0.Number & Slot.Moved) == 0 ? a0 with { Number = a0.Number | Slot.Moved, Store = -1 } : Slot.Unknown;
            case "HarmonyLib.Traverse`1::.ctor":
                return a0.Tag == Tag.Member ? a0 with { Store = -1 } : Slot.Unknown;
        }
        return null;
    }
}
