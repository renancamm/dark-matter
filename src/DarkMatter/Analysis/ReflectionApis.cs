// SPDX-License-Identifier: MIT
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Text.RegularExpressions;

namespace DarkMatter.Analysis;

/// <summary>
/// A reflection call that runs, creates, reads or writes the member or type it is given. Each
/// argument in <see cref="Targets"/> must be traced to a name, or the call is unresolved.
/// </summary>
/// <param name="Targets">Argument indices (counting <c>this</c>) that hold the member or type acted on.</param>
/// <param name="Untraceable">The call finds its member by name on an object's run-time type, which is never traceable.</param>
/// <param name="WritesFields">The call writes fields of the target's type (FieldInfo.SetValue, Harmony field references).</param>
internal sealed record Sink(int[] Targets, bool Untraceable = false, bool WritesFields = false);

/// <summary>What a member lookup returns, given the type or member it is called on.</summary>
internal enum LookupResult {
    /// <summary>Not a lookup the walker follows: the result is unknown.</summary>
    None,
    /// <summary>One member of the receiver's type (GetMethod, AccessTools.Field, PropertyInfo.GetGetMethod, ...).</summary>
    Member,
    /// <summary>A type nested in the receiver's type, counted as the receiver's type.</summary>
    NestedType,
    /// <summary>An array or list of members of the receiver's type (GetMethods, GetProperties, AccessTools.GetDeclaredFields, ...).</summary>
    Members,
    /// <summary>An array of types nested in the receiver's type (GetNestedTypes), counted as the receiver's type.</summary>
    NestedTypes,
}

/// <summary>The reflection APIs the walker models, by "Namespace.Type::Member" name.</summary>
internal static partial class ReflectionApis {
    [GeneratedRegex(@"^System\.(Type|Reflection\.TypeInfo)::(Get(Methods?|Fields?|Property|Properties|Members?|Constructors?|Events?|NestedTypes?)|InvokeMember|GetDeclared\w+|get_Declared\w+)$|^System\.Reflection\.RuntimeReflectionExtensions::GetRuntime\w+$")]
    private static partial Regex MemberLookup();

    // Lookups that return a single member of the receiver's type. Plural forms (GetMethods,
    // GetMember, DeclaredMethods) return arrays, which can be changed after the lookup; they are
    // not followed, so a member taken out of one is untraced.
    [GeneratedRegex(@"^System\.(Type|Reflection\.TypeInfo)::(GetMethod|GetField|GetProperty|GetConstructor|GetEvent|GetDeclaredMethod|GetDeclaredField|GetDeclaredProperty|GetDeclaredEvent)$|^System\.Reflection\.RuntimeReflectionExtensions::GetRuntime(Method|Field|Property|Event)$|^System\.Reflection\.PropertyInfo::(GetGetMethod|GetSetMethod|get_GetMethod|get_SetMethod)$|^System\.Reflection\.EventInfo::(GetAddMethod|GetRemoveMethod|GetRaiseMethod|get_AddMethod|get_RemoveMethod|get_RaiseMethod)$|^System\.Reflection\.MethodInfo::(MakeGenericMethod|GetGenericMethodDefinition)$")]
    private static partial Regex SingleLookup();

    // Lookups that return an array or a list of members of the receiver's type. What the walker knows
    // about each element (a member of that type, name unknown) holds as long as nothing it cannot
    // follow can change the array (see MethodWalker's collections).
    [GeneratedRegex(@"^System\.(Type|Reflection\.TypeInfo)::(GetMethods|GetFields|GetProperties|GetMembers|GetMember|GetEvents|GetConstructors|get_DeclaredMethods|get_DeclaredFields|get_DeclaredProperties|get_DeclaredMembers|get_DeclaredEvents|get_DeclaredConstructors|GetDeclaredMethods)$|^System\.Reflection\.RuntimeReflectionExtensions::GetRuntime(Methods|Fields|Properties|Events)$|^HarmonyLib\.AccessTools::(GetDeclaredMethods|GetDeclaredFields|GetDeclaredProperties|GetDeclaredConstructors)$")]
    private static partial Regex PluralLookup();

    // Instance members of reflection objects that run, read or write the member they are called on.
    [GeneratedRegex(@"^System\.Reflection\.\w+::(Invoke|GetValue|SetValue|GetValueDirect|SetValueDirect|CreateDelegate|AddEventHandler|RemoveEventHandler)$")]
    private static partial Regex MemberSink();

    static readonly HashSet<string> AccessToolsSingle = [
        "Method", "DeclaredMethod", "Field", "DeclaredField", "Property", "DeclaredProperty", "PropertyGetter", "PropertySetter",
        "DeclaredPropertyGetter", "DeclaredPropertySetter", "Constructor", "DeclaredConstructor", "Indexer", "DeclaredIndexer",
        "IndexerGetter", "IndexerSetter", "DeclaredIndexerGetter", "DeclaredIndexerSetter", "FirstMethod", "FirstConstructor", "FirstProperty",
    ];
    // AccessTools members that take "Namespace.Type:Member" as their first argument when it is a string.
    static readonly HashSet<string> AccessToolsByName = [
        "Method", "DeclaredMethod", "Field", "DeclaredField", "Property", "DeclaredProperty", "PropertyGetter", "PropertySetter",
        "DeclaredPropertyGetter", "DeclaredPropertySetter", "MethodDelegate",
    ];
    // MakeDeepCopy creates an instance of its result type and writes its fields; GetDefaultValue
    // creates an instance of a value type (running its parameterless constructor).
    static readonly HashSet<string> AccessToolsSinks = [
        "CreateInstance", "FieldRefAccess", "StaticFieldRefAccess", "StructFieldRefAccess", "MethodDelegate", "MakeDeepCopy", "GetDefaultValue",
    ];
    // Harmony members that run the method they are given (patch methods; reverse patches, which
    // copy the original) or replace its code (the patched original). A patched original that is
    // not traced may be any method, framework ones included, so it is a sink like the attribute
    // and TargetMethod forms of the same patch.
    static readonly HashSet<string> HarmonySinks = [
        "HarmonyLib.HarmonyMethod::.ctor", "HarmonyLib.PatchProcessor::AddPrefix", "HarmonyLib.PatchProcessor::AddPostfix",
        "HarmonyLib.PatchProcessor::AddTranspiler", "HarmonyLib.PatchProcessor::AddFinalizer", "HarmonyLib.PatchProcessor::AddInfix",
        "HarmonyLib.Harmony::CreateReversePatcher", "HarmonyLib.Harmony::ReversePatch", "HarmonyLib.ReversePatcher::.ctor",
        "HarmonyLib.MethodInvoker::GetHandler", "HarmonyLib.Harmony::Patch", "HarmonyLib.Harmony::CreateProcessor",
        "HarmonyLib.PatchProcessor::.ctor",
    ];

    /// <summary>The type and member reference types whose values the walker traces (also through fields).</summary>
    // Matched by signature name, not gated on the framework (G4): this only decides which fields,
    // parameters, returns and locals the walker traces. A type of the same name defined elsewhere is traced
    // the same way, and whatever it holds that is not a resolved type or member makes the node untraced;
    // the calls that act on a traced value are modelled only for the framework's members (see
    // AssemblyWalker.Models). So a same-named type adds tracing and cannot lower a result.
    public static bool IsReflectionType(string typeName) => typeName is "System.Type" or "System.Reflection.TypeInfo"
        or "System.Reflection.MemberInfo" or "System.Reflection.MethodBase" or "System.Reflection.MethodInfo"
        or "System.Reflection.ConstructorInfo" or "System.Reflection.FieldInfo" or "System.Reflection.PropertyInfo"
        or "System.Reflection.EventInfo" or "System.Reflection.MethodInvoker" or "System.Reflection.ConstructorInvoker";

    /// <summary>An array of Type or member values (a field of this type is traced like a Type or member field, see MethodWalker).</summary>
    public static bool IsReflectionArray(string typeName) => typeName.EndsWith("[]", StringComparison.Ordinal) && IsReflectionType(typeName[..^2]);

    /// <summary>typeof(X), TypeInfo, handles and invokers: the result is the argument's type or member.</summary>
    public static bool PassesTypeThrough(string name) =>
        name is "System.Type::GetTypeFromHandle" or "System.Reflection.IntrospectionExtensions::GetTypeInfo"
            or "System.Reflection.TypeInfo::AsType" or "System.Type::get_TypeHandle" or "System.Type::get_UnderlyingSystemType"
            or "System.Reflection.MethodBase::GetMethodFromHandle" or "System.Reflection.FieldInfo::GetFieldFromHandle"
            or "System.Reflection.MethodInvoker::Create" or "System.Reflection.ConstructorInvoker::Create";

    /// <summary>COM activation reaches an arbitrary, usually native, component by GUID or ProgID.</summary>
    public static bool IsComActivation(string name) =>
        name is "System.Type::GetTypeFromCLSID" or "System.Type::GetTypeFromProgID";

    /// <summary>
    /// Member lookup or instantiation on a Type passed as the first argument (or receiver):
    /// reaching any member of a resolved type grants that type's capabilities.
    /// </summary>
    public static bool UsesTypeArgument(string name) =>
        MemberLookup().IsMatch(name)
        || name.StartsWith("HarmonyLib.AccessTools::", StringComparison.Ordinal)
        || name is "System.Activator::CreateInstance" or "System.Runtime.CompilerServices.RuntimeHelpers::GetUninitializedObject"
            or "HarmonyLib.Traverse::Create" or "HarmonyLib.Traverse::.ctor";

    /// <summary>Lookups that return an array or a list of members or nested types (see <see cref="Lookup"/>).</summary>
    public static bool IsPluralLookup(string name) => PluralLookup().IsMatch(name)
        || name is "System.Type::GetNestedTypes" or "System.Reflection.TypeInfo::get_DeclaredNestedTypes" or "HarmonyLib.AccessTools::InnerTypes";

    /// <summary>What a call returns when its first argument (or receiver) is a traced type or member.</summary>
    public static LookupResult Lookup(string name, MethodSignature<string> sig) {
        if (SingleLookup().IsMatch(name)) return LookupResult.Member;
        if (name is "System.Type::GetNestedType" or "System.Reflection.TypeInfo::GetDeclaredNestedType") return LookupResult.NestedType;
        if (PluralLookup().IsMatch(name)) return LookupResult.Members;
        if (name is "System.Type::GetNestedTypes" or "System.Reflection.TypeInfo::get_DeclaredNestedTypes" or "HarmonyLib.AccessTools::InnerTypes") return LookupResult.NestedTypes;
        if (Member(name, "HarmonyLib.AccessTools::") is { } at && sig.ParameterTypes.Length > 0 && sig.ParameterTypes[0] == "System.Type") {
            if (AccessToolsSingle.Contains(at)) return LookupResult.Member;
            if (at is "Inner" or "FirstInner") return LookupResult.NestedType;
        }
        return LookupResult.None;
    }

    /// <summary>
    /// The reflection call's sink description, or null if it only looks things up.
    /// <paramref name="self"/> is 1 when the arguments include <c>this</c> (an instance call, not newobj).
    /// </summary>
    public static Sink? SinkOf(string name, MethodSignature<string> sig, int self) {
        var ps = sig.ParameterTypes;
        if (self == 1 && MemberSink().IsMatch(name)) return new([0], WritesFields: name.EndsWith("::SetValue", StringComparison.Ordinal) || name.EndsWith("::SetValueDirect", StringComparison.Ordinal));
        switch (name) {
            case "System.Type::InvokeMember":
            case "System.Reflection.TypeInfo::InvokeMember":
                return new([0]);
            case "System.Delegate::CreateDelegate": {
                // (Type, MethodInfo, ...), (Type, object, MethodInfo, ...): the MethodInfo.
                // (Type, Type target, string method, ...): the target type.
                // (Type, object target, string method, ...): a name on the object's run-time type.
                int mi = ps.IndexOf("System.Reflection.MethodInfo");
                if (mi >= 0) return new([mi + self]);
                if (ps.Length > 1 && ps[1] == "System.Type") return new([1 + self]);
                return new([], Untraceable: true);
            }
            case "System.Activator::CreateInstance":
                return ps.Length > 0 && ps[0] == "System.Type" ? new([self]) : null;  // CreateInstance<T>() names its type in the IL
            case "System.Runtime.CompilerServices.RuntimeHelpers::GetUninitializedObject":
            case "System.Runtime.Serialization.FormatterServices::GetUninitializedObject":
            case "System.Runtime.Serialization.FormatterServices::GetSafeUninitializedObject":
            case "System.Runtime.CompilerServices.RuntimeHelpers::RunClassConstructor":
            case "System.Runtime.CompilerServices.RuntimeHelpers::RunModuleConstructor":
            case "System.Reflection.MethodInvoker::Create":
            case "System.Reflection.ConstructorInvoker::Create":
                return new([self]);
            case "HarmonyLib.Traverse::GetValue":
            case "HarmonyLib.Traverse`1::get_Value":
                return new([0]);
            case "HarmonyLib.Traverse::SetValue":
            case "HarmonyLib.Traverse`1::set_Value":
                return new([0], WritesFields: true);
        }
        if (Member(name, "HarmonyLib.AccessTools::") is { } at && AccessToolsSinks.Contains(at)) {
            if (at == "MethodDelegate" && ps.Length > 0 && ps[0] == "System.String") return null;  // by name: TypeNameArgument
            return new(ReflectionArguments(ps, self), WritesFields: at.EndsWith("FieldRefAccess", StringComparison.Ordinal) || at == "MakeDeepCopy");
        }
        // Expression factories build code from the members they are given (Call, Field, New, ...):
        // a tree that is compiled runs them. A member found by name on an expression's type (not a
        // System.Type) is found on a run-time type the check does not follow. Field access can be
        // assigned to.
        if (name.StartsWith("System.Linq.Expressions.Expression::", StringComparison.Ordinal) && self == 0) {
            string method = name[(name.IndexOf("::", StringComparison.Ordinal) + 2)..];
            var targets = Enumerable.Range(0, ps.Length).Where(i => IsReflectionType(ps[i])
                && (ps[i] != "System.Type" || ExpressionTypeMembers(name, ps, i) is not { Count: 0 })).ToArray();
            bool byName = method is "Call" or "Field" or "Property" or "PropertyOrField"
                && ps.Length > 1 && ps[1] == "System.String" && ps[0] != "System.Type";
            bool writes = method is "Field" or "MakeMemberAccess" or "Bind" or "MemberBind" or "ListBind";
            return targets.Length > 0 || byName ? new(targets, Untraceable: byName, WritesFields: writes) : null;
        }
        if (HarmonySinks.Contains(name)) {
            // A reverse patch runs the original's code: the original must be traced too.
            var targets = ReflectionArguments(ps, self);
            return targets.Length > 0 ? new(targets) : null;
        }
        return null;
    }

    /// <summary>Whether a type is one of System.Linq.Expressions' expression classes (or an array or sequence of them).</summary>
    public static bool IsExpressionType(string typeName) => typeName.StartsWith("System.Linq.Expressions.", StringComparison.Ordinal)
        || typeName is "System.Collections.Generic.IEnumerable`1" or "System.Collections.ObjectModel.ReadOnlyCollection`1";

    /// <summary>
    /// Expression factories whose result can be compiled without running anything the tree does not
    /// name: parameters and constants, conversions (user-defined operators of the target type are
    /// reached, see <see cref="ExpressionTypeMembers"/>), calls, member access and constructors through
    /// a MethodInfo, FieldInfo, PropertyInfo, MemberInfo or ConstructorInfo, assignment, blocks and
    /// lambdas. Operators (which find methods on the operand types), dynamic expressions (which bind by
    /// name at run time) and every other factory are not listed: a tree that uses them is code generation.
    /// </summary>
    public static bool IsCleanExpressionFactory(string name) => name is "System.Linq.Expressions.Expression::Parameter"
        or "System.Linq.Expressions.Expression::Variable" or "System.Linq.Expressions.Expression::Constant"
        or "System.Linq.Expressions.Expression::Default" or "System.Linq.Expressions.Expression::Convert"
        or "System.Linq.Expressions.Expression::TypeAs" or "System.Linq.Expressions.Expression::Unbox"
        or "System.Linq.Expressions.Expression::Call" or "System.Linq.Expressions.Expression::Field"
        or "System.Linq.Expressions.Expression::Property" or "System.Linq.Expressions.Expression::MakeMemberAccess"
        or "System.Linq.Expressions.Expression::New" or "System.Linq.Expressions.Expression::Assign"
        or "System.Linq.Expressions.Expression::Block" or "System.Linq.Expressions.Expression::Lambda";

    /// <summary>
    /// For an Expression factory's System.Type argument: the members of that type the compiled tree
    /// can run (New: its constructor; Convert: its conversion operators), [] when it only names the
    /// type, or null when the factory finds a member of it by the name in the next argument.
    /// </summary>
    public static IReadOnlyList<string>? ExpressionTypeMembers(string name, IReadOnlyList<string> ps, int i) {
        string method = name[(name.IndexOf("::", StringComparison.Ordinal) + 2)..];
        if (i + 1 < ps.Count && ps[i + 1] == "System.String" && method is "Call" or "Field" or "Property" or "PropertyOrField") return null;
        return method switch {
            "New" => [".ctor"],
            "Convert" or "ConvertChecked" => ["op_Implicit", "op_Explicit"],
            _ => [],
        };
    }

    // Indices of arguments whose declared type is a Type or a member.
    static int[] ReflectionArguments(IReadOnlyList<string> ps, int self) =>
        [.. Enumerable.Range(0, ps.Count).Where(i => IsReflectionType(ps[i])).Select(i => i + self)];

    static string? Member(string name, string typePrefix) =>
        name.StartsWith(typePrefix, StringComparison.Ordinal) ? name[typePrefix.Length..] : null;

    /// <summary>Calls that take an assembly name and a type name: (string assemblyName, string typeName, ...).</summary>
    public static bool TakesAssemblyName(string name) =>
        name is "System.Activator::CreateInstance" or "System.AppDomain::CreateInstance" or "System.AppDomain::CreateInstanceAndUnwrap";

    /// <summary>Lookups by type name (<see cref="TypeNameArgument"/>) that also create an object of the type: they run a constructor.</summary>
    public static bool CreatesByName(string name) => TakesAssemblyName(name) || name == "System.Reflection.Assembly::CreateInstance";

    /// <summary>
    /// Index of the member-name argument of a lookup on a Type (System.Type::GetMethod(name, ...),
    /// AccessTools.Field(type, name), ...), counting <c>this</c>, or null if the call takes none.
    /// </summary>
    public static int? MemberNameArgument(string name) =>
        MemberLookup().IsMatch(name) || name.StartsWith("HarmonyLib.AccessTools::", StringComparison.Ordinal) ? 1 : null;

    /// <summary>
    /// The members a reflection call named <paramref name="method"/> reaches when it names the member
    /// <paramref name="member"/> (null when the name is not a constant): the method, the field, a
    /// property's or an event's accessors, or the constructor. A field whose name is not known
    /// reaches the type's initializer (".cctor") and no other code; a nested type, nothing yet (an
    /// empty list: where the type lives still matters). Null means any member of the type. GetMember
    /// also finds a nested type of that name, which the walker holds as a member: every member of it is
    /// reached, written "/Name" (see <see cref="NestedPrefix"/>).
    /// </summary>
    public static IReadOnlyList<string>? MemberNames(string method, string? member) {
        switch (method) {
            case "GetNestedType" or "GetNestedTypes" or "GetDeclaredNestedType" or "get_DeclaredNestedTypes" or "Inner" or "FirstInner" or "InnerTypes":
                return [];
            case "GetFields" or "get_DeclaredFields" or "GetRuntimeFields" or "GetDeclaredFields" or "GetFieldNames":
            case "GetField" or "GetDeclaredField" or "GetRuntimeField" or "Field" or "DeclaredField" or "FieldRefAccess"
                or "StaticFieldRefAccess" or "StructFieldRefAccess" when member == null:
                return [".cctor"];
            case "GetConstructor" or "GetConstructors" or "get_DeclaredConstructors" or "Constructor" or "DeclaredConstructor" or "GetDeclaredConstructors"
                or "FirstConstructor" or "CreateInstance" or "GetUninitializedObject" or "GetDefaultValue":
                return [".ctor"];
            case "Indexer" or "DeclaredIndexer":
                return ["get_Item", "set_Item"];
            case "IndexerGetter" or "DeclaredIndexerGetter":
                return ["get_Item"];
            case "IndexerSetter" or "DeclaredIndexerSetter":
                return ["set_Item"];
        }
        if (member == null) return null;
        // InvokeMember with an empty name (or "[DISPID=...]") runs the type's default member
        // ([DefaultMember]), whatever it is called: any member (H7).
        if (method == "InvokeMember" && (member.Length == 0 || member.StartsWith('['))) return null;
        return method switch {
            "GetMethod" or "GetDeclaredMethod" or "GetRuntimeMethod" or "Method" or "DeclaredMethod" or "MethodDelegate"
                or "GetField" or "GetDeclaredField" or "GetRuntimeField" or "Field" or "DeclaredField" or "FieldRefAccess"
                or "StaticFieldRefAccess" or "StructFieldRefAccess" => [member],
            "GetProperty" or "GetDeclaredProperty" or "GetRuntimeProperty" or "Property" or "DeclaredProperty" => ["get_" + member, "set_" + member],
            "PropertyGetter" or "DeclaredPropertyGetter" => ["get_" + member],
            "PropertySetter" or "DeclaredPropertySetter" => ["set_" + member],
            "GetEvent" or "GetDeclaredEvent" or "GetRuntimeEvent" => ["add_" + member, "remove_" + member, "raise_" + member],
            "GetMember" => [member, "get_" + member, "set_" + member, "add_" + member, "remove_" + member, NestedPrefix + member],
            "InvokeMember" => [member, "get_" + member, "set_" + member],
            _ => null,
        };
    }

    /// <summary>
    /// The kind of member a single lookup by name returns (GetField, AccessTools.Field, ...: a field), for typing
    /// what is read through it (D5, D6); null for any other lookup (a getter or setter by a property's name, an
    /// indexer, a constructor, GetMember, which can return several kinds).
    /// </summary>
    public static MemberKind? LookupKind(string method) => method switch {
        "GetField" or "GetDeclaredField" or "GetRuntimeField" or "Field" or "DeclaredField" => MemberKind.Field,
        "GetProperty" or "GetDeclaredProperty" or "GetRuntimeProperty" or "Property" or "DeclaredProperty" => MemberKind.Property,
        "GetMethod" or "GetDeclaredMethod" or "GetRuntimeMethod" or "Method" or "DeclaredMethod" => MemberKind.Method,
        _ => null,
    };

    /// <summary>A reached "member" that stands for every member of the nested type named after it (see <see cref="MemberNames"/>).</summary>
    public const string NestedPrefix = "/";

    /// <summary>
    /// Whether a member (or nested type) named <paramref name="actual"/> is one a lookup by the name
    /// <paramref name="reached"/> (from <see cref="MemberNames"/>, without <see cref="NestedPrefix"/>) can
    /// find. Names compare ignoring case: <c>BindingFlags.IgnoreCase</c>, binding flags that are not a
    /// constant, the by-name Expression factories and <c>Delegate.CreateDelegate(..., ignoreCase)</c> all
    /// find a member under any spelling, and an exact lookup finds a subset of that (an over-approximation
    /// only for members whose names differ in case alone; H3). A name ending in '*' is a prefix (GetMember
    /// and InvokeMember look names up that way; for the other lookups a name with a '*' is hand-written IL,
    /// and the prefix covers it too).
    /// </summary>
    public static bool MemberMatches(string reached, string actual) =>
        reached.EndsWith('*') ? actual.StartsWith(reached[..^1], StringComparison.OrdinalIgnoreCase)
            : string.Equals(reached, actual, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Whether <paramref name="member"/> ("T::Name", "T/Nested::Name", ...) is reached by a lookup on
    /// <paramref name="type"/> that names <paramref name="reached"/> (see <see cref="MemberNames"/>): that
    /// member of the type, one of that name of a nested type (the walker counts a nested type as the type it
    /// was found from), or, for "/Name", any member of a nested type of that name (<see cref="MemberMatches"/>).
    /// </summary>
    public static bool ReachesMember(string type, string reached, string member) {
        if (!member.StartsWith(type, StringComparison.Ordinal) || member.Length <= type.Length) return false;
        var rest = member[type.Length..];
        if (reached.StartsWith(NestedPrefix, StringComparison.Ordinal)) {
            if (rest[0] != '/') return false;
            int end = rest.IndexOfAny(['/', ':'], 1);
            return end > 1 && MemberMatches(reached[NestedPrefix.Length..], rest[1..end]);
        }
        int sep = rest.LastIndexOf("::", StringComparison.Ordinal);
        if (sep < 0 || !(sep == 0 || rest[0] == '/')) return false;
        return MemberMatches(reached, rest[(sep + 2)..]);
    }

    /// <summary>
    /// Whether the nested type <paramref name="nested"/> ("T/Name") is one a lookup on <paramref name="type"/>
    /// for the reached "member" <paramref name="reached"/> ("/Name", see <see cref="NestedPrefix"/>) can find.
    /// </summary>
    public static bool ReachesNested(string type, string reached, string nested) =>
        reached.StartsWith(NestedPrefix, StringComparison.Ordinal) && nested.Length > type.Length + 1
            && nested.StartsWith(type + "/", StringComparison.Ordinal) && nested.IndexOf('/', type.Length + 1) < 0
            && MemberMatches(reached[NestedPrefix.Length..], nested[(type.Length + 1)..]);

    /// <summary>
    /// For a by-name Expression factory on a System.Type (Call(Type, string, Type[], params Expression[]),
    /// Field(Expression, Type, string), Property(Expression, Type, string)): the argument indices of the
    /// type and the name, and the single-member lookup it does (for <see cref="MemberNames"/>); null for
    /// any other call. The factories find the member ignoring case (see <see cref="MemberMatches"/>).
    /// </summary>
    public static (int Type, int Name, string Lookup)? ExpressionByName(string name, IReadOnlyList<string> ps) {
        if (!name.StartsWith("System.Linq.Expressions.Expression::", StringComparison.Ordinal)) return null;
        string method = name[(name.IndexOf("::", StringComparison.Ordinal) + 2)..];
        string? lookup = method switch { "Call" => "GetMethod", "Field" => "GetField", "Property" => "GetProperty", "PropertyOrField" => "GetMember", _ => null };
        if (lookup == null) return null;
        for (int i = 0; i + 1 < ps.Count; i++)
            if (ps[i] == "System.Type" && ps[i + 1] == "System.String") return (i, i + 1, lookup);
        return null;
    }

    /// <summary>
    /// Arguments (counting <c>this</c>) of a lookup of a type by name (<see cref="TypeNameArgument"/>) that
    /// can make it find a type other than the one named exactly: the ignoreCase flag (unless it is the
    /// constant false), and the assembly and type resolvers of Type.GetType (unless they are null). A
    /// resolver is the mod's own code and can return any type.
    /// </summary>
    public static (int IgnoreCase, int[] Resolvers) TypeNameOptions(string name, MethodSignature<string> sig) {
        int self = sig.Header.IsInstance ? 1 : 0;
        var ps = sig.ParameterTypes;
        var bools = Enumerable.Range(0, ps.Length).Where(i => ps[i] == "System.Boolean").ToList();
        int ignoreCase = name switch {
            // (string, bool throwOnError, bool ignoreCase), (string, Func, Func, bool throwOnError, bool ignoreCase)
            "System.Type::GetType" or "System.Type::ReflectionOnlyGetType" or "System.Reflection.Assembly::GetType" => bools.Count >= 2 ? bools[1] : -1,
            // (string, bool ignoreCase), (string, bool throwOnError, bool ignoreCase)
            "System.Reflection.Module::GetType" => bools.Count >= 1 ? bools[^1] : -1,
            // (string, bool ignoreCase, ...), (string assemblyName, string typeName, bool ignoreCase, ...)
            "System.Reflection.Assembly::CreateInstance" or "System.Activator::CreateInstance" or "System.AppDomain::CreateInstance"
                or "System.AppDomain::CreateInstanceAndUnwrap" => bools.Count >= 1 ? bools[0] : -1,
            _ => -1,
        };
        int[] resolvers = name == "System.Type::GetType"
            ? [.. Enumerable.Range(0, ps.Length).Where(i => ps[i].StartsWith("System.Func`", StringComparison.Ordinal)).Select(i => i + self)]
            : [];
        return (ignoreCase < 0 ? -1 : ignoreCase + self, resolvers);
    }

    /// <summary>
    /// The single-member lookup whose member names (<see cref="MemberNames"/>) a plural lookup's element of
    /// a given name has: GetMethods -> GetMethod, GetProperties -> GetProperty, ...; null for lookups whose
    /// elements are not named members (fields reach no code but the type initializer, constructors are
    /// ".ctor", nested types are types).
    /// </summary>
    public static string? SingularLookup(string plural) => plural switch {
        "GetMethods" or "get_DeclaredMethods" or "GetDeclaredMethods" or "GetRuntimeMethods" => "GetMethod",
        "GetProperties" or "get_DeclaredProperties" or "GetDeclaredProperties" or "GetRuntimeProperties" => "GetProperty",
        "GetEvents" or "get_DeclaredEvents" or "GetRuntimeEvents" => "GetEvent",
        "GetMembers" or "get_DeclaredMembers" => "GetMember",
        _ => null,
    };

    /// <summary>
    /// Calls that reach the type named by their type argument: the members reached ([".ctor"] for an
    /// instance), empty for any member, or null if the call is not one of them.
    /// </summary>
    public static string[]? TypeArgumentTarget(string name, MethodSignature<string> sig) => name switch {
        "System.Activator::CreateInstance" or "HarmonyLib.AccessTools::CreateInstance" when sig.ParameterTypes.Length == 0 => [".ctor"],
        "HarmonyLib.Traverse::Create" when sig.ParameterTypes.Length == 0 => [],
        "HarmonyLib.AccessTools::MakeDeepCopy" when sig.GenericParameterCount > 0 => [],
        _ => null,
    };

    /// <summary>
    /// Index of the argument that carries a type name for APIs that resolve a type from a
    /// string, or -1 if this call does not take one. Indices count <c>this</c> for instance
    /// methods. <paramref name="member"/> is set when the call returns a member of that type
    /// rather than the type ("Namespace.Type:Member" strings).
    /// </summary>
    public static int TypeNameArgument(string name, MethodSignature<string> sig, out bool member) {
        int self = sig.Header.IsInstance ? 1 : 0;
        var ps = sig.ParameterTypes;
        member = false;
        switch (name) {
            case "System.Type::GetType":
            case "System.Type::ReflectionOnlyGetType":
            case "System.Reflection.Assembly::GetType":
            case "System.Reflection.Assembly::CreateInstance":
            case "System.Reflection.Module::GetType":
            case "HarmonyLib.AccessTools::TypeByName":
                return ps.Length > 0 && ps[0] == "System.String" ? self : -1;
            case "HarmonyLib.Traverse::CreateWithType":
                member = true;
                return ps.Length > 0 && ps[0] == "System.String" ? self : -1;
            case "System.Activator::CreateInstance":  // (string assemblyName, string typeName, ...)
            case "System.AppDomain::CreateInstance":
            case "System.AppDomain::CreateInstanceAndUnwrap":
                return ps.Length > 1 && ps[0] == "System.String" && ps[1] == "System.String" ? self + 1 : -1;
        }
        if (Member(name, "HarmonyLib.AccessTools::") is { } at && AccessToolsByName.Contains(at) && ps.Length > 0 && ps[0] == "System.String") {
            member = true;
            return self;
        }
        return -1;
    }
}

/// <summary>Number of values an instruction pops and pushes, for the generic stack model.</summary>
internal static class StackEffect {
    public static int Pops(StackBehaviour b) => b switch {
        StackBehaviour.Pop0 => 0,
        StackBehaviour.Pop1 or StackBehaviour.Popi or StackBehaviour.Popref => 1,
        StackBehaviour.Pop1_pop1 or StackBehaviour.Popi_pop1 or StackBehaviour.Popi_popi or StackBehaviour.Popi_popi8
            or StackBehaviour.Popi_popr4 or StackBehaviour.Popi_popr8 or StackBehaviour.Popref_pop1 or StackBehaviour.Popref_popi => 2,
        StackBehaviour.Popi_popi_popi or StackBehaviour.Popref_popi_popi or StackBehaviour.Popref_popi_popi8
            or StackBehaviour.Popref_popi_popr4 or StackBehaviour.Popref_popi_popr8 or StackBehaviour.Popref_popi_popref
            or StackBehaviour.Popref_popi_pop1 => 3,
        _ => 0,
    };

    public static int Pushes(StackBehaviour b) => b switch {
        StackBehaviour.Push0 => 0,
        StackBehaviour.Push1 or StackBehaviour.Pushi or StackBehaviour.Pushi8 or StackBehaviour.Pushr4
            or StackBehaviour.Pushr8 or StackBehaviour.Pushref => 1,
        StackBehaviour.Push1_push1 => 2,
        _ => 0,
    };
}
