# Policy changelog

What changed in [policy/policy.jsonc](../policy/policy.jsonc) at each version, newest first. Every
result is stamped with the policy version and the policy file's SHA-256, so a result can be matched
to the entry that produced it. The record starts at policy 3.

Entries keep the terms of their time. The top tier was called **Full access** (tier id `full-access`)
until policy 36. Before policy 13 the tiers were `content-only`, `known-access` and `full-access`, with
`unverified` between the last two from policy 9 to 12.
Letters and numbers in parentheses (R3, H12, D9, ...) name internal review and hardening tasks.

## Policy 36

The top tier "Full access" is renamed "Broad access", with no change to what puts a mod in it or to
its summary. The tier id "full-access" becomes "broad-access", the policy sections "fullAccess" and
"fullAccessCombinations" become "broadAccess" and "broadAccessCombinations", and results carry
"broadAccess" for their reason groups. The pipeline reads results from before v36 as the new names.

## Policy 35

D (typed reflection reads). Analyzer change only, no rule changed. A member found by a constant name on
exactly a resolved type (typeof, a constant type name) carries its declared type when every member of
that kind the name can find there and on the base types (in any casing) is declared as one class or
struct of the mod's own assembly or of the game (game-API map format 7 records the declared type of
every game member, and each game type's interfaces). D5: FieldInfo/PropertyInfo.GetValue through it is
an object of that type or a derived one, as GetType() of a declared value already was (a property only
when its getter returns its type). D6: FieldType, PropertyType and ReturnType are exactly that type.
Both also through a member kept in a field, parameter or return value. D7: a Harmony prefix, postfix or
finalizer's `__instance` declared as object is an instance of the patched type or a derived one, when the
attributes name it by typeof and it alone declares the patched method, and the mod's own code neither
calls the patch method, takes it as a delegate, reaches it by reflection (new HarmonyMethod(type, name)
now counts as a lookup by that name) nor stores into the parameter. D9: a lookup on a game type known only
up to its derived types also reaches the same members of the game's types deriving from it (by base type
or interface). D10: a local whose address is taken somewhere in the method no longer keeps the last
object stored into it, only its declared type (a store through a ref local could replace it). Results
can only move from "Uses reflection the check cannot trace" to bounded reflection or to traced members,
gain labels and reasons (D9) or move to untraced (D10).

## Policy 34

C review (memory-safe patterns). Analyzer change only, no rule changed: four shapes the runtime keeps
memory-safe are no longer raw memory. C1: a span of enum elements over a stackalloc buffer (the enum's
size is its one instance field's, read from the mod's or the framework's metadata). C2: MemoryMarshal
AsBytes, Cast, Read, Write, TryRead and TryWrite with every type argument plain data (no reference,
pointer or native integer, nested structs included). C3: explicit-layout unions over framework enums
and plain framework structs, laid out from the shared framework's own metadata (a framework type that
holds a reference stays unknown). C4: the stores of a stackalloc initializer of primitive or enum
elements, in every shape the compiler emits (stind at constant offsets, initblk, cpblk from constant
data by address or through RuntimeHelpers.CreateSpan): each store's offset and size, or the copy's
length, is checked against the buffer's constant size; v33's cpblk/initblk rule stays for every other
shape (it turned out the compiler does emit them, for initializers of three or more constants). C5: the
game-API map records the game's `[InlineArray]` types (profile format 6), so a mod's compiler-generated
inline-array helper over a game type is checked like one over its own. Game-API map format 6.

## Policy 33

B review (direct memory access). Analyzer change only, no rule changed: the cpblk and initblk
opcodes are raw memory whatever their addresses are. Before, only their address operands were
checked for being managed references; their byte-count operand was not, so a block copy or fill
of a caller-chosen length through a managed address (a write past the destination's own size) was
Limited access. The C# compiler never emits a bare cpblk/initblk (it routes through Unsafe/Buffer,
caught by their own rules), so the two appear only in hand-written IL and always fail closed now.

## Policy 32

H12. Analyzer change only, no rule changed: that signature is also matched when it names the same
types through other tokens (a type reference into the module for its type definition, one framework
facade's System.Exception for another's, as merged assemblies write them; before, only the same bytes
matched, and such a mod's own member counted as unanalyzed-call). A type reference into the module is
resolved part by part (a type named "A/B" is not B nested in A). A framework type no readable runtime
file defines is taken to declare a member name looked up on it (environment only).

## Policy 31

H10b review. Analyzer change only, no rule changed: a member reference that names a type of the mod
(or of a trusted library being profiled) is that code's own member only when the type or one of its
base types there defines a member of that name with the same signature; the runtime matches name and
signature, so a reference to Kill() through a type that derives from Process and declares only
Kill(int) runs Process.Kill (unanalyzed-call; before, the name alone made it the mod's own code). An
`[IgnoresAccessChecksTo]` name is parsed as an assembly display name, quotes included (a quoted
framework assembly name was not recognized); a name that does not parse is unclassified-reference.

## Policy 30

H9 review. Analyzer change only, no rule changed: the null-test exception applies to lookups only
(AccessTools.TypeByName, Assembly.GetType, Module.GetType), not to Assembly.CreateInstance, which
runs a constructor before its result is tested; a type created by name (Assembly.CreateInstance,
Activator/AppDomain.CreateInstance(assembly, type)) reaches its constructors, as
Activator.CreateInstance(Type) does (before, a game or library type's constructor was not reached).

## Policy 29

H9, classification. GCHandle: Alloc, IsAllocated and comparisons are safe; FromIntPtr, the
explicit conversions, ToIntPtr, Free and Target act on whatever handle address they are given
(raw memory). System.Runtime.InteropServices.Marshalling (the `[LibraryImport]` marshallers) is raw
memory, its COM wrappers native code. The CPU feature checks (IsSupported) of the ISA classes the
index uses are safe. TextFieldParser opening a path is a file read (the path is traced), the rest
of it safe. XmlSerializer(Type, XmlAttributeOverrides) is "xml-serialization-open" (the types the
overrides name are not followed), its event and attribute-collection types safe. DriveInfo's
queries are user-info (renaming a volume stays unclassified). Process.GetCurrentProcess and
StartTime are safe. New label capability "ipc" ("Communicates with other programs on your
computer"): named Mutex, Semaphore and EventWaitHandle and their OpenExisting/TryOpenExisting; the
unnamed forms and their instance members are safe. Analyzer: a type found by a constant name with
no assembly part that nothing has, whose result is only tested for null, is not unanalyzed-call; a
delegate constructed from a native int that no ldftn/ldvirtftn in the method produced is native
code (it calls whatever address it is given); a call into an assembly named like the game's that
this game build does not have is the new finding "missing-game-code" (not fully checked).

## Policy 28

H8 review. Analyzer change only, no rule changed: a stackalloc span's length must be the
count's own value (a plain load of the same store, not the buffer, a product or a count kept in
another local); a count or counted buffer stored to a local is only a value; and stackalloc in a
method without localsinit (`[SkipLocalsInit]`) is raw memory (the buffer holds old stack data).

## Policy 27

H8, raw-memory precision. The unsafe compile flag (UnverifiableCode) alone is informational
("unsafe-code"): the runtime gives it no meaning, and every unsafe construct is found in the IL.
Members that touch no memory are safe, matched by their full signature: Marshal.OffsetOf (Type,
string and the generic form), Unsafe.SizeOf and IsNullRef, and the error-code helpers
SetLastPInvokeError, SetLastSystemError, GetHRForLastWin32Error, GetPInvokeErrorMessage and the
(int) forms of ThrowExceptionForHR and GetExceptionForHR (the IntPtr forms take an IErrorInfo
pointer and stay raw memory). Analyzer: a constant 0 stored as a reference is null; a stackalloc
of 1-byte elements with a variable count (no mul) into a span of that element is accounted
for under the count rules (the same store of a local whose address is never taken).

## Policy 26

H7b review. Analyzer change only, no rule changed: a type nested in the looked-up type (the
mod's or the game's; the check counts a nested type found from a type as that type) is also
searched with what it inherits from outside the mod, and a mod type's own indexer no longer
keeps an indexer lookup (found by its parameters, whatever it is called) from a base type's.

## Policy 25

H7b. Analyzer change only, no rule changed: a lookup or a Harmony patch named through one of
the mod's own types also reaches what the type inherits from outside the mod (a game base type
through the game-API map, a trusted library's by its profile, a framework type by these rules
for the names it has; before, nothing). A static method that implements a static abstract or
static virtual interface member (called through a type parameter) is called with any arguments,
as a virtual method is. GetType() of a value of a game (or any non-mod) declared type also
reaches the mod's types that derive from it, by the lookup's names.

## Policy 24

H7 review. Analyzer change only, no rule changed: a lookup of a game or trusted-library type's
property, event or indexer by a name that neither it nor any accessor name of it has (an indexer
renamed with `[IndexerName]` found by AccessTools.Indexer, an explicit interface implementation,
hand-written IL) reaches every member of the type; before, nothing. A Harmony getter or setter
patch without a name patches the indexer's accessor, a finalizer patch Finalize, an operator patch
the type's `op_` methods (before: no target). A method of the mod's own taken as a method handle
(ldtoken: an expression tree's call, compiled) is called with any arguments, as a delegate is; and
one reflection can reach gets any path arguments, as one called from outside does (before, a
private helper invoked by name kept only its direct calls' paths).

## Policy 23

Reflection precision (H7). Analyzer change only, no rule changed: a method of the mod's own
type counts as reached by reflection (any argument) only when a lookup on the type can return
it (by its name, ignoring case, a name ending in `*` as a prefix, a property's or event's name
for the methods the metadata gives it, a nested type found through its outer type), not for
every lookup on the type; lookups by a name parameter and through traced Type fields are
iterated together. A collection kept on the stack across a block start is followed on when
every way in carries it there; one kept along a backward branch is not followed (before, a
conditional backward branch kept it, Limited access). A branch into the middle of an
instruction (or an exception region not on instructions) is code the check cannot read.
Traverse.Create(object) on an object of a declared class or struct is that type (exactly, for
a new or boxed one) or a type derived from it, as for GetType. InvokeMember("") (the default
member) reaches any member.

## Policy 22

Inherited game members (H5 review). Analyzer change only, no rule changed: a member
reference or a lookup by name on a game type also finds what its base types define, as the
runtime and reflection do. A member a game base type defines reaches that member's map entry
(before: not analyzed for a reference, and nothing at all for reflection or a patch target found
by name, where GetMethod or AccessTools.Method run the base type's member); one a framework
base type defines is classified by the rules below as a direct reference to it; one neither
has stays unanalyzed-call. Profile format 5: members by type, and each game type's base type.
Also: a member reference that names one of the mod's (or a library's) own types for a member
neither it nor its base types there define (hand-written metadata; the runtime runs what it
inherits from another assembly, Process.Kill through a type deriving from Process) is
unanalyzed-call; before, it read as the mod's own code and reached nothing.

## Policy 21

The game-API map tells "read, reaches nothing" from "not read" (H5). Analyzer change only, no
rule changed: a game method whose signature or body cannot be decoded reaches unanalyzed-call
(and so does every game method that can reach it), where before it was left out of the map
and read as reaching nothing; a method whose body is not IL (mixed-mode native code) is
native-code, and a game assembly with native or precompiled code gives every one of its methods
native-code (the namespace exemptions below still apply). The game profile lists every method
and field the game defines: a call into a game assembly to a member this build does not define
(removed, renamed, forwarded elsewhere) is unanalyzed-call, not a call that reaches nothing.
Profile format 4.

## Policy 20

Span and stackalloc accounting made stricter (H4). Analyzer change only, no rule changed: a
span constructed in place (`call instance Span<T>::.ctor(void*, int)`) is read from its pointer and
length arguments, after the receiver, and is accounted for only on the address of a local of
exactly that span type; a stackalloc size is a count only from mul.ovf/mul.ovf.un (plain mul can
wrap), and only from a local whose address is never taken; in an explicit layout, a field of a
value type of the mod encoded as a class is of unknown size. Also: a local whose address is taken
anywhere in the method (a ref local can write it where the walker does not look) is trusted to
hold only its declared type, not the type, member, string, path, buffer, start info or
collection last stored to it (an enumerator only while every address of it goes straight to a
call that takes it): a web address, a created folder or a harmless type replaced through a ref
local was Limited access before. The same holds where such a local is known from every store
to it (after a loop head), and a collection or start info stored to it is no longer followed.

## Policy 19

Lookups by name that find what the name does not spell (H3). Analyzer change only, no rule
changed: a member name a lookup reaches matches ignoring case (BindingFlags.IgnoreCase, flags
that are not a constant, the by-name Expression factories, CreateDelegate's ignoreCase), and a
name ending in `*` as a prefix (GetMember), in the game-API map, library profiles, framework
nested types and game exemptions. Delegate.CreateDelegate(Type, Type, string, ...) and
Expression.Call(Type, string, ...), Field/Property(Expression, Type, string) are lookups by name
on that type. Reflection on a type of the mod reaches the types nested in it. A type found by
name ignoring case, or through a Type.GetType resolver, is unresolved reflection.
`[IgnoresAccessChecksTo]` naming a framework assembly is "unclassified-reference" (non-public
framework members are not classified).

## Policy 18

Explicit-layout overlaps (H2). Analyzer change only, no rule changed: a type of the mod with
[StructLayout(LayoutKind.Explicit)] whose instance fields share bytes is "raw-memory" unless
both fields of every overlapping pair are plain data (integers, floats, bools, chars, and the
mod's own enums and structs of those, a few framework value types such as Vector4 and Guid).
A reference, pointer, native integer, managed reference, generic or other assembly's value type
over anything is a type confusion with no API call; a field the check cannot size reaches to the
end of the type.

## Policy 17

Name gating (G4). Analyzer change only, no rule changed: what R6 still matched by name alone
must also come from the framework (see AssemblyWalker.Models): a type found by name no longer
resolves to a mod type of that name alone (the framework's, game's or a library's counts too);
a mod assembly named "System..." is not the framework; root base types, iterator interfaces,
InlineArray attributes, inline-array helper callees, enum bases, delegate constructors, the
types an interpolated value is formatted as, and compiler attributes on a method must be the
framework's.

## Policy 16

Gap closing (G2b, path-label gaps found by the G1a review). The game folder in Documents is
only the Documents folder itself followed directly by "/My Games/Kitten Space Agency" (in
that order and case, "gameFolder"), not any path with "My Games" or "Kitten Space Agency" in
it; an environment variable is never the game folder. A path parameter of a method that code
outside the mod can call (public, a Harmony patch method, attributed) is also untraced, next
to what the mod's own calls pass, as for reflection. Interpolated strings: ToStringAndClear starts a new text (which can also
follow the old one), what is appended after a branch can begin the text, a handler with a
format provider or whose address is used for anything but its own members is untraced, and a
value that is not a string, number, boolean, GUID or one of the mod's own enums (a char, a
type with its own ToString, a custom format, an alignment on a path) is untraced; char's
ToString is untraced. Parts joined end to end (string.Concat, interpolation) that can make a
".." segment together (a "/." next to "./", or next to a value the check cannot read as text)
are untraced, and so are string edits that can make one (Substring, Remove, Insert, most
Replace and Trim calls, ChangeExtension, GetFileNameWithoutExtension, compatibility Normalize).

## Policy 15

Gap closing (G2a, tier gaps found by the G1a review). Any method Harmony would use as a
transpiler (named Transpiler, `[HarmonyTranspiler]` or `[HarmonyILManipulator]`, a signature
taking or returning CodeInstruction, a transpiler given to Harmony.Patch, ReversePatch or
PatchProcessor.AddTranspiler) is "code-rewrite", whether or not it uses a CodeInstruction
member. A trusted-library member whose exemption says its arguments are checked at the mod's
call ("atCall": Harmony's patching API, HarmonyMethod, the patch attributes, the modelled
AccessTools members, Traverse, the operand setters) is "unresolved-reflection" when it is
taken as a delegate or method handle, or reached by reflection or a patch, since those
arguments are then not checked. An operand that is a string on one path and something else
on another is not inert. FirstOrDefault/SingleOrDefault/LastOrDefault/DefaultIfEmpty with a
default value can return that default. GetMember, GetMembers and DeclaredMembers also find
nested types: a name they are narrowed to reaches every member of the nested type of that
name. A Type or member array handed to a member outside the mod's own assembly that the
walker does not model can hold anything afterwards (untraced, not bounded). String
arguments to a method of the mod's own generic type are recorded, and a member-name
parameter with a call the check saw but no recorded value can name anything. An
XmlSerializer for a type the code does not fix there (typeof(T), a Type parameter, a run-time
type) is "xml-serialization-open" (deep game access, as "xml-serialization"); in the game it
passes on "xml-serialization-game" (deep game access) instead of nothing, which a mod's
call keeps only where it can choose the type (a type argument that is not the game's, or a
Type, object or generic argument); reflection and patches on such a game member keep it. Only
the game member that makes the XmlSerializer has it, not the game code calling that member.
Mach-O universal files in the 64-bit byte-swapped form are native files.

## Policy 14

Every label has a stable "id", which results carry next to its text (reasons are keyed by
their capability or finding as before). Results also carry every piece of evidence
behind a label or reason, sorted, with its count, instead of the first five. Detection
unchanged: every mod keeps its tier, labels and reasons.

## Policy 13

Three player-facing tiers. "content-only", "known-access", "unverified" and "full-access"
become "no-code", "limited-access" and "full-access", each with a name and a one-line
summary. Unverified is no longer a tier of its own: its reasons are the "deep-game-access"
group of Full access. The Full-access reasons are split into three groups, reported apart:
"deep-game-access" (raw memory, bounded reflection, transpilers on the game's code,
XmlSerializer), "system-access" (native code, code loaded or built at run time, programs,
unsafe deserializers, late binding, untraced reflection, COM, native binaries, transpilers on
other code, and the network combinations) and "not-fully-checked" (unreadable code, files
and archives, files not analyzed, scripts, embedded binaries, name collisions, the resource
combinations, and, moved from Unverified, unclassified framework members and calls into code
that was not analyzed: gaps in what was checked, not something the mod does). Detection
unchanged; the tier of a mod that was Unverified becomes Full access.

## Policy 12

Review fixes (R6). A Harmony transpiler is Unverified only on the game's code: a transpiler
whose target is the framework, a trusted library, the mod's own code, code that was not
analyzed, or a target the check cannot place is Full access ("rewrite-outside-game", a reason
of its own rather than "code-generation": the instructions are still traced, but the code
they rewrite is not bounded to the game). The mod's own code counts as outside because the
analysis of its IL, including what is proved on it (a folder it opens, a constant name),
holds only as written. Targets: `[HarmonyPatch]` targets of a class with a transpiler,
TargetMethod(s) results, Harmony.Patch with a transpiler, reverse patches (when the mod uses
the transpiler helpers, as the stand-in can carry one), and PatchProcessor.AddTranspiler
(whose original the check does not link: always outside). This also keeps trusted-library
exemptions sound: a rewritten library member is Full access. A code-rewriting mod also gets
"process-start" back on a game member it reaches or patches whose game-API map entry opens a
fixed web address or a folder (shell-open, shell-open-folder), as for exempt game members:
the instructions that proof is about can change. XmlSerializer for a type the check did not
trace stays Unverified, as an explicit exception to the placement principle (the XML cannot
choose the type). Framework semantics the analyzer
models by name (reflection lookups and sinks, collections and LINQ, name filters, path
combiners and sources, interpolated strings, ProcessStartInfo, Directory.CreateDirectory for
folder opens, clean expression trees, string.Empty, inert patch parameter types) apply only to
members that live in the shared framework, game path sources only to members of the game's
assemblies, and Harmony's only to members of 0Harmony; a type named like one elsewhere is
ordinary code. Harmony's patching API is exempt from "rewrite-outside-game" (it adds the
transpilers it is given; what they rewrite is placed at the mod).

## Policy 11

Game interaction and over-matching (R4). Harmony transpilers (CodeInstruction, CodeMatch,
CodeMatcher, Transpilers, an ILGenerator's DefineLabel and DeclareLocal) are "code-rewrite",
Unverified: the instructions Harmony compiles are the game method's own and ones whose
members are traced (an instruction's operand is a reflection sink, and writing an
instruction's fields by reflection is unresolved), and OpCodes.Calli is native code; OpCode,
Label and LocalBuilder values are safe. Real code generation (Emit, DynamicMethod,
ILGenerator.Emit, ...) is unchanged. A transpiler on a game member that an exemption names
gets the exempted capability back. A Harmony patch whose patch methods can only observe (a
void prefix, postfix or finalizer whose parameters are strings, numbers or `__state`) passes on
nothing of a game or trusted-library target. Process.Start of a folder the method has just
created with Directory.CreateDirectory, traced to the mod's or the game's folders, is
"shell-open-folder" (a label). IPAddress and IPEndPoint are values (safe); NetworkInformation
is "user-info", except Ping (network). A plural member lookup whose elements are only taken
through LINQ filters that require a constant name reaches only the members of that name.
XmlSerializer's constructors for one type are "xml-serialization" (Unverified, instead of
unclassified); Serialize and Deserialize are safe; an XmlSerializerAssembly attribute is
dynamic loading. An XML load whose
path starts with a traced folder (an untraced part only appended) is a file read, not a
possible web address. ELF and Mach-O files are native binaries, not unreadable files.

## Policy 10

Reflection precision and split (R3). Reflection whose target is known only up to a game or
mod type and the types derived from it (obj.GetType() on an object of a declared game or mod
type), or to any type of a game or mod assembly (typeof(X).Assembly.GetType of a name built at
run time), or whose member came from a lookup on such a type and was then passed to code the
check does not follow, is Unverified ("bounded-reflection"); everything else the check cannot
trace stays Full access. Traced now: elements of member arrays and lists from GetMethods,
GetProperties, `AccessTools.GetDeclared*`, ... (ldelem, foreach, LINQ First/Where/ToList, ...)
until something untraced is put into them; Type and member parameters (from every call site,
unless the method can be called from outside the mod) and return values (from every ret);
closure fields (a public field of a private type is not assignable from outside);
TargetMethods iterators (yield return) and returned arrays or lists. Expression factories
(Call, Field, Property, New, ...) are reflection sinks and are classified ("reflection");
compiling a tree built only from traced members is not code generation. Expression.Dynamic
is late binding.

## Policy 9

Four tiers. New tier "unverified" between Known access and Full access, for blind spots
bounded to the game's or the mod's own code and memory ("unverified" section): raw memory,
unclassified framework members and calls into code that was not analyzed move there from
"fullAccess". A mod is Full access if any Full-access reason or combination applies, else
Unverified if any Unverified reason applies. What game and library members pass on through
overrides and patches is still every capability that raises the tier. Detection unchanged.

## Policy 8

Review fixes. Reflection on a resolved type and Harmony patch targets are decided by where
the type lives (game-API map, library profile, unanalyzed, unclassified framework member),
including the assembly a type name names. A shipped file named like the framework, the game
or a trusted library is Full access (name-collision). Reads through an address that is not a
managed reference, initobj/cpobj/mkrefany, and by-reference arguments, locals and returns
that are not managed references are raw memory. `[HarmonyPatch]` attributes inherited from a
base class are merged. File paths are traced per operation (path atoms through arguments,
fields and results; rooted literals are absolute paths) instead of over a neighbourhood
("traceDepth" removed). New rules: Vector Load/StoreUnsafe and aligned loads and stores,
XStreamingElement.Save(path), ZipFile.OpenAsync, XML loads by URL ("fileAccess.urls":
network unless the path is traced to a file), certificate
files, the certificate store, chain building, persisted keys, MetadataUpdater.ApplyUpdate.
Harmony's AccessTools exemption names the members modelled at the mod (MakeDeepCopy and
GetDefaultValue are now sinks). Game profiles list the game's types (format 3).

## Policy 7

Hardening phase 4, second half: manifest resources that hold a program, library or archive
(by leading bytes, a PE header anywhere, or a bundler's file name) are Full access
(embedded-binary), as are linked resources. `[HarmonyPatch]` and `[HarmonyDelegate]` targets
are decoded: a framework target gets its type's capabilities as reflection does, a game
target its Full-access game-API capabilities, a trusted-library target its profile; a
Harmony attribute type of the mod is untraced reflection, as are a TargetMethod result
that is not traced, every TargetMethods result and an untraced Harmony.Patch original.
Writes into the mod's or the game's folders get "Changes files in its own or the game's
folders"; with a network connection (or with a write outside the game, which may be the
same folders) they are Full access (fullAccessCombinations). A file method taken as a
delegate is not path-traced. Trusted-library attribute constructors apply their profile.
Harmony's attribute constructors are exempt like its patching API.

## Policy 6

Hardening phase 4, first half (close the boundary): a call into a trusted library applies
that member's library profile (`profile --library`), Full-access capabilities and findings
included; a trusted library without a profile for every trusted version is not analyzed.
The game-API map keeps Full-access capabilities and covers non-public members. Curated
exemptions in "game.exempt" and "libraries.exempt".

## Policy 5

Hardening phase 3 (reflection provenance, in the analyzer): invoking, creating, reading or
writing a member or type that is not traced to a name is unresolved reflection, including
through fields (resolved from every writer), Harmony "Type:Member" strings, patch methods
and Traverse, Delegate.CreateDelegate by name, typeof(T) of a generic parameter, and
bodiless extern methods (UnsafeAccessor). Finding text reworded.

## Policy 4

Hardening phase 2 (classification inversion): a framework member no rule matches is
Full access (unclassified-reference); a call into an assembly that is not the mod, a
trusted library, the game or the framework is Full access (unanalyzed-call). New
"safe" list, informational "reflection" capability, Path.GetTempFileName is a file write.

## Policy 3

Hardening phase 1 (late binding, Marshal, more deserializers, archive/XML/FileSystemInfo
file labels, certificate store, services/WMI, temp folder counts as outside).
