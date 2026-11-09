# Known gaps

- **Bounded reflection relies on declared types (policy 10).** `x.GetType()` on a value whose
  declared type is a game or mod type (and, since policy 23, `Traverse.Create(x)`) is taken to be that
  type or one derived from it; IL that
  breaks its own declared types (unverifiable code, which C# does not produce) is not detected.
  A member array from a lookup on a game or mod type that was passed to code the check does not
  follow in the mod's own code is bounded to that type, although that code could have put another
  member into it; putting an untraced member into it is caught only where the walker sees the array.
  Passed to framework, game or library code the check does not model, the array is untraced from
  then on (policy 15). Bounded
  reflection grants the capabilities of the members it names on the declared type and, since policy
  35, on the game's types deriving from it (by base type or interface); not those of a trusted
  library's or another mod's type deriving from a game type, and for a framework type only the type's
  own. The mod's own types that derive from the declared type count as reached by it (any argument for
  the methods it can return; policy 25). Typed reads (policy 35) rely on the same declared types: a field
  of the mod's own assembly holds what its declared type allows only for IL that respects its types (an
  explicit-layout overlap of a reference is raw memory already, see below), and the game's member types
  are those of the game build the map was made from, which the scan is stamped with.
- **Harmony's `__instance` is bounded only by what the mod does (policy 35).** A patch method whose
  `__instance` is declared as `object` gets the patched type's bound only when the mod's own code does not
  call it, take it as a delegate or reach it by reflection. Another mod can still call a public patch
  method with any object, as it can call any public method (see "Another mod can change this mod's
  reflection fields"); that is not followed. Harmony's other injected parameters (`__result`, `___field`,
  the original's named arguments, `__args`) are not typed, and a constructor or a method a base type
  also declares (an override) is not bounded (Harmony may patch the base type's).
- **Explicit-layout overlaps are judged from metadata, and coarsely (policy 18; narrowed policy 34).** A
  field whose type the check cannot lay out (a value type from the game or a library, a framework
  struct that holds a reference or native integer, a generic type or parameter, an inline array)
  counts as not plain and as reaching to the end of the type, so it can over-flag a union of plain
  game structs; a native integer over an integer counts too, although it alone reaches no memory.
  Framework enums and framework structs of plain data are laid out since policy 34 from the shared
  framework's own assemblies (the runtime the check runs on, whose version the result stamps, is
  taken to lay plain value types out as the game's runtime does; a layout from it is never used to
  bound a reference). The mod's own
  structs are sized with natural alignment, rounded up. Unverifiable IL (not C#) that stores a
  reference into a location of an unrelated type without a cast gives the same type confusion
  without any overlap, and is not detected (see "Bounded reflection relies on declared types").
  Only the mod's own types are checked. A public explicit union of the game, a trusted library or
  the framework that overlaps references would let a mod confuse types through it without a layout
  of its own. None is known: Harmony's only union is plain data.
- **Deep game access is coarse (policy 9).** All direct memory access is deep game access,
  whatever the address: a pointer the mod makes up, or is handed by code the check did not trace,
  is not yet told apart from one the game hands over, although only the latter is bounded to the
  game's memory. Until this is split, the group means "the check cannot follow this", not "this
  stays inside the game". An author who knows the rules can aim for this group alone; see "The
  groups explain the tier" in [Tiers and labels](tiers-and-labels.md). (Parts of .NET the policy does not classify and calls into code
  that was not analyzed were in the same tier until policy 13, and are now couldn't be fully
  checked.) The B review (policy 33) decided against splitting the reason by origin, and this is
  now a settled decision rather than deferred work: under the threat model the attacker hand-edits
  IL, so a pointer's game origin cannot be proven to survive arithmetic, a store and reload, or a
  pass through untraced code; and "bounded to the game's memory" is not a boundary worth promising
  a player, because a write into the game's own heap can corrupt game state the game then acts on,
  with the player's full privileges. Keeping all direct memory access in one group is the honest
  reporting.
- **Exemptions are reviewed by hand.** The game's native code and direct memory use are exempt
  as a whole (by namespace), because almost every game member reaches them. A game member that
  lets a mod choose the address it reads or writes (a handle passed as `IntPtr`, an unchecked
  native buffer) is not told apart. Harmony's patching and reflection API is exempt from the
  capabilities that implement patching; what is patched is checked at the mod.
- **Overrides in the game contribute capabilities that raise the tier, not labels.** A virtual game
  method's labels come from its own code and callees; what other game types' overrides do counts
  toward the tier only. Calls through a framework interface or base class (`IDisposable`,
  `object.ToString`) on a game or library object are not followed into the object's code.
- **Findings inside the game are not carried.** Reflection the check cannot trace (an
  `UnsafeAccessor` included) and unclassified framework members inside the game's own code do not
  reach the mods that call it; trusted libraries do carry them. Game code the check cannot read is
  the exception: it is not analyzed (policy 21). A delegate a mod reads from a game field (for
  example a static `Action<string>` the game's type initializer fills) runs game code that the
  mod's call through it does not reach in the map: a field load is not a call, and type initializers
  are left out. A game method that makes the delegate it returns does reach its target.
- **A call into a trusted library is merged over every trusted version**, and same-named
  library assemblies share one call model, which can over-report.
- **Microsoft libraries a mod ships are analyzed as the mod's own code.** Only the mod loaders'
  releases are trusted by hash. A genuine Microsoft package that a mod bundles (ASP.NET Core,
  `Microsoft.Extensions.*`) is analyzed like the mod's code: what it can do counts, its unclassified
  framework members are couldn't be fully checked, and a copy named like a library a loader ships
  but with another hash is reported as one. Trusting such files would need a ledger of official
  package hashes, which does not exist yet. This over-reports and never lowers a result.
- **Dependencies on other mods are not followed.** A call into an assembly that the mod does not
  ship, and that is not trusted, the game or the framework, makes the mod Broad access
  (couldn't be fully checked), whatever that other mod's own tier is (Limited access or Broad
  access): the other mod's result says what it can do.
- **Framework members are classified by name, by hand.** The policy's `safe` list says which
  framework members need no capability; it is not derived from the framework's own code. A
  framework call that reaches a capability through a member the list wrongly calls safe (for
  example through a virtual call on an object the game hands over) is missed.
- **Results depend on the .NET runtime the tool runs on**, whose shared framework decides which
  assembly names count as the framework. The runtime version is in each result's stamp.
- **The allowlist and the scan trust the index snapshot as published.** Archives are verified
  against the hashes the snapshot carries, but not against the ledger's own attestation, and the
  snapshot is fetched over HTTPS from the index's site. "Trusted" means "the build the author
  published", not "safe".
- **One game build for every mod.** Each scan uses the game folder it is given, whatever game
  versions a release declares (`game_min`, `game_max`; mostly a self-declared minimum). A mod
  built against another game build can call game assemblies or members that build does not have,
  which count as code that was not analyzed (members since policy 21; an assembly named like the
  game's that the build lacks altogether is "Calls game code that this game version does not have"
  since policy 29, in the same group; a member the build lacks keeps "Calls code that was not
  analyzed", with evidence that says so). A member named through a
  derived type that this build declares on a base type is looked up there, as the runtime does
  (policy 22): a game base type's map entry, or a framework base type's member by the policy's
  rules. Members are matched by name, not signature: an overload a base type adds under a name the
  derived type also has is taken to be the derived type's.
- **The game-API map covers only the assemblies it was generated from**, and must be
  regenerated for each game update; the game exemptions in the policy were reviewed against one
  game build and must be reviewed again (the profile prints how many members reach a Broad-access
  capability, by group). The same holds for library profiles and exemptions when the allowlist changes.
- **Opening a folder (policy 11)** is told apart from starting a program only for a folder the same
  method creates with `Directory.CreateDirectory` just before (in the same block, on the same
  argument or local) and then starts through `Process.Start(string)` or a `ProcessStartInfo` with
  nothing but its file name and `UseShellExecute` set, traced to the mod's or the game's folders and
  ending in a literal name without a dot. Any other folder, and a web address that is not a
  constant, counts as starting a program. A folder replaced by a link between the two calls is
  not detected. The dot-less rule was reviewed against Windows `ShellExecute`, macOS `open` and
  Linux `xdg-open`: an existing directory is routed to the file manager on each, and a launchable
  bundle or document requires a dotted extension, so the rule is sound as long as the directory
  exists at the start. The check assumes `CreateDirectory` created it; it does not know the call
  threw at run time (a Windows reserved device name such as `CON`, or another invalid name). If no
  directory was created, a dot-less start on Windows can complete through `PATHEXT` to a sibling
  executable the mod ships in its own folder. The name is not recoverable at the decision point to
  reject it, so this stays open; a start the check cannot prove opens a folder should be read as
  possibly starting a program.
- **Transpilers on the game's code are deep game access as a whole (policy 11).** The check traces what a transpiler's
  instructions name, not the patched method Harmony compiles from them: game instructions moved,
  copied or dropped, and memory or native calls the game method already makes, are not followed.
  An instruction's opcode that is not a constant (taken from another instruction) is accepted as
  one of the game method's own. `OpCodes.Calli` anywhere in a mod counts as native code, even when
  it is only compared. Transpiler helpers that look a member up by name themselves
  (`CodeInstruction.Call`, `LoadField`, `StoreField`, `CallClosure`) carry their library profile,
  which is Broad access. Game exemptions that cover a whole namespace (the engine's native and
  memory code) still apply to a method a transpiler rewrites. MonoMod IL manipulation (`ILContext`,
  `ILCursor`) is not modelled: its members carry their library profile, which is Broad access.
  Only a transpiler whose target is placed in the game's code stays deep game access (policy 12): the
  mod's own code, a game type known only up to its derived types (which can be the mod's), and a
  `PatchProcessor` given a transpiler (whose original the check does not link to it) count as
  outside, which is system access. A mod that uses the transpiler helpers and also makes a
  `[HarmonyDelegate]` to a member outside the game counts as rewriting it (a reverse patch's
  stand-in can carry a transpiler, and the two are not told apart). Of what the game-API map
  proves on the game's own instructions, only opening a web address or a folder is given back
  (as starting a program) for a game member a code-rewriting mod reaches. The game exemptions given
  back to a transpiler's target are looked up on the type the patch names. A member that type
  inherits from a game base type does not get the base type's exemptions back, so what they cover
  is not counted for it (H5 review; not fixed).
- **Observing patches (policy 11)** are recognized by their signature only: a prefix, postfix or
  finalizer that returns nothing and takes only strings, numbers, `__originalMethod` or `__state`. It
  can still throw (a prefix that throws stops the original), read static game state and change it
  directly, as any mod code can; a struct or enum parameter counts as changing.
- **Name filters (policy 11)** are proved only for a lambda that begins with `m.Name == "constant"`
  (or `string.Equals`) on its parameter and returns false otherwise, and that is created where it is
  used (a lambda that captures a variable). A lambda without captures is cached by the compiler in a
  static field, which the check does not follow: it reaches every member, as before. (Until policy 23
  the cached form was also Broad access: the member array on the stack at the branch the compiler's
  caching code puts before the LINQ call counted as handed to code the check does not follow. A
  collection every way into a block carries at the same place on the stack is now followed on; two
  different ones meeting there, as after `b ? x.GetMethods() : y.GetMethods()`, are not.) A filter
  given to `Where` is never treated as a name filter.
- **XmlSerializer is deep game access (policy 11)**, even for a type the check traced: the types it
  fills (from the type's fields, properties and `XmlInclude` attributes) are not enumerated. It is
  deep game access too when the check did not trace the type at all (a generic `typeof(T)`), although
  that type is then not bounded to the game's or the mod's code. This is a deliberate exception to
  the placement principle: the XML cannot choose the types (unlike `BinaryFormatter`), and what
  `XmlSerializer` runs is the parameterless constructors and public setters of types the mod's own
  code names, which is how ordinary mods keep their settings. A
  pre-generated `<Assembly>.XmlSerializers.dll` next to the type's assembly is loaded when present:
  a shipped one is analyzed as one of the mod's files; one the mod writes there is a write into its
  own folder, like any DLL the loader would load. The game's own XML loading is exempt, except for a
  game member that makes an `XmlSerializer` for a type its caller gives it (policy 15), which counts
  where a mod gives it a type of its choosing.
- **The game's XML helpers are recognized only where the serializer is made (policy 15).** A game
  member counts as one when its own code makes an `XmlSerializer` for a type it does not fix (a
  generic parameter, a `Type` it is given, an object's run-time type). A game method that only
  passes a type it is given on to such a helper (a generic wrapper) is not followed, and a call
  counts as choosing the type only through type arguments and `Type`, `object` or generic
  arguments: a helper that serializes the run-time type of an argument declared as a game class,
  given a mod subclass, is not counted. Neither fails toward the higher tier; the mod's own types'
  constructors and setters are analyzed with the mod either way, so what is missed is a framework
  type the mod picks. The other way round, reflection that reaches a game type's type initializer
  also counts a serializer that initializer makes with `XmlAttributeOverrides`
  ("xml-serialization-game", policy 29). A mod cannot give a type initializer a type, so this
  over-reports.
- **`foreach` over a user-defined or game inline array** indexes it with a loop variable, which the
  check cannot bound, so it counts as raw memory access. Collection expressions, `params` spans and
  indexing with a run-time value (a bounds-checked span) are not affected.
- **Some memory-safe compiler output still counts as raw memory** (it fails toward Broad access):
  the stores of a `stackalloc` initializer of struct elements (`stackalloc Pair[] { ... }`: the
  buffer is sized with `sizeof` and the offsets built from it, which the offset proof of policy 34
  does not cover), a `stackalloc` of game enum elements (the game's enum sizes are not in the map),
  reading a `ref` field of a `ref struct` (it waits on a type-reinterpretation check that does not
  exist yet, see "Explicit-layout overlaps"), `MemoryMarshal` members other than `AsBytes`, `Cast`,
  `Read`, `Write` and their `Try` forms (`AsRef`, `GetReference`, `CreateSpan`, ...), and a span built
  in place on the address of a field or an argument, or of a local taken in another block. Each
  needs more than the kind of an address to be shown safe (offsets inside the buffer, the game's
  layout, the type behind a reference). Policy 34 (the C review) removed from this list a
  `stackalloc` of the mod's or the framework's enums, initializers of primitive and enum elements,
  the four `MemoryMarshal` reinterpretations over plain data, and the inline-array helpers over a
  game `[InlineArray]` type; the acceptance of each relies, like every check here, on IL that
  respects its declared types (see "Fields read or written through an unmanaged pointer").
- **Reflection by member name** on a resolved type grants all of that type's capabilities, which
  can over-label. Writing a private framework field through reflection on a resolved type is
  not told apart from other member access on that type.
- **Reflection through parameters, returns and collections is traced coarsely (policy 10).** A
  parameter's or return value's types are the union over every analyzed call or `return`, not
  per call; a helper that takes a `Type` and looks a member up on it reaches the members named
  by every string any call passes, on every type any call passes (all members when a name is not
  traced). A parameter of a public method, or of any method of a type the mod's own reflection
  reaches, is untraced (Broad access), even when every caller in the mod passes a traced member.
  Arrays and lists are followed only in the method that made them (or through a field of this
  assembly typed as an array of types or members); a list kept in a field, a dictionary, a tuple,
  an enumerator kept across `yield return`, a LINQ `Select`, or a lambda's parameter is not
  followed. Iterating all of a type's methods (`GetMethods()`) and picking one by name in a lambda
  grants every member's capabilities (labels included). Compiled expression trees are clean only
  for the factories listed above; operators (which find methods on operand types) and dynamic
  expressions are code generation. A by-name factory on an expression (`Expression.Field(expr,
  "name")`, `Expression.Call(expr, "name", ...)`) finds its member on the expression's run-time
  type, which is unresolved reflection; one on a `System.Type` (`Expression.Call(typeof(T), "name",
  ...)`) is a lookup by name on that type, like `GetMethod("name")` (policy 19). A value read with
  `GetValue` is given the member's declared type only for a member found by a constant name on exactly
  one type (policy 35, see [How it works](how-it-works.md)); a value returned by `Invoke`, a member found on a run-time
  type, in an array or list, or by a name that is not a constant, a member of a trusted library or of
  another of the mod's assemblies, and a plain `object` parameter (not typed from what its callers
  pass, even when only the mod's own code calls the method) are not typed, and `typeof(X).FullName` is not folded to a constant name. Reflection on such a value is
  untraced (Broad access), which over-reports. The type is not carried through a call that returns
  `object`, a local whose address is taken, or a generic helper.
- **Member names match ignoring case, always (policy 19).** The check does not read the binding
  flags of a lookup: every name a lookup reaches matches the members of that name in any casing, and
  a name ending in `*` every member whose name starts with the rest. Where a type has members whose
  names differ only in case, a lookup reaches all of them (an over-approximation, erring upward).
  On a framework type the capabilities do not depend on the name (the whole type's count), but a name
  in another spelling than the framework's can count as a member the policy does not classify.
  Reflection on a type of the mod reaches the methods of it (and of the types nested in it) that the
  lookup can return, by those rules, by a property's or event's name for the methods the metadata
  gives it whatever they are called, and every method for a lookup not narrowed to names (policy 23;
  before, every method). On game and trusted-library types a property, event or indexer lookup reaches
  the members named `get_X`, `set_X`, `add_X`, `remove_X`, `raise_X` (an indexer: `get_Item`,
  `set_Item`); when the type has no member of the name or of any of those names (an indexer renamed
  with `[IndexerName]` found by `AccessTools.Indexer`, an explicit interface implementation, hand-written
  IL), its accessors have other names, and the lookup reaches every member of the type (policy 24;
  before, nothing). A game type whose base type has a conventional indexer and which renames its own is
  still read as the base type's.
- **Non-public framework members are classified by name (policy 19).** The policy's rules name
  framework members without regard to their visibility. A mod can call a non-public framework
  member directly only with `[assembly: IgnoresAccessChecksTo("...")]`, which the runtime honours:
  naming a framework assembly there counts as a part of .NET the check does not classify (Broad
  access). The name is read as an assembly display name, as the runtime reads it (a version or key
  after a comma, a quoted name: policy 31), and one that does not parse counts the same. Naming the game or a trusted library adds nothing, because the game-API map and library
  profiles cover their non-public members; another assembly is code that was not analyzed where it
  is called. Reflection on a non-public framework member of a type with a broad `safe` rule is not
  told apart (see "Framework members are classified by name, by hand").
- **Another mod can change this mod's reflection fields through reflection** (for example
  `FieldInfo.SetValue` on this mod's type). Direct assignments from other assemblies are caught
  in their own analysis; reflective ones are not.
- **A type or member handed to other framework APIs** (serializers, `TypeDescriptor`) is not
  followed; only the reflection calls listed above require a traced target.
- **A type found by name only to test whether it exists (policy 29)** is accepted from a short
  instruction pattern right after the lookup (a branch on it, a `pop`, or a comparison with null),
  for a name with no assembly part that the mod, the game, the framework and the trusted libraries
  do not have, and only for a lookup (`AccessTools.TypeByName`, `Assembly.GetType`, `Module.GetType`):
  a by-name `CreateInstance` has run a constructor before its result is tested (policy 30). Any other use of the result keeps "Calls code that was not analyzed", including the
  same test written another way (stored to a local first, `?.`), so it errs toward Broad access.
- **Named kernel objects are one label (policy 29).** "Communicates with other programs on your
  computer" covers a named `Mutex`, `Semaphore` or `EventWaitHandle`, which can also squat another
  program's single-instance lock so that it will not start; a name that is a constant `null` (no
  sharing) is labelled too. Their access-control forms (`MutexAcl`, `SemaphoreAcl`,
  `EventWaitHandleAcl`) and named memory-mapped files are not classified this way (unclassified, and
  memory-mapped files are file writes).
- **A delegate's code address is trusted only straight from `ldftn`/`ldvirtftn` (policy 29).** A
  delegate constructed from any other native int is native code; one built from a method pointer kept
  in a local first (which C# does not emit) counts too. Constructors of the shape `(object, IntPtr)`
  of game, library and other assemblies' types are treated as delegates' (only the framework's
  `HandleRef` is known not to be one), which can over-report native code for such a type. A delegate
  object passed as another delegate's code address is accepted. That needs unverifiable IL that
  coerces an object to a native int, and the call would jump into heap memory. The COM vtable
  types of `System.Runtime.InteropServices.Marshalling` other than the COM wrappers count as raw
  memory, not native code. Both are Broad access; only the group differs.
- **Overloads share a node** in the call model, which can over-label file access.
- **Only a fixed list of tool names is renamed on extraction** (`.git`, `.vscode`, `CLAUDE.md`
  and the others under ["The tools underneath"](usage.md#the-tools-underneath)). Configuration of other tools (`.envrc`, `_darcs`,
  `.vs`, `.windsurfrules`, `.clinerules` and other editors' and agents' folders) is written as it is, so do not run such tools in
  the state folder; the tier is not affected either way. Renaming also does not stop git from taking a
  folder laid out as a bare repository (`HEAD`, `objects`, `refs`, `config`; `_dm_.git` itself is one)
  as a repository when git runs inside it: do not run git below `extracted/`, or set
  `safe.bareRepository=explicit`.
- **7z, RAR, xz, bzip2, zstd, LZ4 and cabinet archives** are recognized but not extracted, and
  count as Broad access; so do zip entries compressed with a method other than stored, deflate or
  deflate64.
- **Embedded resources are recognized, not analyzed.** A program, library or archive embedded as
  a resource is Broad access even when it is a harmless managed library (analyzing it in memory
  and checking it against the allowlist is not done yet). A payload with no recognizable bytes
  (compressed with deflate or brotli under a name no bundler uses, encrypted, hidden in other
  data) is not found; reading the assembly's own resources together with a write into the mod's
  or the game's folders, or outside the game, is Broad access for that reason.
- **Code-folder writes are a pair of capabilities, not a data flow.** A network connection plus a
  write into the mod's or the game's folders (or a write the check cannot place) is Broad access
  whether or not the downloaded bytes are what is written. A Limited-access mod with "Changes
  files in its own or the game's folders" can still write there what it computes or reads from
  the places its other labels name.
- **Harmony patch targets are approximated.** When several attributes on a class or method name a
  type or method, every combination counts. A base class in another of the mod's assemblies is
  treated like one outside the mod (unresolved reflection), not merged. A patched game
  member contributes its capabilities that raise the tier, not its labels (as with overrides in the game
  profile): a prefix that redirects a game method's file write is labelled only as "Changes how
  the game works". The other way round, a patched game member contributes everything its whole
  call tree can reach, although a patch only changes that member's arguments and result (a patch
  class whose patch methods can only observe contributes nothing, see "Observing patches"). A
  `Harmony.Patch` call counts its original like reflection, whatever its patch methods are. A `TargetMethod` whose result is
  traced only grants what the lookup granted (for a trusted-library type, the policy's rules,
  not the library profile).

- **Fields read or written through an unmanaged pointer** (`ldfld`/`stfld` on a native integer
  instead of an object or a managed reference), and the receiver of a value type's instance
  method, are not told apart from ordinary field access and calls: that needs IL type checking
  (an IL verifier). Reads, writes, by-reference arguments, locals and returns are checked.
  Only the kind of address is checked, not the type of what it points to (policy 20): unverifiable
  IL (not C#, which needs `Unsafe.As` or pointers, both flagged) that reads, writes or passes a value
  through a managed address as another type than the location holds, for example as a span, can make
  up a reference with no finding. The one place the check needs this, a span built in place, is
  accepted only on the address of a local of exactly that span type.
- **Path tracing is flow-insensitive and approximates string edits.** An argument's origins are
  the union over every analyzed call, a field's over every store; values kept in collections,
  tuples or `string.Format` are untraced (outside the game). `Replace`, `Substring` and similar
  edits are treated as appending to the original path (and as changing where it begins and ends),
  and as untraced when they can make a `..` segment (policy 16). An interpolation handler's text
  is followed in walk order: what is appended after a branch or a `ToStringAndClear` can begin the
  text, and the parts before stay in it.
  A path that begins with the mod's or the game's folder is taken to be a file path whatever is
  appended (an empty folder path would let the rest begin it). A game or trusted-library member that
  writes a path its caller passes counts as writing outside the game, whatever the caller passes.
- **A number's text is taken to have no path in it (policy 16).** Integers formatted into a path
  (`$"{dir}/save_{n}.json"`, `n.ToString()`) add nothing to where it comes from. The current
  culture's number format decides a negative sign and group separators, and a mod that installs a
  culture of its own with a sign such as `"/../"` could leave a folder that way. The check does not
  follow number formats; this does not fail toward a higher tier or a broader label.
- **Reflection on game types is matched by name in the game-API map.** A member inherited from a
  base game type is found through the derived type (policy 22; past the last game base type, the
  framework type's members by the policy's rules). A type nested two levels deep that is found
  through its outer type (`GetNestedType("A").GetMember("B")` on a game type) is matched in the
  game-API map by its first nested name only. The `B` that `A` nests is then not fully reached
  there. A framework type found this way is not searched through its nested types' base types. Of
  the mod's own types, the base chain is followed by type name, so with two analyzed types of one
  name only the first is followed (H7b review; not fixed). `new T()` with a type argument chosen by
  the caller is not followed into `T`'s constructor; a certificate loaded with
  `X509KeyStorageFlags.PersistKeySet` is not labelled as changing the key store.
- **Name gating is not covered by negative fixtures (policy 17).** The check applies its modelled
  framework, game and Harmony semantics only to members that come from those assemblies (see [How
  it works](how-it-works.md), item 7), but no fixture yet defines a type named like a framework type (`System.Type`,
  `System.Linq.Enumerable`, `System.IO.Path`, ...) in a mod or in an assembly the check did not
  analyze to show that it gets no modelled semantics; the gating was checked by reading the code and
  by the existing fixtures and the index giving the same results. Every gate fails toward the higher
  tier: a name that is not the framework's loses the narrowing, it never gains one. The raw-memory
  gates (span element sizes, `sizeof`, inline-array helpers) can only be reached with hand-written IL.
- **A trusted library's own Harmony patches are not part of a mod's result (decided policy 17).**
  A mod loader's `[HarmonyPatch]` attributes (StarMap patches `KSA.ModLibrary`, `KSA.Program` and
  `KSA.Mod` to load mods) are applied by the loader itself when it starts, whether or not a mod is
  installed or calls it, and a copy shipped with a mod is not the one that runs (the loader's copy
  wins). Counting them would give every mod that uses the loader the loader's patches, so a mod that
  starts patching the game itself would no longer stand out. Library profiles therefore leave them
  out, and so nothing in the check reports what a loader's own patches do: they are the loader's
  behaviour, trusted with its published build by hash. This does not fail toward a higher tier. A
  mod that calls `Harmony.PatchAll` on a loader's assembly applies those patches again: that counts
  as patching, like any `PatchAll`, but the targets are not followed.
- **Some parts have fewer negative fixtures than the rest (policy 17; updated policy 30).** Three
  areas were listed here as checked only by the code's author and the benign fixtures. Parts of each
  have since been reviewed independently (policies 20 to 30), but a way to look safer than a mod is
  may remain:
  - The folder-open proof tells opening a folder the method has just created apart from starting a
    program. How its folder is traced was reviewed, and it has negative fixtures for a folder replaced through a
    ref local and for a folder helper invoked by reflection (both "Starts other programs"). The
    proof's own shape (same block, same argument) has none. It can lower a result: a mod it wrongly
    accepts gets the folder-opening label in place of "Starts other programs".
  - Archive handling in the pipeline was analyzed and reviewed: extraction, renamed tool names,
    per-listing errors, cached profiles and results, and state-folder paths built from listing ids,
    versions and file names. Archives the check cannot extract are Broad access, and a mismatched
    archive is not scanned.
  - Direct memory access was reviewed twice: a census of every raw-memory finding in the index, and
    an end-to-end review of the detection against every IL and API route (policy 33). It has
    negative fixtures for a forged `GCHandle`, reads through an `IntPtr`, pointer locals, hand-written
    `stackalloc` IL, and hand-written block copies and fills (`cpblk`, `initblk`) through both managed
    and forged addresses. The second review found and closed one gap: `cpblk`/`initblk` were flagged
    only when their address operand was not a managed reference, so a block copy or fill of a
    caller-chosen length through the address of a local was Limited access; they are now raw memory
    whatever the address. There are still no fixtures for function-pointer calls (`delegate* unmanaged`,
    probed by hand only), reference reads through a raw pointer, or a raw address handed back to the
    game. All direct memory access is at least deep game access and is never Limited access. The
    C review (policy 34) then narrowed four memory-safe shapes out of it, each with a control that
    loses the finding and hand-written near-misses that keep it (a store one byte past an
    initializer's buffer, a block copy one byte too long or from data too short, a span of enums
    over half the bytes it needs, a reinterpretation over a struct with a hidden reference or a
    native integer, a union over a framework struct holding a native integer, a span of one more
    element than a game inline array has). It also found that the C# compiler does emit bare
    `cpblk`/`initblk`, for `stackalloc` initializers of three or more constants, which the B review
    had taken to be hand-written IL only; those shapes are now proven by their constant bounds.
