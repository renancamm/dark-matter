# Dark Matter

Static access analysis for Kitten Space Agency mods. Dark Matter reads a mod's compiled .NET
assemblies, without loading or running them, and places the mod in one of three access tiers
with a list of what it can do, in the way an app store lists permissions.

> **Status: prototype.** Results are only as complete as the policy's rules. A missing label
> means the check found nothing, not that nothing is there. Design rule: **every blind spot
> fails upward, to Full access, never to Limited access or No code.**

## Tiers

A tier states what a mod can do, as far as the check can account for it. It is not a judgement
of whether the mod is harmful, and it says what the mod *can* do, not what it does.

| Tier | Shown to players | Meaning |
|---|---|---|
| **No code** | Only adds content. It can't run programs. | Ships no code files: parts, planets, textures, sounds. |
| **Limited access** | It can only do what's listed. | Ships code, and everything it can run was looked at. The labels are the complete list. |
| **Full access** | It can do anything a program on your computer can. | Something in the mod can reach beyond what the check can list, or the check could not look at all. The labels are what it saw, not a complete list. |

A Full-access result says why, in one or more groups. Every group with a reason is listed, so a
mod whose reasons move from one group to another between releases stands out even though its
tier stays the same.

| Group | Shown to players | For example |
|---|---|---|
| **Deep game access** | Works with the game's code and memory directly, in ways the check can't follow all the way. | direct memory access, transpilers on the game's code |
| **System access** | Uses features that can reach anything on your computer. | native code, starting programs, loading code at run time |
| **Couldn't be fully checked** | Part of the mod couldn't be inspected. | an unreadable file, a script or installer, an embedded archive |

**The groups explain the tier; they are not a scale.** The claim is the tier: Full access. Deep
game access means the check's blind spots for this mod are of a kind ordinary modding has, not
that the mod stays inside the game. Code the check cannot follow can still do anything, and a
determined author who knows the rules can aim for that group alone. Couldn't be fully checked
means the check does not know what a part does, not that it does anything; it is often a
packaging problem the author can fix. Only Limited access says the labels are complete.

Many widely used mods are Full access (loaders, scripting bridges, physics mods, mods that use
native libraries). For those, trust rests on the author rather than on the check.

A reason reached through another member (a framework, game or trusted-library member the mod
calls, reaches by reflection or patches) is reported in that reason's group.

### Deep game access

The mod:

- reads or writes memory directly: pointer code (including pointer types in the signatures of
  members it calls, reads and writes through an address that is not a managed reference, a block
  copy or fill whatever its address (`cpblk`, `initblk`: their byte count is not bounded by a managed
  address, so a length past the destination writes out of bounds; policy 33), and a
  by-reference argument, local or returned reference that is not one), `Marshal`, `Unsafe`,
  `NativeMemory`, `MemoryMarshal`, the `[LibraryImport]` marshallers
  (`System.Runtime.InteropServices.Marshalling`), a `GCHandle` made from, turned into or used as an
  address (`FromIntPtr`, its conversions, `ToIntPtr`, `Free`, `Target`; `Alloc` and `IsAllocated` are
  fine, policy 29), vector loads and stores at an unchecked offset, and a type with
  `[StructLayout(LayoutKind.Explicit)]` whose fields share bytes where one of them is not plain data
  (a reference, pointer, native integer or managed reference over anything: the runtime then reads
  one field's bits as the other's type, with no API call; policy 18). Unions of plain data only
  (integers, floats, bools, chars, the mod's own enums and structs of those) are fine. The game's API
  is pointer-heavy, so ordinary mods do this. Policy 9 does not yet tell an address the game hands
  over from one the mod makes up (see "Known gaps"). Not counted (policy 27): the unsafe compile
  flag on its own (it changes nothing at run time, and every unsafe construct is found in the code
  itself; `--facts` records it as `unsafe-code`), members that touch no memory (`Marshal.OffsetOf`,
  `Marshal.SizeOf`, `Unsafe.SizeOf`, `Unsafe.IsNullRef` and the error-code helpers such as
  `GetLastWin32Error` and `SetLastPInvokeError`, matched by their exact signatures, so a form that
  takes an `IntPtr` still counts), and a span over a `stackalloc` buffer or the compiler's constant
  data whose length fits it (`stackalloc int[n]`, and `stackalloc byte[n]` with no multiply, when the
  length is the same store of a local whose address is never taken; since policy 28 a `stackalloc` in
  a method compiled without clearing its locals, `[SkipLocalsInit]`, counts, since the buffer then
  holds what the stack held before). Not counted either (policy 34, the C review): a span of enum
  elements over such a buffer (the enum's size is its one instance field's, read from the mod's or
  the framework's metadata); the stores of a `stackalloc` initializer of primitive or enum elements
  (`stackalloc int[] { 1, 2, 3 }`: each store's offset and size, or the block fill or copy from
  constant data the compiler emits for three or more constants, is checked against the buffer's
  constant size); `MemoryMarshal.AsBytes`, `Cast`, `Read`, `Write`, `TryRead` and `TryWrite` when
  every type argument is plain data (no reference, pointer or native integer anywhere in it: the
  runtime then bounds them to the span's own bytes); and an explicit-layout union over a framework
  enum or a plain framework struct, laid out from the shared framework's own metadata
- uses reflection the check traces only to the game's or its own code: a member of the run-time
  type of an object whose declared type is a game or mod type (`vehicle.GetType().GetField(...)`:
  that type or one derived from it; since policy 35 also a value read with `GetValue` through a
  game or mod member declared as such a type, and a Harmony patch method's `__instance` declared as
  `object`, see "How it works"), a type found by a name built at run time in a game or mod
  assembly (`typeof(KSA.Program).Assembly.GetType(name)`), or a member from a lookup on a game or
  mod type (`GetMethods()`, ...) after the array or list was passed to code the check does not
  follow. Ordinary modding reads game internals this way; the check knows which code it is in but
  not exactly which member, so the labels may miss what that member does
- rewrites the game's code, and only the game's, with a Harmony transpiler (`CodeInstruction`,
  `CodeMatch`, `CodeMatcher`, `Transpilers`, an `ILGenerator`'s labels and locals, or, since policy
  15, any method Harmony would run as a transpiler: one named `Transpiler` or marked
  `[HarmonyTranspiler]`, a method taking or returning Harmony instructions, a transpiler given to
  `Harmony.Patch`, even one that only drops instructions with LINQ; any other target is system
  access, see below). Harmony compiles the patched game method
  from the instructions the transpiler returns, which the check does not read as a whole: what the
  new instructions name is traced (see System access), `OpCodes.Calli` is native code, but
  what the game method's own instructions do once rearranged is not followed. Ordinary modding
  does this to change the game's behaviour inside a method
- reads or writes XML with `XmlSerializer` for a type: it creates objects of that type and of the
  types its fields, properties and attributes name, and sets their members, which the check does
  not follow (the type is chosen in the mod's code, not by the XML). This holds even when the check
  did not trace the type (a generic `typeof(T)`, a `Type` it is given: "Reads or writes XML into objects
  of a type chosen at run time", policy 15), which is then not bounded to the game's or the mod's
  code: see "XmlSerializer is deep game access" under Known gaps
- has the game read or write XML into objects of a type the mod chooses (policy 15): a call to a game
  member that makes an `XmlSerializer` for a type its caller gives it (`Load<T>`, `LoadAs(Type)`),
  with a type argument that is not the game's own or a `Type` or object argument, and reflection on
  or a patch of such a member. A call that gives it only the game's own types is not counted

### System access

The mod:

- runs native code: P/Invoke, `calli`, mixed-mode or precompiled (ReadyToRun) assemblies, native binaries, `NativeLibrary`,
  COM wrappers (`ComWrappers`, `StrategyBasedComWrappers`), and a delegate constructed from a native int
  that no `ldftn`/`ldvirtftn` in the same method made (it calls whatever address it is given; policy 29;
  an ordinary C# delegate is not)
- ships a native program or library: a file without .NET metadata, or an ELF or Mach-O image
- loads or builds code at run time: `Assembly.Load*`, `Reflection.Emit` (`DynamicMethod`,
  `ILGenerator.Emit`, `AssemblyBuilder`), compiled expression trees (unless the tree is built only
  from members the check traced, see below), Roslyn, `MetadataUpdater.ApplyUpdate`, an
  `[XmlSerializerAssembly]` attribute. A Harmony transpiler on the game's code is not code
  generation (see Deep game access)
- rewrites code other than the game's with a Harmony transpiler (policy 12): a transpiler whose
  target is a framework member (`string.Concat`), a trusted library's, one of the mod's own, a
  member of code that was not analyzed, a game type known only up to its derived types, or a target
  the check cannot place (an untraced `TargetMethod` result or `Harmony.Patch` original, any
  `PatchProcessor.AddTranspiler`, a reverse patch's original when the mod uses the transpiler
  helpers). Deep game access covers a transpiler only because what it can change is bounded to the game
  method it rewrites
- starts other programs: `Process.Start`, except opening a fixed web address, or a folder the
  same method has just created with `Directory.CreateDirectory` in its own or the game's folders
  (whose name has no extension)
- uses a deserializer that can create any type (`BinaryFormatter`, `NetDataContractSerializer`, ...)
- calls members by name at run time (`dynamic`, late binding)
- uses reflection the check cannot trace to the game's or its own code: a type name built at run
  time (outside `typeof(GameType).Assembly.GetType(...)`), or invoking, creating, reading or
  writing a member or type that does not come from a constant name, `typeof`, or a lookup on one
  (for example one found with `GetType()` on an object of an unknown type, or in a framework
  assembly's `GetTypes()`), an array or list of members into which something untraced was put,
  a `Type` or member parameter of a method that code outside the mod can call (or that the mod's own
  reflection can return: a lookup by its name, ignoring case, with a `*` prefix or by its property's
  or event's name, or one not narrowed to names; since policy 23 a lookup no longer reaches every
  method of the type), an
  `[UnsafeAccessor]`, a type found by name ignoring case or through a `Type.GetType` resolver
  (policy 19), or starts a COM component. A `GetMember`, `GetMembers` or `DeclaredMembers`
  lookup also finds nested types, so a name it is narrowed to reaches every member of the nested type
  of that name (policy 15). A default value given to `FirstOrDefault`, `SingleOrDefault`,
  `LastOrDefault` or `DefaultIfEmpty` is one of the values the result can be, and an array or list of
  members handed to framework, game or library code the check does not model (`Array.SetValue`,
  `IList.Add`, `Array.Copy`) can hold anything afterwards (policy 15). Harmony patch targets count as reflection: a
  `TargetMethod` or `TargetMethods` result or `Harmony.Patch` original that is not traced (an
  array, list or `yield return` iterator of traced members is traced), a Harmony attribute
  type defined by the mod (its constructor sets the target in code), and the operand of an
  instruction a transpiler makes or changes (`new CodeInstruction(op, operand)`, `operand = ...`,
  `CodeMatcher.SetOperandAndAdvance`, ...) that is neither traced nor an inert value (a number, a
  string, a label, a local, or another instruction's operand; a value that is a string on one path
  and something else on another is not inert). Harmony members whose arguments the check traces
  only at the mod's direct call (the patching API, `HarmonyMethod`, the patch attributes, the
  modelled `AccessTools` members, `Traverse`, the operand setters; `"atCall"` in the policy) count
  as untraced reflection when they are taken as a delegate or method handle, or reached by
  reflection (`GetMethod("Patch").Invoke`, `Activator.CreateInstance(typeof(CodeInstruction), ...)`)
  or a patch (policy 15)
- reaches by reflection, or patches with Harmony, a framework, game or trusted-library member that
  can reach any of the above: a prefix sees and can change the patched method's arguments, so a patch on
  `Process.Start`, or on a game method that starts whatever its caller names, starts programs. A
  patch class whose patch methods can only observe (a prefix, postfix or finalizer that returns
  nothing and takes only strings, numbers, `__originalMethod` or `__state`) passes nothing on from a
  game or trusted-library target; a transpiler on a game member that a policy exemption names gets
  the exempted capability back (the exemption assumes the game's own code runs there), and one on a
  game member that opens a fixed web address or a folder starts programs (policy 12)
- calls a trusted-library or game member that can reach any of the above, unless the policy
  exempts that member for that capability (each exemption is listed with its reason in
  [policy/policy.jsonc](policy/policy.jsonc); for example Harmony's patching API, whose code
  generation and native code are how patching works, and the game's own native bindings)
- connects to the internet and changes files in its own or the game's folders, where the mod
  loader finds code (any DLL in a mod folder, `mod.toml`, `*.deps.json`, the game's mod
  manifest), or in places the check cannot place outside them. The check does not prove the
  written bytes came from the network; the pair is enough to install code for the next launch

### Couldn't be fully checked

The mod:

- contains code, a file or an archive the check cannot read, or ships a script or installer; an
  archive counts as unreadable when extraction refused any of its entries (absolute paths, `..`,
  links, devices, names Windows does not allow, two names that are one file ignoring case)
- embeds a program, library or archive as a resource: recognized by its leading bytes (PE,
  ELF, Mach-O, zip, gzip, 7z, RAR, xz, zstd, LZ4, bzip2, cabinet, tar), by a PE header anywhere
  in the resource, or by a bundler's name (Costura.Fody's `costura.*.dll.compressed`, `*.dll`);
  a resource linked from a separate file counts too
- reads its own embedded data and writes files where the game loads code from, or to places the
  check cannot place outside the game's code folders: an embedded binary the check cannot
  recognize (compressed or encrypted) has to be written out this way
- ships a file named like a .NET, game or trusted-library assembly that is not the trusted copy
  itself: references to that name load the other assembly, not the file the check read
- uses a part of .NET the policy does not classify (every framework member must match a
  capability rule or the policy's `safe` list), directly or by reflection on a framework type
- calls code that was not analyzed: an assembly that is not one of the mod's files, a trusted
  library, the game, or the .NET framework (for example another mod it depends on, or a game
  assembly the current game no longer ships), or a trusted library without a profile for every
  trusted version. This includes reflection on a type of such an assembly
  (`Type.GetType("Some.Type, OtherMod")`), or a type found by name that none of them has, unless
  the name has no assembly part and the result is only tested for null (`AccessTools.TypeByName("Other.Mod")
  != null`, a check whether another mod is installed: nothing is loaded or run; policy 29)
- calls game code that this game version does not have: an assembly named like the game's (`KSA`,
  `Brutal.*`, `Planet.*`) that the game build the check is run against does not have at all, usually
  a mod built for another game version (policy 29)
- lists a file that was not analyzed (for example one whose hash changed after extraction)

**Labels**, shown in every tier (the complete list in Limited access, what the check saw in
Full access):

| Label | What it covers |
|---|---|
| Changes how the game works | patches game code (Harmony, including `[HarmonyPatch]` attributes, MonoMod, Mono.Cecil) |
| Connects to the internet | any network or pipe connection (not IP addresses or endpoints as values), including XML loaded from a path whose beginning the check cannot trace (it can be a web address) |
| Changes game saves | file writes traced to the game's save folder |
| Changes files in its own or the game's folders | file writes or deletes traced to the mod's folder or the game's folders, where the loader finds mod code and settings |
| Changes files outside the game | file writes or deletes not traced to the mod's or the game's folders (including through a file method taken as a delegate, or a Harmony patch on one) |
| Reads files outside the game | file reads not traced to the mod's or the game's folders |
| Reads information about you and your computer | user and computer name, environment variables, running programs, the Windows registry, the certificate store and persisted keys, the computer's network interfaces and connections, its drives (`DriveInfo`) |
| Changes system settings | writes to the Windows registry, permanent environment variables, the certificate store, persisted keys |
| Closes other programs | `Process.Kill` |
| Communicates with other programs on your computer | named `Mutex`, `Semaphore` and `EventWaitHandle` objects (created or opened by name), which every program of the user shares: a signal to a cooperating program, or one that holds another program's (policy 29; unnamed ones are the game's own) |
| Opens websites in your browser | `Process.Start` with a fixed `http(s)` address |
| Opens its own or the game's folders | `Process.Start` of a folder the same method has just created with `Directory.CreateDirectory`, traced to the mod's or the game's folders, whose name has no extension |
| Uses your clipboard | clipboard get/set |
| Uses connected devices | serial ports |

Cryptography, compression, threads, reflection on known types, locating standard folders and
process-only environment variables are recorded but carry no label and do not affect the tier.

## How it works

`darkmatter` reads each assembly once and records, per method: referenced capabilities,
reflection targets, calls, field reads and writes, and where file paths come from. Every
decision is then made from that one model, using the rules in
[policy/policy.jsonc](policy/policy.jsonc).

1. **Capabilities.** Each member reference in the IL is matched against the policy's rules;
   the most specific (longest) pattern wins.
2. **Nothing unaccounted for.** Every reference into another assembly is resolved by assembly
   name: one of the mod's own files (analyzed with it), a trusted library, the game (the game
   profile's assembly list, else the policy's `game.assemblies` patterns), or the .NET shared
   framework the tool runs on. A framework member that matches no capability or `safe` rule,
   and any reference to an assembly that is none of these, means Full access (couldn't be fully checked). Members are
   classified by the policy, not derived from the framework's code. A reference that names one of the
   mod's own types for a member neither it nor its base types in the mod define (hand-written
   metadata: the runtime then runs what the type inherits from another assembly) counts as not
   analyzed too (policy 22), and so does one whose signature differs from every member of that name
   there (policy 31: the runtime matches name and signature, so `Kill()` named through a type that
   derives from `Process` and declares only `Kill(int)` runs `Process.Kill`). Signatures are compared
   type by type (policy 32): a merged assembly can name `System.Exception` through `mscorlib` in a
   definition and through `netstandard` in a reference to it, and that is still the mod's own member.
3. **Reflection.** Constant strings, integers and `typeof` tokens are tracked through the stack
   and locals. A type resolved from a constant (`Type.GetType("System.Net.Http.HttpClient")`)
   gets the capabilities of that type and all its members by the policy's rules. Where the type
   lives decides the rest, as for a typeof: its assembly qualifier, or for a name without one, the
   calling assembly and the core library (`Type.GetType`) or any assembly with a type of that
   name (`AccessTools.TypeByName`). Members reached on a framework type must be classified; on a
   game type they get the game-API map's capabilities of the members reached (by a constant
   member name, else the whole type); on a trusted-library type its profile; anywhere else it is
   code that was not analyzed. On a type of the mod's own, a lookup (or a Harmony patch named through
   it) also reaches what the type inherits from its first base type outside the mod, by these same
   rules for that base type; a name only the mod's types have is theirs (policy 25; before, nothing),
   except an indexer's, which `AccessTools.Indexer` finds by its parameters (policy 26). A type nested
   in the looked-up type, the mod's or the game's, is searched with what it inherits too, since a nested
   type found from a type counts as that type (policy 26).
   A type name that is not a constant at the call is unresolved and
   means Full access, and so is one looked up ignoring case or through a `Type.GetType` type or
   assembly resolver (policy 19). A member name matches ignoring case (`BindingFlags.IgnoreCase`,
   flags that are not a constant, and the by-name expression factories find a member under any
   spelling), and a name ending in `*` is a prefix, as `GetMember` reads it (policy 19).
   `Delegate.CreateDelegate(Type, Type, "name")` and the expression factories that take a
   `System.Type` and a name (`Expression.Call(typeof(T), "name", ...)`, `Expression.Property(e,
   typeof(T), "name")`) look the member up by name on that type, like `GetMethod`. Reflection on
   a type of the mod's own reaches the types nested in it, since a nested type found with
   `GetNestedType` or `GetMember` counts as the type it was found from. Members looked up on a resolved type
   (`GetMethod`, `AccessTools.Field`, ...) carry that type, and `Invoke`, `GetValue`,
   `SetValue`, `CreateDelegate`, `Activator.CreateInstance(Type)`, Harmony patch methods,
   expression-tree factories (`Expression.Call`, `Field`, `Property`, `New`, ...) and similar
   calls must act on such a member or type, or they are Full access too. A type created by name
   (`Assembly.CreateInstance("T")`, `Activator.CreateInstance("Asm", "T")`) reaches its
   constructors (policy 30). Arrays and lists from
   plural lookups (`GetMethods`, `GetProperties`, `AccessTools.GetDeclaredFields`, ...) are
   followed within the method that made them: each element (`foreach`, indexing, LINQ `First`,
   `Where`, `ToList`, ...) is a member of the looked-up type, which granted all of that type's
   capabilities, until something untraced is put into the array or list or it is passed to code
   the check does not follow. When every element is taken out by a LINQ `First`, `Single`, `Last`,
   `Any`, `All` or `Count` whose lambda the check proves requires a constant name
   (`m => m.Name == "Draw" && ...`), the lookup reaches only the members of that name. A type or member kept in a field (or an array of them), passed as
   an argument, or returned by a method of the mod is traced through every write to that field,
   every call, every `return` in the mod; a field that is also assigned something else, that
   other assemblies can assign, or whose type has fields written through reflection, a parameter
   of a method that code outside the mod can call (public on a visible type, virtual, a Harmony
   patch method, one with attributes a loader looks for, one taken as a delegate or reached by
   the mod's own reflection, a static method implementing a static abstract or static virtual
   interface member, which generic code calls through a type parameter: policy 25), and the result of a method that can be overridden, are not traced.
   A method handed to Harmony by name (`new HarmonyMethod(type, name)`) counts as reached by
   reflection like `AccessTools.Method(type, name)` (policy 35): Harmony calls it with the patched
   method's arguments, so its parameters are not traced from the mod's own calls alone.
   A member name passed as a string parameter is traced from every call too. Harmony's
   `TargetMethods` may return an array or list of traced members or `yield return` them. A
   compiled expression tree built only from traced members (parameters, constants, conversions,
   calls, member access, constructors, assignments, blocks, lambdas) runs only those members and
   is not code generation. A member of the run-time type of an object of a declared game or mod
   type, and a type of a game or mod assembly found by a name built at run time, are bounded:
   deep game access, not system access. A lookup on such a run-time type also reaches the same
   members of every game type deriving from the declared one, by base type or interface (policy 35).
   **Typed reads (policy 35).** A field, property or method found by a constant name on exactly a
   resolved type (not on a run-time type) carries its declared type when every member of that kind the
   name can find there and on the base types, in any casing, is declared as the same class or struct of
   the mod's own assembly or of the game (the game-API map records the declared types of the game's
   members). Its `FieldType`, `PropertyType` or `ReturnType` is then exactly that type, and a value read
   with `FieldInfo.GetValue` or `PropertyInfo.GetValue` through it is of that type or one derived from it
   (a property's only when its getter returns that type), also through a member kept in a field,
   parameter or return value. A Harmony prefix, postfix or finalizer whose `__instance` is declared as
   `object` gets an instance of the patched type or one derived from it, when its attributes name that
   type by `typeof` and the type alone declares the patched method, the class has no `TargetMethod(s)`,
   `[HarmonyPatchAll]` or `[HarmonyArgument]`, and the mod's own code does not call the patch method,
   take it as a delegate, reach it by reflection (`new HarmonyMethod(type, name)` included) or store into
   the parameter. Anything else stays untraced. Tracking resets at every branch target and exception handler,
   except that a local's type or member is traced from all its stores (and when they differ, as
   one of them).
4. **Libraries by hash, not by name.** A file is trusted only if its SHA-256 is on the
   allowlist. A file that uses a trusted library's assembly name with an unknown hash is
   analyzed as mod code and flagged. Every other bundled file is analyzed with the mod, so a
   capability inside a bundled library is part of the mod's result.
5. **Trusted-library profiles.** `darkmatter profile --library` analyzes the trusted files
   themselves (all versions together, keyed by SHA-256) and records, for every member, the
   capabilities and findings it can reach: through its callees, the overrides a virtual call can
   dispatch to, and its type's static constructor. A mod calling a trusted member gets that
   member's profile, Full-access capabilities included, merged over every trusted
   version (the loader decides which copy is loaded). A call into a library with an unprofiled
   version, or to a member no profiled version has, counts as code that was not analyzed. The policy's
   `libraries.exempt` lists the members whose capability is the library's own job and is
   accounted for at the mod (Harmony's patching and reflection helpers), with a reason each.
   A trusted library's attribute on a mod's type or method counts as a call to its constructor.
6. **File access by path origin.** The path operand of each file operation is traced through
   the values it is built from (`Path.Combine`, concatenation, interpolated strings, file-system
   objects) to the APIs and literals it comes from: the mod's folder, the game's folders and
   saves, user folders, environment variables, absolute paths and web addresses. Arguments are
   traced to every analyzed call, fields to every store, results to every value returned. A part
   of a path that cannot be traced (an argument of a method no analyzed code calls, a field other
   code can assign, a virtual method's result, a literal with a `..` segment) counts as outside
   the game; so does an argument of a method that code outside the mod can call (a public or
   attributed method, a Harmony patch method), next to what the mod's own calls pass (policy 16).
   Parts joined end to end (`string.Concat`, interpolated strings) that can make a `..` segment
   together, and edits that can make one (`Substring`, `Remove`, `Insert`, most `Replace` and
   `Trim` calls, a file name without its extension), are untraced. In an interpolated string, a
   value that is not a string, a number, a boolean, a GUID or one of the mod's own enums (a char,
   a type with its own `ToString`, anything with a custom format) is untraced, and so is the whole
   text of a handler given a format provider or whose address is used for anything but its own
   members. The Documents folder itself followed directly by `My Games/Kitten Space Agency` (in
   that order and case) is the game's folder; anything else in Documents, and anything under an
   environment variable, is outside the game. Writes into the mod's or
   the game's folders are labelled, because that is where the loader finds code; the policy's
   `fullAccessCombinations` make such a write (or one outside the game) Full access together
   with a network connection. The game's own writes there, reached through the game-API map,
   are not labelled. An XML load (which also takes a web address) whose path begins with a folder
   the check traced is a file read, whatever is appended to it; one whose beginning is not traced
   can be a web address.
7. **Harmony patches by attribute.** `[HarmonyPatch]` and `[HarmonyDelegate]` values are decoded
   from the metadata (every constructor Harmony has: a type, a method name, a type name, a
   `MethodType`, which names the member as Harmony finds it: a getter or setter without a name is the
   indexer's accessor, a finalizer `Finalize`, an operator kind the type's `op_` methods, policy 24;
   `[HarmonyPatchAll]` means every method of the type), merged with the class's
   and its base classes' attributes as Harmony merges them (it reads them with `inherit: true`).
   A patch class whose base class is in another assembly is reflection the check cannot trace. A target in the
   framework gets that type's capabilities, as reflection on a constant type name does; a game
   target gets the capabilities of the patched member in the game-API map that raise the tier (its
   labels too for a reverse patch or a delegate, which run the target's code); a trusted-library
   target gets its library profile; a target anywhere else is code that was not analyzed.
   Patches on game members otherwise only add "Changes how the game works", and a patch class
   whose patch methods can only observe its target passes nothing of a game or trusted-library
   target on. Transpilers on the game's code are deep game access ("Rewrites the game's code ..."), not
   code generation: `OpCodes` and `Label` values are data, and what an instruction refers to is a
   reflection sink. A transpiler on any other target, or on one the check cannot place, is Full
   access ("Rewrites code other than the game's ...", policy 12).
   The framework and Harmony semantics the check models by name (reflection lookups and sinks,
   collections and LINQ, name filters, path sources and combiners, interpolated strings,
   `ProcessStartInfo`, the folder a method creates, clean expression trees, the parameter types
   that make a patch observing) apply only to members that live in the shared framework, the game
   (for the policy's game path sources) or 0Harmony (policy 12). A type that is only named like one
   (`System.Type` defined in a mod, or in an assembly the check did not analyze) is ordinary code.
   Since policy 17 the same holds for the other things the check recognized by name alone: the
   root base types (`System.Object`, ...) a patch class or an iterator derives from, the interfaces
   an iterator implements, an enum's `System.Enum` base, the `InlineArray` attribute and the
   `Unsafe`/`MemoryMarshal` calls of the compiler's inline-array helpers, a delegate type's
   constructor, the types an interpolated value is formatted as (a mod type named `System.Guid` has
   its own `ToString`), and the compiler attributes that do not make a method callable from outside.
   One of the mod's assemblies named `System...` is not the framework (what its methods are given is
   traced). A type found by name (`AccessTools.TypeByName`, `[HarmonyPatch("Type", "Method")]`)
   reaches every framework, game and trusted-library type of that name even when the mod defines
   one too (before, the mod's own type hid them). Type names in signatures (`System.Type`,
   `System.String`, `FileInfo` parameters and fields) are still matched by name: they only decide
   what is traced, and a same-named type adds tracing.
8. **Manifest resources.** Every embedded resource is read (never unpacked or loaded) and must
   look like data; see "Couldn't be fully checked" for what counts as an embedded binary. Analyzing an
   embedded assembly as part of the mod is not done yet: it is Full access.
9. **Compiler-generated code.** Collection expressions and `params` spans compile to helpers
   that use `Unsafe`. Those helpers are exempt only when their IL matches the compiler's
   template and each call passes a matching inline-array type and an in-range constant. The
   inline-array type is the mod's own, one of the framework's `InlineArrayN<T>`, or (policy 34) one
   of the game's, whose length and element type the game-API map records from the game build.
10. **Game-API map.** `darkmatter profile` derives, from the game's own assemblies, which labels
   and which capabilities that raise the tier each game method (public or not) leads to, for example
   `GameSaves.MakeSave` changes game saves, and a method that starts whatever its caller names
   starts other programs. A mod calling that method gets them. The policy's `game.exempt` lists
   what the game does on its own account (its native bindings and raw memory use, reading its
   own version), with reasons. The map holds the game's assembly names (the .NET runtime the
   game ships is skipped), type, method and field names, capability tags and one example each,
   and (format 7, policy 35) the declared type of every field, property and method's return, and the
   interfaces of each type, for typed reflection reads and derived types (see 3).
   A game method missing from the map was read and reaches nothing the policy counts. What was not
   read never reads that way (policy 21): a game method whose body cannot be decoded, and every game
   method that can reach it, is "not analyzed"; a call into a game assembly to a member neither the
   type named nor its base types define (one a mod's other game build has) is not analyzed either
   (one a base type defines is that member, policy 22); a game file
   that cannot be read is listed as skipped and is not a game assembly, so calls into it are not
   analyzed (the pipeline does not keep such a profile and scans its results again next run).
11. **Fail closed.** Undecodable IL, unreadable files, unextractable archives and files whose
   hash changed since extraction are reported and count as Full access. No blind spot leaves a
   mod in No code or Limited access. A game or library profile made by an older tool or with
   a different policy is refused.

The trusted-library allowlist is built from the content index's snapshot, which carries the
stamped releases of
[content-index-releases](https://github.com/KSAModding/content-index-releases). Each release
archive is verified against its stamped SHA-256, then expanded to per-file DLL hashes across
every release that is not yanked of each trust anchor (by default, listings of type `mod-loader`).
The file hashes in each result let a loader check, at load time, that it runs only the files that
were analyzed.

## Policy

[policy/policy.jsonc](policy/policy.jsonc) holds the capability rules, the label wording, the
tier names and summaries, the Full-access triggers in their three groups (the `fullAccess`
section, and `fullAccessCombinations`, each with its group) and the game-specific path sources.
It is embedded in the tool at build time; `--policy FILE` overrides it. The tool validates it on
load: every capability must be assigned to exactly one of a Full-access group, a label, file-path
tracing or the informational list, and every finding to exactly one Full-access group. Results are stamped with the tool version, the policy version and the
policy file's SHA-256, so a result can be reproduced.

## Requirements

- .NET 10 SDK, for the analyzer and the pipeline
- Python 3.9 or later, for the test harness (standard library only)
- Python 3.11 or later, only for the two old download scripts (see "The tools underneath")

## Usage

```sh
dotnet build src/DarkMatter -c Release -o out
dotnet build src/DarkMatter.Pipeline -c Release -o out
```

`darkmatter` is the analyzer. `darkmatter-pipeline` scans the content index or one mod: it
downloads, verifies and extracts release archives and runs the analyzer on them. They are
separate programs, and the pipeline runs the analyzer as its own process, so the process that
reads mod code never touches the network or writes files taken from an archive.

### Scan the content index

```sh
dotnet out/darkmatter-pipeline.dll scan index --game path/to/game
dotnet out/darkmatter-pipeline.dll report darkmatter-state/runs/<run>.json --out report.html
```

`scan index` reads the content index's snapshot
(`https://ksamodding.github.io/content-index-releases/v1/index.json`) and scans the newest
release of every listing: the newest stable one if the listing has one, else its newest of any
status, by semantic version. Yanked releases are skipped. Each release is identified by its
listing id, version and stamped archive SHA-256; its archive is downloaded from the stamped URL
(or a mirror the stamp lists) and verified against that hash before anything else. An archive
that cannot be fetched or does not match its stamp is reported as not scanned, never analyzed in
its place, and the run exits 1. So is a listing whose id cannot name a folder (a Windows device
name, a trailing dot, a separator or `..`, or a name extraction would rename) or that an earlier
listing already has ignoring case (the first is scanned), a release whose
download URL does not end in exactly one file name (a trailing `/`, or an encoded one), and a
listing whose archive cannot be read or extracted because of a file-system error, or that hits
any other error (the reason names the error's type): each fails on its own, nothing is stored for
it, and the other listings are scanned.

Everything is kept in a state folder (`--state DIR`, default `./darkmatter-state`): the
snapshot, verified archives by hash, extracted trees, the allowlist and trusted files, the game
and library profiles, one result per release (`results/<id>/<sha256>.json`) and one document per
run (`runs/`). The allowlist comes from the snapshot's mod loaders, and the profiles are made as
needed, so there is nothing to prepare but the game folder. A release whose stored result has the
current scan key (tool and pipeline versions and the SHA-256 of their assemblies, the .NET
runtime, policy, game DLLs, the allowlist's hashes and names, and the extraction limits) is not
scanned again: a second
run rescans nothing, and a change of policy, tool or pipeline build, game build or a loader
release rescans everything. A release whose download URL now names another file is scanned
again too (result paths start with that name). A result that may come from a passing problem of
the computer (a file-system error while extracting, a file the analyzer could not read) fails
closed as usual but is marked `retry` and scanned again by the next run. A stored result that
cannot be read (damaged, a duplicate key, no result or no tier) is not used: the release is
scanned again, and when it was the listing's last recorded result the change is reported with
nothing to compare (`"previous": "unreadable"`), not as unchanged. Cached profiles are checked
before they are used again (they parse, have the format `darkmatter version` reports and the
current policy's hash, and have every part the analyzer reads, not empty); one that fails is
deleted and made again with a warning, and the library profiles are made again with a new game
profile. A profile just made that fails the same check ends the run with an error. `--full`
rescans everything anyway and makes the profiles again. A `latest.json` that cannot be read is
moved aside (`latest.json.damaged-TIME`) with a warning, and that run reports every listing as new
(and cannot report a listing that has gone since, having no record of it);
`scan mod ID@VERSION` does not read it. When the snapshot cannot be downloaded, or the download is
not a usable snapshot, the copy an earlier run kept is used with a warning that it may be out of
date (a release yanked since then, a trust anchor included, is still treated as it was), and the
run document and stored results mark it (`snapshot.stale`); a download replaces that copy only
once it has been read as a snapshot. These checks catch damage, not edits: the state folder is trusted. Each mod's extracted files are limited to 4 GiB (`--max-extracted-bytes N`;
the stamp records the limits, and another limit is another key); a mod over the limit counts as
not extracted. The extracted trees are kept, so the state folder needs that much disk per large
mod (the largest in the index unpacks to about 2.2 GB). Keep the state folder outside any
version-controlled working tree you run tools in: extraction renames the names tools act on
(below), but a folder inside a repository is still part of it. Each run reports what changed for each listing since its last recorded result:
a new listing, a new release, or a rescan (a new key, `--full` or a retry) that changed the tier,
the labels, the reason groups or the reasons. One scan at a time can use a state folder (it holds
a lock file); a second one exits 1.

Output is text (`--format text`, the default: the counts, the changes, what was not scanned, and
the results of new and changed listings; `--all` for every listing, `-v` for evidence) or the run
document as JSON (`--format json`), which holds every result with every piece of evidence.
`report` renders a run document, or a results file of `darkmatter analyze --json`, as one
self-contained HTML page with no script, to share with people who do not run the tool. Every
string in it is HTML-encoded, with control and format characters (bidirectional overrides,
zero-width characters) shown as `\uXXXX` escapes as in the text output, and its
Content-Security-Policy allows no script and only the page's own style sheet (by hash): names and
evidence come from untrusted archives.

### Scan one mod

```sh
dotnet out/darkmatter-pipeline.dll scan mod StarMap --game path/to/game        # newest release
dotnet out/darkmatter-pipeline.dll scan mod StarMap@0.5.2 --game path/to/game  # a given version
dotnet out/darkmatter-pipeline.dll scan mod path/to/MyMod --game path/to/game  # a local folder, zip or DLLs
```

A listing id is scanned like a listing of the index (a yanked version is refused). Local files,
such as a build before release, are copied or extracted with the same rules as an archive; they
have no stamp, so they are identified by their files' hashes and their result is not stored.

### Results

Each result has the mod's tier, its labels, and its Full-access reasons in their groups. Labels
and reasons carry a stable id next to their text, and every piece of evidence behind them,
sorted, with the count. File paths are relative to the release's archive, as extracted: a
component renamed by extraction (below) appears renamed, for example `MyMod/_dm_.git/x.dll`. Text output shows the
first 20 lines of evidence per label or reason, the HTML report the first 100; the JSON has all
of them.

### The tools underneath

```sh
dotnet out/darkmatter-pipeline.dll build-allowlist --out allowlist.json --library-dir libraries/
dotnet out/darkmatter.dll profile --out game-api-profile.json path/to/game/*.dll
dotnet out/darkmatter.dll profile --library --allowlist allowlist.json --game-profile game-api-profile.json \
    --out library-profiles.json libraries/*/*
dotnet out/darkmatter.dll analyze --allowlist allowlist.json --library-profile library-profiles.json \
    --game-profile game-api-profile.json --name MyMod path/to/mod/*.dll
```

`scan` runs these itself. `build-allowlist` writes the allowlist alone, and `--library-dir`
writes every trusted file to `libraries/<sha256>/`; `profile --library` profiles them (only files
whose hash is on the allowlist). Without `--library-profile`, every call into a trusted library
counts as code that was not analyzed. Profiles record the policy they were made with, and one
made with another policy is refused. `analyze` takes `-v` for the evidence, `--json FILE` for
machine-readable results, `--facts FILE` for the per-file analysis facts (what the analyzer
observed before the policy was applied, for detection work), `--manifest FILE` for several mods,
and `@listfile` inputs, one path per line. `darkmatter version` prints the stamp results carry, and the profile format
(`profileFormat`) this build writes.

`extract DOWNLOADS EXTRACTED --manifest FILE` unpacks zip, tar and tar.gz archives, nested ones up
to `--max-depth` levels, and writes the manifest that groups code files into mods; `scan` uses the
same extraction. Archives are untrusted: entries with absolute paths, `..`, links, devices or names
that collide ignoring case are never written, the size limit counts bytes actually written
(4 GiB per mod by default; the counted bytes, the file count and the nesting depth are what stop
archive bombs), and any archive that could not be extracted completely is listed as unextracted,
which the analyzer reports as Full access. A path component named like a version-control, editor
or coding-agent folder or file (`.git`, as a folder or a file, `.gitmodules`, `.gitattributes`,
`.hg`, `.svn`, `.bzr`, `.jj`, `.vscode`, `.idea`, `.cursor`, `.cursorrules`, `.claude`, `CLAUDE.md`,
`CLAUDE.local.md`, `AGENTS.md`, `AGENTS.override.md`, `.gemini`, `GEMINI.md`, `.mcp.json`;
ignoring case (a dotless i counts as i, as on NTFS), Unicode normalization and zero-width
characters) is written with the prefix `_dm_` (`.git/config` becomes `_dm_.git/config`), with a
warning once per name and mod: git, editors and coding agents run in or reading an extracted tree
would otherwise take these as their repository, hooks, tasks or instructions. Every other rule
applies to the renamed name, and one that then collides with another entry (an archive with both
`.git/x` and `_dm_.git/x`) makes the archive unextracted. The analyzer never looks at folder names,
so the rename changes only the paths a report shows. `compare-results` prints the counts of the
three tiers, of labels and of Full-access reasons by group, the mods whose tier changed, and the
Full-access mods whose reason groups changed (it also reads results from before policy 13, which
had four tiers);
`rank-unclassified FACTS.json --manifest manifest.json` ranks the framework members the policy
does not classify, from `analyze --facts`. Run `dotnet out/darkmatter-pipeline.dll help` for
every option.

`scan`'s downloads (the snapshot and the archives, over HTTPS with .NET) have not yet run against
the live index: .NET could not open TLS connections in the sandbox the code was written in. A full
index scan has run with the archives fetched by another client and put in the state folder's
`archives/`, where `scan` verifies each one against its stamp before use. Until `scan` has
downloaded on its own once, `scripts/fetch_releases.py` and `scripts/build_allowlist.py` (the
old GitHub-API path, feeding `extract` and `analyze --manifest`) stay as a fallback.

### Game-API map

```sh
dotnet out/darkmatter.dll profile --out game-api-profile.json path/to/game/*.dll
dotnet out/darkmatter.dll analyze --game-profile game-api-profile.json --allowlist allowlist.json path/to/mod/*.dll
```

The map is derived from proprietary assemblies, so it is generated locally and never committed.
The tracked policy names game members only (in `game.exempt`), never game code. Besides methods and
capability tags it holds the game's assembly, type and member names, each type's base type,
(format 6, policy 34) the game's `[InlineArray]` types with their length and element type, so a
mod's compiler-generated helper over one of them can be checked against the game's own layout, and
(format 7, policy 35) the declared type of each member and the interfaces of each type (type names
only), so a value a mod reads by reflection from a game member can be typed.

## Layout

| Path | Purpose |
|---|---|
| `policy/policy.jsonc` | capability rules, labels, tiers, Full-access triggers and their groups, path sources |
| `src/DarkMatter/Analysis/` | single pass over each assembly: IL decoding, capabilities, reflection, calls, fields, path sources |
| `src/DarkMatter/Evaluation/` | file-path origin tracing, reach propagation, tiers and labels per mod, the game-API map, trusted-library profiles |
| `src/DarkMatter/Cli/` | command line: options, inputs, text and JSON output |
| `src/DarkMatter/Policy.cs` | policy loading, validation and rule matching |
| `src/DarkMatter.Pipeline/Scan/` | `scan`: release selection, stored results by release and scan key, the analyzer process, changes, text output |
| `src/DarkMatter.Pipeline/Report/` | `report`: the HTML report |
| `src/DarkMatter.Pipeline/Extract/` | `extract`: archive detection, entry name checks, zip and tar extraction into a claimed tree, the manifest |
| `src/DarkMatter.Pipeline/Index/` | the index snapshot, archives verified against their stamp, `build-allowlist`, HTTPS with retries |
| `src/DarkMatter.Pipeline/Results/` | `compare-results`, `rank-unclassified` |
| `scripts/test_fixtures.py` | build the fixtures and check the analyzer, extraction and scans against them |
| `scripts/fetch_releases.py`, `scripts/build_allowlist.py` | the old GitHub-API download path, a fallback until `scan` has downloaded from the live index once |
| `fixtures/` | minimal assemblies for each case |

## Testing

```sh
python3 scripts/test_fixtures.py
```

Builds the analyzer and every fixture and checks tiers, labels, evidence, allowlist handling,
the game-API map, fail-closed behaviour, policy validation, archive extraction safety
(`darkmatter-pipeline extract` on hostile archives), scans of a small offline snapshot (release
selection, stored results, changes, archives that do not match their stamp), the HTML report's
encoding, and the result tools.

Everything is built in one incremental MSBuild run into each project's own `bin/` and `obj/`, so
a run after a small change recompiles only what changed (`--rebuild` starts from scratch). The
checks are grouped and the groups run in parallel. While working on one area, run only its
groups, and run everything before committing:

```sh
python3 scripts/test_fixtures.py --list                     # group names
python3 scripts/test_fixtures.py --only evasion,harmony-patch
```

A filtered run ends by saying how many groups it skipped. The harness turns off the C# compiler
server (`UseSharedCompilation=false`). In sandboxes that block its pipe, every compile otherwise
waits for the connection to time out.

## Development

`DarkMatter.slnx` contains the analyzer, the pipeline and every fixture; `global.json` pins the
.NET 10 SDK band. Code under `src/` builds with nullable reference types, the recommended .NET
analyzers and code-style enforcement, with warnings treated as errors
(`src/Directory.Build.props`). Fixtures are exempt: they contain code written to be flagged.
Formatting follows `.editorconfig`:

```sh
dotnet format src/DarkMatter/DarkMatter.csproj --verify-no-changes
dotnet format src/DarkMatter.Pipeline/DarkMatter.Pipeline.csproj --verify-no-changes
```

## Known gaps

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
  groups explain the tier" above. (Parts of .NET the policy does not classify and calls into code
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
  ship, and that is not trusted, the game or the framework, makes the mod Full access
  (couldn't be fully checked), whatever that other mod's own tier is (Limited access or Full
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
  game build and must be reviewed again (the profile prints how many members reach a Full-access
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
  which is Full access. Game exemptions that cover a whole namespace (the engine's native and
  memory code) still apply to a method a transpiler rewrites. MonoMod IL manipulation (`ILContext`,
  `ILCursor`) is not modelled: its members carry their library profile, which is Full access.
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
  the cached form was also Full access: the member array on the stack at the branch the compiler's
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
- **Some memory-safe compiler output still counts as raw memory** (it fails toward Full access):
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
  reaches, is untraced (Full access), even when every caller in the mod passes a traced member.
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
  one type (policy 35, see "How it works"); a value returned by `Invoke`, a member found on a run-time
  type, in an array or list, or by a name that is not a constant, a member of a trusted library or of
  another of the mod's assemblies, and a plain `object` parameter (not typed from what its callers
  pass, even when only the mod's own code calls the method) are not typed, and `typeof(X).FullName` is not folded to a constant name. Reflection on such a value is
  untraced (Full access), which over-reports. The type is not carried through a call that returns
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
  naming a framework assembly there counts as a part of .NET the check does not classify (Full
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
  same test written another way (stored to a local first, `?.`), so it errs toward Full access.
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
  memory, not native code. Both are Full access; only the group differs.
- **Overloads share a node** in the call model, which can over-label file access.
- **Only a fixed list of tool names is renamed on extraction** (`.git`, `.vscode`, `CLAUDE.md`
  and the others under "The tools underneath"). Configuration of other tools (`.envrc`, `_darcs`,
  `.vs`, `.windsurfrules`, `.clinerules` and other editors' and agents' folders) is written as it is, so do not run such tools in
  the state folder; the tier is not affected either way. Renaming also does not stop git from taking a
  folder laid out as a bare repository (`HEAD`, `objects`, `refs`, `config`; `_dm_.git` itself is one)
  as a repository when git runs inside it: do not run git below `extracted/`, or set
  `safe.bareRepository=explicit`.
- **7z, RAR, xz, bzip2, zstd, LZ4 and cabinet archives** are recognized but not extracted, and
  count as Full access; so do zip entries compressed with a method other than stored, deflate or
  deflate64.
- **Embedded resources are recognized, not analyzed.** A program, library or archive embedded as
  a resource is Full access even when it is a harmless managed library (analyzing it in memory
  and checking it against the allowlist is not done yet). A payload with no recognizable bytes
  (compressed with deflate or brotli under a name no bundler uses, encrypted, hidden in other
  data) is not found; reading the assembly's own resources together with a write into the mod's
  or the game's folders, or outside the game, is Full access for that reason.
- **Code-folder writes are a pair of capabilities, not a data flow.** A network connection plus a
  write into the mod's or the game's folders (or a write the check cannot place) is Full access
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
  framework, game and Harmony semantics only to members that come from those assemblies (see "How
  it works", item 7), but no fixture yet defines a type named like a framework type (`System.Type`,
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
    versions and file names. Archives the check cannot extract are Full access, and a mismatched
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

## License

MIT. See [LICENSE](LICENSE).
