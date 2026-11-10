# Tiers and labels

The complete criteria for each tier, each Broad-access group and each label. The short version is in
the [README](../README.md#tiers-and-labels).

A tier states what a mod can do, as far as the check can account for it. It is not a judgement
of whether the mod is harmful, and it says what the mod *can* do, not what it does.

| Tier | Shown to players | Meaning |
|---|---|---|
| **No code** | Only adds content. It can't run programs. | Ships no code files: parts, planets, textures, sounds. |
| **Limited access** | It can only do what's listed. | Ships code, and everything it can run was looked at. The labels are the complete list. |
| **Broad access** | It can do anything a program on your computer can. | Something in the mod can reach beyond what the check can list, or the check could not look at all. The labels are what it saw, not a complete list. |

A mod's tier covers its own code. The result notes each mod it requires with that mod's own tier
(see [Usage](usage.md#dependencies)).

A Broad-access result says why, in one or more groups. Every group with a reason is listed, so a
mod whose reasons move from one group to another between releases stands out even though its
tier stays the same.

| Group | Shown to players | For example |
|---|---|---|
| **Deep game access** | Works with the game's code and memory directly, in ways the check can't follow all the way. | direct memory access, XML serializers, a game type chosen at run time |
| **System access** | Uses features that can reach anything on your computer. | native code, starting programs, loading code at run time |
| **Couldn't be fully checked** | Part of the mod couldn't be inspected. | an unreadable file, a script or installer, an embedded archive |

**The groups explain the tier; they are not a scale.** The claim is the tier: Broad access. Deep
game access means the check's blind spots for this mod are of a kind ordinary modding has, not
that the mod stays inside the game. Code the check cannot follow can still do anything, and a
determined author who knows the rules can aim for that group alone. Couldn't be fully checked
means the check does not know what a part does, not that it does anything; it is often a
packaging problem the author can fix. Only Limited access says the labels are complete.

Many widely used mods are Broad access (loaders, scripting bridges, physics mods, mods that use
native libraries). For those, trust rests on the author rather than on the check.

A reason reached through another member (a framework, game or trusted-library member the mod
calls, reaches by reflection or patches) is reported in that reason's group.

## Deep game access

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
  is pointer-heavy, so ordinary mods do this. Not counted (policy 39): a pointer to a named type that a
  game member returned, while the mod only keeps it in a local, passes it back to the game or to its
  own methods as the same pointer type (or to the game as a reference to that type), and reads fields
  of the type it points to. A write through it, arithmetic, a cast to another type, a `void*`, and a
  pointer that did not come from a game call still count (see [Known gaps](known-gaps.md)). Not counted (policy 27): the unsafe compile
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
- uses reflection on a game type chosen at run time (policy 38): a type found by a name built at run
  time in a game or mod assembly (`typeof(KSA.Program).Assembly.GetType(name)`). The check knows
  the assembly but not the type, so it cannot list what the type's members do
- reads or writes XML with `XmlSerializer` for a type: it creates objects of that type and of the
  types its fields, properties and attributes name, and sets their members, which the check does
  not follow (the type is chosen in the mod's code, not by the XML). This holds even when the check
  did not trace the type (a generic `typeof(T)`, a `Type` it is given: "Reads or writes XML into objects
  of a type chosen at run time", policy 15), which is then not bounded to the game's or the mod's
  code: see "XmlSerializer is deep game access" in [Known gaps](known-gaps.md)
- has the game read or write XML into objects of a type the mod chooses (policy 15): a call to a game
  member that makes an `XmlSerializer` for a type its caller gives it (`Load<T>`, `LoadAs(Type)`),
  with a type argument that is not the game's own or a `Type` or object argument, and reflection on
  or a patch of such a member. A call that gives it only the game's own types is not counted

## System access

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
  generation (see the label "Rewrites parts of the game's code")
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
  [policy/policy.jsonc](../policy/policy.jsonc); for example Harmony's patching API, whose code
  generation and native code are how patching works, and the game's own native bindings)
- connects to the internet and changes files in its own or the game's folders, where the mod
  loader finds code (any DLL in a mod folder, `mod.toml`, `*.deps.json`, the game's mod
  manifest), or in places the check cannot place outside them. The check does not prove the
  written bytes came from the network; the pair is enough to install code for the next launch.
  Making a folder and deleting a file or folder do not count for the pair (policy 41): they put
  nothing there

## Couldn't be fully checked

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
  a mod built for another game version (policy 29). Neither this nor a missing game member counts
  when the check is given another game build that has the assembly and defines the member
  (policy 37, see [Usage](usage.md#several-game-builds)): the call then reaches what that build's
  game code does, and the result names the build in a warning
- lists a file that was not analyzed (for example one whose hash changed after extraction)

**Labels**, shown in every tier (the complete list in Limited access, what the check saw in
Broad access):

| Label | What it covers |
|---|---|
| Changes how the game works | patches game code (Harmony, including `[HarmonyPatch]` attributes, MonoMod, Mono.Cecil) |
| Rewrites parts of the game's code | a Harmony transpiler on the game's code, and only the game's (policy 38; a Broad-access reason before): `CodeInstruction`, `CodeMatch`, `CodeMatcher`, `Transpilers`, an `ILGenerator`'s labels and locals, a method named `Transpiler` or marked `[HarmonyTranspiler]`, a method taking or returning Harmony instructions, a transpiler given to `Harmony.Patch`. The patched game method counts with everything it can do, and what the new instructions name is traced. An untraced operand, `OpCodes.Calli`, a memory opcode or a target that is not the game's code is a Broad-access reason |
| Uses the game's internals by reflection | reflection traced to a game or mod type and the types derived from it, without knowing the exact type (policy 38; a Broad-access reason before): a member of the run-time type of an object declared as such a type (`vehicle.GetType().GetField(...)`), a value read with `GetValue` through a member declared as such a type, a Harmony patch method's `__instance` declared as `object`, a member from a lookup after its array was passed to code the check does not follow. A member looked up by name counts with what members of that name can do on the type and on the game types deriving from it. A type used without a named member (an object created from it) counts with everything any of their members can do, unless the use only reads or writes a field |
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
