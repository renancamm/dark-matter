# How it works

`darkmatter` reads each assembly once and records, per method: referenced capabilities,
reflection targets, calls, field reads and writes, and where file paths come from. Every
decision is then made from that one model, using the rules in
[policy/policy.jsonc](../policy/policy.jsonc).

1. **Capabilities.** Each member reference in the IL is matched against the policy's rules;
   the most specific (longest) pattern wins.
2. **Nothing unaccounted for.** Every reference into another assembly is resolved by assembly
   name: one of the mod's own files (analyzed with it), a trusted library, the game (the game
   profile's assembly list, else the policy's `game.assemblies` patterns), or the .NET shared
   framework the tool runs on. A framework member that matches no capability or `safe` rule,
   and any reference to an assembly that is none of these, means Broad access (couldn't be fully checked). Members are
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
   means Broad access, and so is one looked up ignoring case or through a `Type.GetType` type or
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
   calls must act on such a member or type, or they are Broad access too. A type created by name
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
   type is bounded: the label "Uses the game's internals by reflection" (policy 38), not system
   access. A type of a game or mod assembly found by a name built at run time is deep game access. A lookup on such a run-time type also reaches the same
   members of every game type deriving from the declared one, by base type or interface (policy 35).
   A value read by reflection and kept in a local declared as `object` is followed across a
   branch (policy 40), so the null-conditional form `value?.GetType().GetMethod(...)` is traced.
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
   take it as a delegate, reach it by reflection or store into the parameter. A patch applied in code
   (policy 42) bounds it the same way: `harmony.Patch(original, postfix: new HarmonyMethod(typeof(X),
   "Name"))`, with the HarmonyMethod made inside that call and the original a method found by a constant
   name on one type, which that type alone declares. A HarmonyMethod kept anywhere else is a lookup like
   any other, which reaches the patch method by reflection. The HarmonyMethod may wait in a local that
   holds nothing else and is loaded only into that call (policy 44). Harmony fills such a patch method's
   other parameters by name, so one declared as `object` and named `__result`, `__N` or like a parameter
   of the original is an object of the type the original declares there (policy 43), when every overload
   agrees on it and no attribute can rename it. Neither bound holds when a method of the mod that Harmony
   may call takes the same value by reference, because Harmony does not compare the types (policy 44). A parameter declared as `object` of a method
   that nothing outside the mod can call (not public on a visible type, not virtual, not a patch method,
   not used as a delegate or reached by reflection) holds what the mod's calls pass (policy 42): an object
   of the type each argument is declared as, or of a type derived from it. Anything else stays untraced. Tracking resets at every branch target and exception handler,
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
   member's profile, Broad-access capabilities included, merged over every trusted
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
   `broadAccessCombinations` make such a write (or one outside the game) Broad access together
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
   target on. A pointer a game member returns is followed while it is only passed on and read
   through (policy 39, see [Tiers and labels](tiers-and-labels.md)). Transpilers on the game's code are the label "Rewrites parts of the game's code"
   (policy 38), not code generation: `OpCodes` and `Label` values are data (except `Calli`, native
   code, and the memory opcodes, raw memory), and what an instruction refers to is a reflection sink. A transpiler on any other target, or on one the check cannot place, is Broad
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
   look like data; see ["Couldn't be fully checked"](tiers-and-labels.md#couldnt-be-fully-checked) for what counts as an embedded binary. Analyzing an
   embedded assembly as part of the mod is not done yet: it is Broad access.
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
   interfaces of each type, for typed reflection reads and derived types (see 3). Format 8 (policy 43)
   adds the declared type of each method's parameters where it is a class or struct, by name and by index,
   and the index of each of those names.
   A game method missing from the map was read and reaches nothing the policy counts. What was not
   read never reads that way (policy 21): a game method whose body cannot be decoded, and every game
   method that can reach it, is "not analyzed"; a call into a game assembly to a member neither the
   type named nor its base types define (one a mod's other game build has) is not analyzed either
   (one a base type defines is that member, policy 22), unless another game build given to the
   check defines it: the call then reaches what that build's map lists (policy 37); a game file
   that cannot be read is listed as skipped and is not a game assembly, so calls into it are not
   analyzed (the pipeline does not keep such a profile and scans its results again next run).
11. **Fail closed.** Undecodable IL, unreadable files, unextractable archives and files whose
   hash changed since extraction are reported and count as Broad access. No blind spot leaves a
   mod in No code or Limited access. A game or library profile made by an older tool or with
   a different policy is refused.

The trusted-library allowlist is built from the content index's snapshot, which carries the
stamped releases of
[content-index-releases](https://github.com/KSAModding/content-index-releases). Each release
archive is verified against its stamped SHA-256, then expanded to per-file DLL hashes across
every release that is not yanked of each trust anchor (by default, listings of type `mod-loader`).
The file hashes in each result let a loader check, at load time, that it runs only the files that
were analyzed.

## The policy

[policy/policy.jsonc](../policy/policy.jsonc) holds the capability rules, the label wording, the
tier names and summaries, the Broad-access triggers in their three groups (the `broadAccess`
section, and `broadAccessCombinations`, each with its group) and the game-specific path sources.
It is embedded in the tool at build time; `--policy FILE` overrides it. The tool validates it on
load: every capability must be assigned to exactly one of a Broad-access group, a label, file-path
tracing or the informational list, and every finding to exactly one Broad-access group. Results are stamped with the tool version, the policy version and the
policy file's SHA-256, so a result can be reproduced.
