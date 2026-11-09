#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the fixtures and check the analyzer and the pipeline's extraction against them.

  test_fixtures.py [--only GROUP[,GROUP...]] [--list] [--jobs N] [--rebuild] [--keep]

Requires the .NET 10 SDK and Python 3.9 or later (standard library only). Exits non-zero if any
check fails.

The analyzer, the pipeline and every fixture are built in one MSBuild run, incrementally, into each
project's own bin/ and obj/ (gitignored): a run after a small change recompiles only what changed.
--rebuild builds everything from scratch. The compiler server is turned off (UseSharedCompilation):
where it cannot be reached, as in a sandbox, every compile waits for it to time out.

Checks are grouped (--list); groups run in parallel and report in a fixed order. --only runs the
named groups and the shared setup they need, and the summary says how many groups were skipped.
--keep leaves the temporary directory (profiles, results, test archives) in place for inspection.
"""
import argparse, base64, concurrent.futures, fcntl, glob, hashlib, html.parser, io, json, os, re, shutil, stat, subprocess, sys, tarfile, tempfile
import threading, time, traceback, xml.sax.saxutils, zipfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
failures = []

# Checks expected to fail until the hardening phase that fixes them lands. A pending check
# that fails is reported but does not fail the run; one that passes fails the run, so the
# entry gets removed and any later regression turns the suite red.
PENDING = set()

# Broad-access reason groups (policy "broadAccess").
DEEP, SYSTEM, UNCHECKED = "deep-game-access", "system-access", "not-fully-checked"

# Evasion fixtures (fixtures/evasion/cases/<case>.cs), each built into its own assembly.
# Expected result: a tier, or a label the mod must carry (or a list of both).
EVASION = {
    "EnumerateAndInvoke": ("tier", "broad-access"),
    "ViaGetType": ("tier", "broad-access"),
    "ViaGenericType": ("tier", "broad-access"),
    "DelegateByName": ("tier", "broad-access"),
    "UnsafeAccessor": ("tier", "broad-access"),
    "FieldUntracked": ("tier", "broad-access"),
    "FieldOpen": ("tier", "broad-access"),
    "FieldViaReflection": ("tier", "broad-access"),
    "HarmonyByRuntimeName": ("tier", "broad-access"),
    "HarmonyPatchMethod": ("tier", "broad-access"),
    "TraverseByRuntimeName": ("tier", "broad-access"),
    "Dyn": ("tier", "broad-access"),
    "Unzip": ("label", "Changes files outside the game"),
    "DeleteViaBase": ("label", "Changes files outside the game"),
    # Raw memory is deep game access as a whole since policy 9. Reading through an address the mod
    # is handed is a forged-address case: system access once raw memory is split (task R2).
    "Peek": [("tier", "broad-access"), ("group", (DEEP, "Reads or writes memory directly"))],
    "TypeNames": ("tier", "broad-access"),
    "TypeNamesNone": ("tier", "limited-access"),
    "ProvenInvoke": ("tier", "limited-access"),
    "ProvenField": ("tier", "limited-access"),
    "ProvenBranch": ("tier", "limited-access"),
    "HarmonyByName": [("tier", "limited-access"), ("label", "Connects to the internet")],
    "TraverseByName": ("tier", "limited-access"),
    "MethodGroupDelete": ("label", "Changes files outside the game"),
    # G2a (policy 15): a checked-at-the-call Harmony member reached another way; a LINQ default value.
    "PatchDelegate": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "PatchInvoke": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "DefaultFirst": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "DefaultIfEmpty": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    # G2b (policy 16): path labels. The game's folder in Documents only in order; interpolation handlers
    # cleared, branched, with a provider, passed by reference; values that are not path text; ".." made
    # of parts or by an edit. The two controls keep their one label.
    "GameNameInFile": [("tier", "limited-access"), ("labels", ["Changes files outside the game", "Reads information about you and your computer"])],
    "GameNameOutOfOrder": [("tier", "limited-access"), ("labels", ["Changes files outside the game"]),
                           ("evidence", ("Changes files outside the game", ["GameNameOutOfOrder::Below", "GameNameOutOfOrder::Above"]))],
    "GameFolderInDocuments": [("tier", "limited-access"), ("labels", ["Changes files in its own or the game's folders"])],
    "InterpolationCleared": [("tier", "limited-access"), ("label", "Changes files outside the game")],
    "InterpolationClearedUrl": [("tier", "limited-access"), ("label", "Connects to the internet")],
    "InterpolationBranch": [("tier", "limited-access"), ("label", "Changes files outside the game")],
    "InterpolationProvider": [("tier", "limited-access"), ("label", "Changes files outside the game")],
    "InterpolationToString": [("tier", "limited-access"), ("label", "Changes files outside the game")],
    "InterpolationChar": [("tier", "limited-access"),
                          ("evidence", ("Changes files outside the game", ["InterpolationChar::Formatted", "InterpolationChar::Rooted"]))],
    "InterpolationValues": [("tier", "limited-access"), ("labels", ["Changes files in its own or the game's folders"])],
    "OwnHelperPath": [("tier", "limited-access"), ("labels", ["Changes files in its own or the game's folders"])],
    "ConcatDots": [("tier", "limited-access"),
                   ("evidence", ("Changes files outside the game", ["ConcatDots::Concatenated", "ConcatDots::Interpolated"]))],
    "EditDots": [("tier", "limited-access"),
                 ("evidence", ("Changes files outside the game", ["EditDots::Replaced", "EditDots::Cut", "EditDots::NameOnly"]))],
    "InterpolationByRef": [("tier", "limited-access"), ("label", "Changes files outside the game")],
    "InterpolationRefLocal": [("tier", "limited-access"), ("label", "Changes files outside the game")],
    # G5b (policy 17): regression cases for v8 rules. Hot reload is code generation; a part the check cannot
    # trace after the mod's own folder is outside (each join); a CompactHUD-like XML save and load in its own
    # folder (created there, loaded back from an interpolated path) stays the one own-folder label.
    "MetadataUpdate": [("tier", "broad-access"), ("group", (SYSTEM, "Builds code at run time"))],
    # The untraced part can also keep it in its own folder, so both labels (origins "own, untraced").
    "OwnFolderUntracedPart": [("tier", "limited-access"), ("labels", ["Changes files in its own or the game's folders", "Changes files outside the game"]),
                              ("evidence", ("Changes files outside the game", ["OwnFolderUntracedPart::Combined", "OwnFolderUntracedPart::Concatenated",
                                                                                 "OwnFolderUntracedPart::Interpolated"]))],
    "OwnFolderXml": [("tier", "limited-access"), ("labels", ["Changes files in its own or the game's folders"]),
                     ("evidence", ("Changes files in its own or the game's folders", ["OwnFolderXml::SaveWinPos"]))],
    # H2 (policy 18): explicit-layout overlaps. Two references, or a reference over an integer and a native
    # integer, are a type confusion with no API call (raw memory); a union of plain data only is not.
    "OverlapRefs": [("tier", "broad-access"), ("groups", {DEEP: ["Reads or writes memory directly"]})],
    "OverlapRefInt": [("tier", "broad-access"), ("groups", {DEEP: ["Reads or writes memory directly"]})],
    "OverlapInlineArray": [("tier", "broad-access"), ("groups", {DEEP: ["Reads or writes memory directly"]})],
    "OverlapPlainUnion": [("tier", "limited-access"), ("labels", [])],
    # H4 (policy 20): a local replaced through a ref local taken before its store is not the value the walker
    # saw there: a web address or a folder the mod created, so handed to the shell, stays starting a program.
    # (The controls without the alias are shell-open/link and game-interaction OpenOwnFolder.)
    "AliasedUrl": [("tier", "broad-access"), ("group", (SYSTEM, "Starts other programs"))],
    "AliasedFolder": [("tier", "broad-access"), ("group", (SYSTEM, "Starts other programs"))],
    # The same for a traced type (bounded reflection); UnaliasedType is the control without the ref local.
    "AliasedType": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "UnaliasedType": [("tier", "limited-access"), ("labels", [])],
    # H4 review: the same when a copy of the local is used after a loop head, where a local is known from
    # every store to it in the method (the summaries walk the method again and must skip the alias too).
    "AliasedTypeLoop": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "UnaliasedTypeLoop": [("tier", "limited-access"), ("labels", [])],
    # H8 (policy 27): raw-memory precision. The unsafe compile flag alone, the layout queries and error-code
    # helpers that touch no memory, and stackalloc of 1-byte elements with a variable count into a span are
    # not raw memory (each was before H8). A pointer local (with the same flag), Marshal.ReadInt32(IntPtr)
    # and GetExceptionForHR(int, IntPtr) still are.
    "UnsafeFlagOnly": [("tier", "limited-access"), ("labels", [])],
    "NoMemoryOffsetOf": [("tier", "limited-access"), ("labels", [])],
    "NoMemorySizeOf": [("tier", "limited-access"), ("labels", [])],
    "NoMemoryErrors": [("tier", "limited-access"), ("labels", [])],
    "StackallocBytes": [("tier", "limited-access"), ("labels", [])],
    # H8 review: the same span in a [SkipLocalsInit] method reads stack memory it never wrote.
    "StackallocNoInit": [("tier", "broad-access"), ("groups", {DEEP: ["Reads or writes memory directly"]})],
    "UnsafePointerLocal": [("tier", "broad-access"), ("groups", {DEEP: ["Reads or writes memory directly"]})],
    "MemoryReadIntPtr": [("tier", "broad-access"), ("groups", {DEEP: ["Reads or writes memory directly"]})],
    "ErrorInfoIntPtr": [("tier", "broad-access"), ("groups", {DEEP: ["Reads or writes memory directly"]})],
    # H9 (policy 29): classification. Named kernel objects are the new "ipc" label, unnamed ones safe; GCHandle.Alloc
    # and IsAllocated safe, FromIntPtr/Target raw memory; the game's own process and start time safe; DriveInfo's
    # queries user-info (renaming a volume stays unclassified); TextFieldParser(path) a traced file read;
    # XmlSerializer(Type, XmlAttributeOverrides) xml-serialization-open; the [LibraryImport] marshallers raw memory,
    # the COM wrappers native code; CPU feature checks safe. Each was "Uses a part of .NET the check does not classify".
    "IpcNamed": [("tier", "limited-access"), ("labels", ["Communicates with other programs on your computer"])],
    "IpcUnnamed": [("tier", "limited-access"), ("labels", [])],
    "GCHandleAlloc": [("tier", "limited-access"), ("labels", [])],
    "GCHandleForged": [("tier", "broad-access"), ("groups", {DEEP: ["Reads or writes memory directly"]})],
    "OwnProcessStart": [("tier", "limited-access"), ("labels", [])],
    "DriveList": [("tier", "limited-access"), ("labels", ["Reads information about you and your computer"])],
    "DriveRename": [("tier", "broad-access"), ("groups", {UNCHECKED: ["Uses a part of .NET the check does not classify"]})],
    "CsvOwnFolder": [("tier", "limited-access"), ("labels", [])],
    "CsvOutside": [("tier", "limited-access"), ("labels", ["Reads files outside the game"])],
    "XmlOverrides": [("tier", "broad-access"), ("groups", {DEEP: ["Reads or writes XML into objects of a type chosen at run time, which the check does not follow"]})],
    "MarshallerUse": [("tier", "broad-access"), ("groups", {DEEP: ["Reads or writes memory directly"]})],
    "ComWrappersUse": [("tier", "broad-access"), ("groups", {SYSTEM: ["Runs native code"]})],
    "CpuFeatures": [("tier", "limited-access"), ("labels", [])],
    # H9: a type found by a name with no assembly part that nothing has, only tested for null, runs nothing
    # (Broad access, "Calls code that was not analyzed" before H9). Created, handed to a serializer, kept in a
    # field, or named with an assembly part, it stays code that was not analyzed.
    "TypeByNameNullTest": [("tier", "limited-access")],
    "TypeByNameCreate": [("tier", "broad-access"), ("groups", {UNCHECKED: ["Calls code that was not analyzed"]})],
    "TypeByNameSerialize": [("tier", "broad-access"), ("groups", {UNCHECKED: ["Calls code that was not analyzed"]})],
    "TypeByNameField": [("tier", "broad-access"), ("groups", {UNCHECKED: ["Calls code that was not analyzed"]})],
    "TypeByNameQualified": [("tier", "broad-access"), ("groups", {UNCHECKED: ["Calls code that was not analyzed"]})],
    # H9 review: a by-name CreateInstance runs a constructor before its result is tested: not a lookup only.
    "CreateByNameNullTest": [("tier", "broad-access"), ("groups", {UNCHECKED: ["Calls code that was not analyzed"]})],
    # H9 control: ordinary C# delegates (ldftn, ldvirtftn) are not native code.
    "DelegatesOrdinary": [("tier", "limited-access"), ("labels", [])],
    # C review (policy 34): memory-safe patterns no longer counted as raw memory, each with a near-miss that stays
    # "Reads or writes memory directly". C1: spans of enum elements (the enum's size is its underlying type's).
    # C2: MemoryMarshal.AsBytes/Cast/Read/Write/TryRead/TryWrite with plain type arguments; a struct with a hidden
    # string, a native int and the other MemoryMarshal members stay raw memory. C3: explicit-layout unions over
    # framework enums and plain structs laid out from the framework's metadata; a framework struct with a native
    # int (GCHandle) and a generic instantiation stay raw memory. C4: the stores and block copies of stackalloc
    # initializers of primitive and enum elements; struct elements (sizeof-based offsets) stay raw memory.
    "EnumSpan": [("tier", "limited-access"), ("labels", [])],
    "MemoryMarshalPlain": [("tier", "limited-access"), ("labels", [])],
    "MemoryMarshalHidden": [("tier", "broad-access"), ("groups", {DEEP: ["Reads or writes memory directly"]})],
    "MemoryMarshalNativeInt": [("tier", "broad-access"), ("groups", {DEEP: ["Reads or writes memory directly"]})],
    "MemoryMarshalOther": [("tier", "broad-access"), ("groups", {DEEP: ["Reads or writes memory directly"]})],
    "UnionFrameworkPlain": [("tier", "limited-access"), ("labels", [])],
    "UnionFrameworkHandle": [("tier", "broad-access"), ("groups", {DEEP: ["Reads or writes memory directly"]})],
    "UnionFrameworkGeneric": [("tier", "broad-access"), ("groups", {DEEP: ["Reads or writes memory directly"]})],
    "StackallocInit": [("tier", "limited-access"), ("labels", [])],
    "StackallocInitStruct": [("tier", "broad-access"), ("groups", {DEEP: ["Reads or writes memory directly"]})],
}

# Embedded-resource fixtures (fixtures/embedded, one assembly per payload): expected tier.
EMBEDDED = {"text": "limited-access", "pe": "broad-access", "zip": "broad-access", "costura": "broad-access", "linked": "broad-access"}

# Harmony patch-attribute fixtures (fixtures/harmony-patch/mod/cases/<case>.cs), analyzed with the
# Harmony stand-in allowlisted and profiled, and the game stand-in's profile. Same form as EVASION.
HARMONY_PATCH = {
    "GameTarget": [("tier", "limited-access"), ("labels", ["Changes how the game works"])],
    "GameFullTarget": [("tier", "broad-access"), ("reason", "Starts other programs")],
    "FrameworkTarget": [("tier", "limited-access"), ("label", "Changes files outside the game")],
    "ProcessTarget": [("tier", "broad-access"), ("reason", "Starts other programs")],
    "ByName": [("tier", "broad-access"), ("reason", "Starts other programs")],
    "CustomAttribute": [("tier", "broad-access"), ("reason", "Uses reflection the check cannot trace")],
    "TargetMethodUntraced": [("tier", "broad-access"), ("reason", "Uses reflection the check cannot trace")],
    "TargetMethodTraced": [("tier", "limited-access"), ("labels", ["Changes how the game works"])],
    "Delegate": [("tier", "broad-access"), ("reason", "Starts other programs")],
    "ReversePatch": [("tier", "limited-access"), ("label", "Changes game saves")],
    "PatchAll": [("tier", "broad-access"), ("reason", "Starts other programs")],
    # G5a (policy 17): a target split across a base class (the type) and the patch class (the method).
    "InheritedTarget": [("tier", "broad-access"), ("reason", "Starts other programs")],
    # D7 (policy 35): a prefix's or postfix's __instance declared as object is the patched game method's instance,
    # when the attributes name the type by typeof and that type alone declares the method (Broad access, system
    # access before: "Uses reflection the check cannot trace"). Near misses keep "Uses reflection the check cannot
    # trace": a TargetMethod, a method the named type only inherits, the mod's own call to the patch method, the
    # patch method handed to Harmony again by name, __instance overwritten, [HarmonyArgument] on it.
    "InstanceGame": [("tier", "broad-access"), ("groups", {DEEP: ["Uses reflection on the game's or its own code that the check cannot fully follow"]}),
                     ("label", "Uses your clipboard")],
    "InstanceTargetMethod": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "InstanceInherited": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "InstanceCalled": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "InstanceManual": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "InstanceReassigned": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "InstanceRenamed": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    # D7 review: an internal method handed to Harmony by name gets the patched method's arguments too (before policy
    # 35 its path parameter was traced from the mod's own call only: no "outside the game" label).
    "ManualPatchPath": [("tier", "limited-access"), ("label", "Changes files outside the game"), ("label", "Changes files in its own or the game's folders")],
}

# Reflection the check traces since policy 10 (fixtures/reflection-precision/cases/<case>.cs): benign
# controls, analyzed like the Harmony patch fixtures. Same form as EVASION.
BOUNDED = "Uses reflection on the game's or its own code that the check cannot fully follow"
REFLECTION_PRECISION = {
    "MemberArrayMod": [("tier", "limited-access"), ("labels", [])],
    "MemberArrayGame": [("tier", "limited-access"), ("labels", ["Changes game saves"])],
    "MemberParameter": [("tier", "limited-access"), ("labels", [])],
    "TargetMethodsIterator": [("tier", "limited-access"), ("labels", ["Changes how the game works"])],
    "ExpressionCompiled": [("tier", "limited-access"), ("labels", [])],
    "BoundedGameType": [("tier", "broad-access"), ("groups", {DEEP: [BOUNDED]})],
    # G2a (policy 15): nested types found by GetMember(s), a lookup array written by the framework,
    # a member name given to a method of the mod's own generic type.
    "NestedByMember": [("tier", "broad-access"), ("group", (SYSTEM, "Starts other programs"))],
    "NestedByFilter": [("tier", "broad-access"), ("group", (SYSTEM, "Starts other programs"))],
    "LookupSetValue": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "NameGeneric": [("tier", "broad-access"), ("group", (SYSTEM, "Starts other programs"))],
    # G5b (policy 17): regression cases for v8 rules. A type qualified with another mod's assembly; a game type
    # by qualified name, and found by name alone (the game profile's type list); a framework member the policy
    # does not classify, reached by reflection.
    "OtherModType": [("tier", "broad-access"), ("groups", {UNCHECKED: ["Calls code that was not analyzed"]})],
    "GameTypeByName": [("tier", "limited-access"), ("labels", ["Changes game saves"])],
    "GameTypeFoundByName": [("tier", "broad-access"), ("group", (SYSTEM, "Starts other programs"))],
    "UnclassifiedByName": [("tier", "broad-access"), ("groups", {UNCHECKED: ["Uses a part of .NET the check does not classify"]})],
    # H9 review: a game type created by name (Assembly.CreateInstance, Activator.CreateInstance(assembly, type)) runs its constructor.
    "GameCreateByName": [("tier", "broad-access"), ("group", (SYSTEM, "Starts other programs"))],
    # H3 (policy 19): lookups by name that find a member the name does not spell exactly (ignoring case, a
    # GetMember prefix), by-name lookups outside GetMethod (Delegate.CreateDelegate(Type, Type, string),
    # Expression.Call/Property(Type, string)), nested types of a reflected type, a type name ignoring case,
    # IgnoresAccessChecksTo. Each probe was Limited access (or had fewer labels) before, except TrustedIgnoreCase
    # (the same result before, by the library type as a whole; checked below by its evidence); the controls look
    # the same member up by its exact name.
    "IgnoreCaseGame": [("tier", "broad-access"), ("group", (SYSTEM, "Starts other programs"))],
    "ExactNameGame": [("tier", "broad-access"), ("group", (SYSTEM, "Starts other programs"))],
    "IgnoreCaseLabel": [("tier", "limited-access"), ("labels", ["Uses your clipboard"])],
    "FlagsNotConstant": [("tier", "broad-access"), ("group", (SYSTEM, "Starts other programs"))],
    "TypeNameIgnoreCase": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "TypeNameExactCase": [("tier", "broad-access"), ("group", (SYSTEM, "Starts other programs"))],
    "MemberPrefix": [("tier", "limited-access"), ("labels", ["Uses your clipboard"])],
    "MemberExactName": [("tier", "limited-access"), ("labels", ["Uses your clipboard"])],
    "DelegateByNameGame": [("tier", "broad-access"), ("group", (SYSTEM, "Starts other programs"))],
    "DelegateByNameIgnoreCase": [("tier", "broad-access"), ("group", (SYSTEM, "Starts other programs"))],
    "DelegateByNameOwn": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "ExpressionByNameGame": [("tier", "broad-access"), ("group", (SYSTEM, "Starts other programs"))],
    "ExpressionPropertyByName": [("tier", "limited-access"), ("labels", ["Changes game saves"])],
    "ExpressionByNameOwn": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "NestedReach": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "NestedDirect": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "TrustedIgnoreCase": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "TrustedExactName": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "TrustedNestedPrefix": [("tier", "broad-access"), ("group", (SYSTEM, "Starts other programs"))],
    "TrustedNestedExact": [("tier", "broad-access"), ("group", (SYSTEM, "Starts other programs"))],
    "AccessChecksFramework": [("tier", "broad-access"), ("groups", {UNCHECKED: ["Uses a part of .NET the check does not classify"]})],
    "AccessChecksDisplayName": [("tier", "broad-access"), ("groups", {UNCHECKED: ["Uses a part of .NET the check does not classify"]})],
    "AccessChecksGame": [("tier", "limited-access"), ("labels", [])],
    # H10b review (policy 31): the framework assembly's name quoted, as a display name may write it (Limited access before).
    "AccessChecksQuoted": [("tier", "broad-access"), ("groups", {UNCHECKED: ["Uses a part of .NET the check does not classify"]})],
    # H7 (policy 23): "reached by reflection" is the members a lookup can return (F1), not every method of the
    # type. Negatives (each Broad access before and after): a name parameter's method reached only through a Type
    # field (the reach must be iterated with the names), a GetMember prefix, a nested type's method found by a
    # name in another case through its outer type. Controls (Broad access before H7): GetFields reaches no method
    # but the initializer; a hook installer looks its own prefixes up by constant names.
    "XF1Order": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "XF1GetMemberStar": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "XNestedReach": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "XF1Benign": [("tier", "limited-access"), ("labels", [])],
    "XF1NamedHooks": [("tier", "limited-access"), ("labels", [])],
    # H7: Traverse.Create(object) on an object of a declared class is that type or a derived one, as for GetType
    # (Broad access, system access before); a new object is exactly its type (Limited access, with the label every
    # use of Traverse has); one declared as object is untraced.
    "TraverseObjectGame": [("tier", "broad-access"), ("groups", {DEEP: [BOUNDED]})],
    "TraverseObjectNew": [("tier", "limited-access"), ("labels", ["Changes how the game works"])],
    "TraverseObjectUntyped": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    # H7 review (policy 24): an indexer renamed with [IndexerName] on a game type, found by AccessTools.Indexer or
    # patched by a getter patch without a name, reaches every member of the type (Limited access before: nothing);
    # its control, a conventional indexer, reaches only get_Item. A getter patch without a name on the mod's own
    # renamed indexer, an expression tree's call of a private method (a method handle), and private path and
    # folder helpers invoked by name are given any argument (each had fewer labels or Limited access before).
    "IndexerRenamedGame": [("tier", "broad-access"), ("group", (SYSTEM, "Starts other programs"))],
    "IndexerPlainGame": [("tier", "limited-access"), ("labels", ["Changes how the game works"])],
    "IndexerPatchGame": [("tier", "broad-access"), ("group", (SYSTEM, "Starts other programs"))],
    "IndexerPatchOwn": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "ExpressionTreeOwnCall": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "ReflectedPathHelper": [("tier", "limited-access"), ("labels", ["Changes files in its own or the game's folders", "Changes files outside the game"])],
    "ReflectedFolderHelper": [("tier", "broad-access"), ("group", (SYSTEM, "Starts other programs"))],
    # H7b (policy 25): a lookup or a Harmony patch named through the mod's own type finds what the type inherits
    # from a game, framework or trusted-library base type; a static abstract interface member's implementation is
    # called through a type parameter with any argument; GetType() of a game-typed value can be the mod's type
    # deriving from it. Each probe was Limited access (GameDerivedGetType: without the untraced reason) before.
    # Controls: names only the mod's own types have (a method, a property), a type without a game base, an
    # implementation that ignores its argument.
    "InheritedGame": [("tier", "broad-access"), ("group", (SYSTEM, "Starts other programs"))],
    "InheritedGameAny": [("tier", "broad-access"), ("group", (SYSTEM, "Starts other programs"))],
    "InheritedFramework": [("tier", "broad-access"), ("group", (SYSTEM, "Starts other programs"))],
    "InheritedPatch": [("tier", "broad-access"), ("group", (SYSTEM, "Starts other programs"))],
    "InheritedTrusted": [("tier", "broad-access"), ("group", (SYSTEM, "Starts other programs"))],
    "InheritedNoBase": [("tier", "limited-access"), ("labels", [])],
    "InheritedOwnName": [("tier", "limited-access"), ("labels", [])],
    "InheritedTrustedOwnName": [("tier", "limited-access"), ("labels", ["Changes how the game works"])],
    "StaticAbstractExplicit": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "StaticAbstractImplicit": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "StaticAbstractBenign": [("tier", "limited-access"), ("labels", [])],
    "GameDerivedGetType": [("tier", "broad-access"), ("groups", {DEEP: [BOUNDED], SYSTEM: ["Uses reflection the check cannot trace"]})],
    # H7b review (policy 26): a type nested in the mod's own type, or in a game type, found from the outer type
    # (which the walker counts as the outer type) is searched with what it inherits; a base type's renamed indexer
    # found by its parameters through a mod type that has its own. Each was Limited access before. Control: a
    # name only the mod's nested type has.
    "InheritedNested": [("tier", "broad-access"), ("group", (SYSTEM, "Starts other programs"))],
    "InheritedNestedOwnName": [("tier", "limited-access"), ("labels", [])],
    "GameNestedInherited": [("tier", "broad-access"), ("group", (SYSTEM, "Starts other programs"))],
    "InheritedIndexer": [("tier", "broad-access"), ("group", (SYSTEM, "Starts other programs"))],
    # D5 (policy 35): a value read with FieldInfo/PropertyInfo.GetValue from a game member found by a constant name on
    # exactly a game type is of the member's declared game class or a derived type, also through a FieldInfo kept in a
    # field (each Broad access with "Uses reflection the check cannot trace" before; now deep game access only). Near
    # misses keep "Uses reflection the check cannot trace": the value replaced on a path, a member declared as object,
    # the member looked up on a run-time type, names that differ only in case with different types, a hidden base
    # field, a cached FieldInfo that can also hold a member declared as object.
    "ValueFieldGame": [("tier", "broad-access"), ("groups", {DEEP: [BOUNDED]})],
    "ValuePropertyGame": [("tier", "broad-access"), ("groups", {DEEP: [BOUNDED]})],
    "ValueFieldCached": [("tier", "broad-access"), ("groups", {DEEP: [BOUNDED]})],
    "ValueReplaced": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "ValueObjectField": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "ValueDerivedLookup": [("tier", "broad-access"), ("groups", {DEEP: [BOUNDED], SYSTEM: ["Uses reflection the check cannot trace"]})],
    "ValueCaseCollision": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "ValueHiddenField": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "ValueFieldReassigned": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    # A game type found by name is typed from the map when the game alone has that name (checked below with the
    # mod's own type of that name in another assembly). ShadowUniverse is that other assembly, a plain type alone.
    "ValueByName": [("tier", "broad-access"), ("groups", {DEEP: [BOUNDED]})],
    "ShadowUniverse": [("tier", "limited-access"), ("labels", [])],
    # D6 (policy 35): FieldType, PropertyType and ReturnType of such a member are exactly its declared type (Broad
    # access before, "Uses reflection the check cannot trace"). Near misses: declared as object; found on a run-time type.
    "DeclaredFieldType": [("tier", "limited-access"), ("labels", [])],
    "DeclaredPropertyTypeCached": [("tier", "limited-access"), ("labels", ["Uses your clipboard"])],
    "DeclaredReturnType": [("tier", "limited-access"), ("labels", [])],
    "DeclaredTypeObject": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "DeclaredTypeDerived": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    # D9 (policy 35): a lookup on the run-time type of a game-typed value reaches the members of the game's types
    # derived from it (by base type or interface, D3). DerivedGameMember had only the bounded reason before,
    # DerivedGameInterface no label; DerivedGameDirect is the control (same before and after). The mod's own derived
    # type is GameDerivedGetType above (policy 25).
    "DerivedGameMember": [("tier", "broad-access"), ("groups", {DEEP: [BOUNDED], SYSTEM: ["Starts other programs"]})],
    "DerivedGameInterface": [("tier", "broad-access"), ("groups", {DEEP: [BOUNDED]}), ("labels", ["Changes game saves"])],
    "DerivedGameDirect": [("tier", "broad-access"), ("groups", {DEEP: [BOUNDED]}), ("labels", ["Uses your clipboard"])],
    # D10 (policy 35): values the rule cannot type stay untraced: a local declared as object whose address is passed
    # to a method (which can store any object there; before D10 the walker kept the last object it saw there), a call
    # of the mod's that returns object, a cast through a generic helper.
    "ValueAliasedRef": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "ValuePassedThrough": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "ValueCastGeneric": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    # D10: the same for an object of a game class read from a field (deep game access only before D10).
    "ObjectAliasedRef": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
}

# Hand-written IL the C# compiler does not emit (H7): fixtures/il-probes is a generator the harness runs to write
# these assemblies, which are only analyzed (nothing generated is run). A member array carried on the stack along
# a backward branch and changed at the loop head through that copy (Limited access before H7), with its
# straight-line control; a property setter not named set_P, reached by the property's name (F1 guard 3), with
# its conventionally named control; a branch into the middle of an instruction (Limited access before H7).
IL_PROBES = {
    "ProbeLoopStloc": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "ProbeStraight": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "AccessorOdd": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "AccessorPlain": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "BranchIntoInstruction": [("tier", "broad-access"), ("groups", {UNCHECKED: ["Contains code the check cannot read"]})],
    # H8 (policy 27): stackalloc of 1-byte elements with a variable count. The control is a Span<byte> of the
    # same store of the count; a wider element, an aliased or restored count and a truncated size stay raw memory.
    "StackallocByteIl": [("tier", "limited-access"), ("labels", [])],
    "StackallocByteWide": [("tier", "broad-access"), ("groups", {DEEP: ["Reads or writes memory directly"]})],
    "StackallocByteAliased": [("tier", "broad-access"), ("groups", {DEEP: ["Reads or writes memory directly"]})],
    "StackallocByteRestored": [("tier", "broad-access"), ("groups", {DEEP: ["Reads or writes memory directly"]})],
    "StackallocByteTruncated": [("tier", "broad-access"), ("groups", {DEEP: ["Reads or writes memory directly"]})],
    # H8 review: a length that is not the count's own value (the buffer itself, the buffer reloaded from a
    # local, a product of the count) and a size that is not the count (count * 0) stay raw memory, before
    # H4's multiply too (a byte count kept in a local and reloaded as a Span<int>'s length).
    "StackallocByteSelfLength": [("tier", "broad-access"), ("groups", {DEEP: ["Reads or writes memory directly"]})],
    "StackallocByteReloaded": [("tier", "broad-access"), ("groups", {DEEP: ["Reads or writes memory directly"]})],
    "StackallocByteScaledLength": [("tier", "broad-access"), ("groups", {DEEP: ["Reads or writes memory directly"]})],
    "StackallocByteZeroScale": [("tier", "broad-access"), ("groups", {DEEP: ["Reads or writes memory directly"]})],
    "StackallocCountReloaded": [("tier", "broad-access"), ("groups", {DEEP: ["Reads or writes memory directly"]})],
    "StackallocCountControl": [("tier", "limited-access"), ("labels", [])],
    # H9 (H8 review): a delegate made from a native int no ldftn/ldvirtftn produced calls whatever address it is
    # given (native code; Limited access before H9); the control takes its pointers from ldftn and ldvirtftn.
    "DelegateFromInt": [("tier", "broad-access"), ("groups", {SYSTEM: ["Runs native code"]})],
    "DelegateFromLdftn": [("tier", "limited-access"), ("labels", [])],
    # H10b review (policy 31): a member reference through the mod's own type deriving from Process for Kill(), which
    # the type declares only as Kill(int), runs Process.Kill (Limited access, nothing labelled before: matched by
    # name); the control calls the type's own Kill(int) through a generic instantiation, as C# writes it.
    "OverloadOwnType": [("tier", "broad-access"), ("groups", {UNCHECKED: ["Calls code that was not analyzed"]})],
    "OverloadOwnMatch": [("tier", "limited-access"), ("labels", [])],
    # H5 review fix 3 (policy 22), now with a fixture: the same reference through an own type that declares no Kill.
    "OverloadOwnInherited": [("tier", "broad-access"), ("groups", {UNCHECKED: ["Calls code that was not analyzed"]})],
    # H12 (policy 32): the same own-type reference with the parameter's type named another way than in the
    # definition (a type reference into the probe, as a merged assembly names framework types through other
    # facades): the probe's own member (Broad access before: the blobs differ); a name the probe lacks is not.
    "OverloadOwnEquivalent": [("tier", "limited-access"), ("labels", [])],
    "OverloadOwnUnresolved": [("tier", "broad-access"), ("groups", {UNCHECKED: ["Calls code that was not analyzed"]})],
    # B review (policy 33): cpblk and initblk copy or fill a caller-chosen number of bytes from a destination
    # address, which a managed address does not bound (a length past the destination is an out-of-bounds
    # write). They are raw memory whatever the addresses are. CpblkManaged and InitblkManaged copy/fill
    # through the address of a local (Limited access before, nothing labelled: only the address was checked);
    # CpblkForged, the near-miss, fills from a native int the method is handed (Broad access before and after).
    "CpblkManaged": [("tier", "broad-access"), ("groups", {DEEP: ["Reads or writes memory directly"]})],
    "CpblkForged": [("tier", "broad-access"), ("groups", {DEEP: ["Reads or writes memory directly"]})],
    "InitblkManaged": [("tier", "broad-access"), ("groups", {DEEP: ["Reads or writes memory directly"]})],
    # C review (policy 34), hand-written variants of the stackalloc-initializer shapes (C4) and enum spans (C1). The
    # controls are the compiler's shapes written by hand (Limited access); every near-miss breaks one bound by one
    # unit and stays "Reads or writes memory directly": a 4-byte store at offset 5 or 8 of an 8-byte buffer, a
    # reference stored into the buffer, a fill or copy one byte too long, a copy whose constant data is shorter
    # than its length, a copy from the span's second element with the whole data's length, and a span of 8
    # int-sized (or long-sized) enum elements over a buffer half that size.
    "InitStoreIl": [("tier", "limited-access"), ("labels", [])],
    "InitStoreOffByOne": [("tier", "broad-access"), ("groups", {DEEP: ["Reads or writes memory directly"]})],
    "InitStorePastEnd": [("tier", "broad-access"), ("groups", {DEEP: ["Reads or writes memory directly"]})],
    "InitStoreRef": [("tier", "broad-access"), ("groups", {DEEP: ["Reads or writes memory directly"]})],
    "InitblkIl": [("tier", "limited-access"), ("labels", [])],
    "InitblkOverrun": [("tier", "broad-access"), ("groups", {DEEP: ["Reads or writes memory directly"]})],
    "CpblkIl": [("tier", "limited-access"), ("labels", [])],
    "CpblkOverrun": [("tier", "broad-access"), ("groups", {DEEP: ["Reads or writes memory directly"]})],
    "CpblkSourceShort": [("tier", "broad-access"), ("groups", {DEEP: ["Reads or writes memory directly"]})],
    "CreateSpanIl": [("tier", "limited-access"), ("labels", [])],
    "CreateSpanIndexOverrun": [("tier", "broad-access"), ("groups", {DEEP: ["Reads or writes memory directly"]})],
    "EnumSpanIl": [("tier", "limited-access"), ("labels", [])],
    "EnumSpanOverrun": [("tier", "broad-access"), ("groups", {DEEP: ["Reads or writes memory directly"]})],
    "EnumSpanLongOverrun": [("tier", "broad-access"), ("groups", {DEEP: ["Reads or writes memory directly"]})],
    # D review (policy 35), D5: a value read through a member is typed only by a member of the kind the read is made on
    # (ValueKindMismatch calls PropertyInfo.GetValue on a FieldInfo), and a property's type only when its getter
    # returns that type (PropertyGetterMismatch). The controls are typed: bounded to the probe's own class.
    "ValueKindField": [("tier", "broad-access"), ("groups", {DEEP: [BOUNDED]})],
    "ValueKindMismatch": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "PropertyGetterMatch": [("tier", "broad-access"), ("groups", {DEEP: [BOUNDED]})],
    "PropertyGetterMismatch": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
}

# Ordinary game interaction that policy 11 no longer counts as Broad access (fixtures/game-interaction/
# cases/<case>.cs): benign controls, and the real APIs next to them that still are. Analyzed like the
# Harmony patch fixtures. Same form as EVASION.
REWRITES = "Rewrites the game's code with a Harmony transpiler, which the check cannot follow instruction by instruction"
REWRITES_OUTSIDE = "Rewrites code other than the game's with a Harmony transpiler"
XML_TYPES = "Reads or writes XML into objects whose types the check does not follow"
XML_OPEN = "Reads or writes XML into objects of a type chosen at run time, which the check does not follow"
XML_GAME = "Has the game read or write XML into objects of types the mod chooses, which the check does not follow"
GAME_INTERACTION = {
    "TranspilerOperand": [("tier", "broad-access"), ("groups", {DEEP: [REWRITES]}), ("labels", ["Changes how the game works"])],
    "DynamicMethodEmit": [("tier", "broad-access"), ("reason", "Builds code at run time")],
    "TranspileFramework": [("tier", "broad-access"), ("group", (SYSTEM, "Rewrites code other than the game's with a Harmony transpiler"))],
    "ObservingPostfix": [("tier", "limited-access"), ("labels", ["Changes how the game works"])],
    "OpenOwnFolder": [("tier", "limited-access"), ("labels", ["Changes files in its own or the game's folders", "Opens its own or the game's folders"])],
    # Workstream A near-miss: a ProcessStartInfo with any member beyond FileName and UseShellExecute (here
    # Verb) is not a plain shell open, so it stays "Starts other programs" and does not become a folder open.
    "StartInfoVerb": [("tier", "broad-access"), ("group", (SYSTEM, "Starts other programs"))],
    "NetworkValues": [("tier", "limited-access"), ("labels", ["Reads information about you and your computer"])],
    "NamedMemberLookup": [("tier", "limited-access"), ("labels", [])],
    "AnyMemberLookup": [("tier", "limited-access"), ("labels", ["Uses your clipboard"])],
    # G5c (policy 17): NamedMemberLookup's name filter without a capture (the compiler caches it in a static field
    # of <>c, which the proof does not follow), given to FirstOrDefault and to Where: every member is reached,
    # the clipboard one included, as for AnyMemberLookup. Before H7 (policy 23) these were Broad access (bounded
    # reflection): at the join after the cache's brtrue the walker lost the GetMethods() array still on the stack
    # (Pass escaped the whole stack at every block start). Since H7 ("J1") a collection the merged entry carries
    # with the same id at the same depth is followed on. XG5cJoin: two different arrays meet there (not followed).
    "CachedNameFilter": [("tier", "limited-access"), ("labels", ["Uses your clipboard"]),
                         ("evidence", ("Uses your clipboard", ["CachedDrawer::Draw"]))],
    "CachedNameFilterWhere": [("tier", "limited-access"), ("labels", ["Uses your clipboard"]),
                              ("evidence", ("Uses your clipboard", ["CachedWhereDrawer::Draw"]))],
    "XG5cJoin": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace")), ("label", "Uses your clipboard")],
    "XmlSettings": [("tier", "broad-access"), ("groups", {DEEP: [XML_TYPES]}), ("labels", [])],
    "XmlOwnFolder": [("tier", "limited-access"), ("labels", ["Reads files outside the game"])],
    "XmlUntraced": [("tier", "limited-access"), ("label", "Connects to the internet")],
    # G2a (policy 15): a transpiler that uses no CodeInstruction member; operands that skip the check at
    # the call (a setter delegate, Activator, a join with a string); the game's XML helper for a mod type.
    "LinqTranspiler": [("tier", "broad-access"), ("group", (DEEP, REWRITES)), ("group", (SYSTEM, "Starts other programs"))],
    "RewriteNestedExempt": [("tier", "broad-access"), ("group", (DEEP, REWRITES)), ("group", (SYSTEM, "Starts other programs"))],
    "OperandSetterDelegate": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "OperandActivator": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "OperandJoin": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "XmlGameHelper": [("tier", "broad-access"), ("groups", {DEEP: [XML_GAME]})],
    # H5 review: a lookup by name on a derived game type finds the game base type's member too.
    "InheritedLookup": [("tier", "broad-access"), ("groups", {SYSTEM: ["Starts other programs"]})],
    "DeclaredLookup": [("tier", "limited-access"), ("labels", [])],
    "XmlGameType": [("tier", "limited-access")],
    "XmlGenericType": [("tier", "broad-access"), ("groups", {DEEP: [XML_OPEN]})],
    # G2b (policy 16): a patch method's path parameter is also whatever Harmony passes it.
    "PatchPathArgument": [("tier", "limited-access"),
                          ("labels", ["Changes how the game works", "Changes files in its own or the game's folders", "Changes files outside the game"])],
    # G5a (policy 17): regression cases. Transpiler placement by target route: Harmony.Patch, TargetMethod,
    # a reverse patch (explicit transpiler, or one its stand-in carries) on a game method stay deep game
    # access; PatchProcessor.AddTranspiler (original not linked), the mod's own method and the same routes on
    # a framework method are outside.
    # Operands written through CodeMatcher.Operand (and a control), a CodeInstruction subclass, a game
    # method taken as a delegate, AccessTools.MakeDeepCopy.
    "TranspilePatchCall": [("tier", "broad-access"), ("groups", {DEEP: [REWRITES]}), ("labels", ["Changes how the game works"])],
    "TranspileTargetMethod": [("tier", "broad-access"), ("groups", {DEEP: [REWRITES]}), ("labels", ["Changes how the game works"])],
    "TranspileProcessor": [("tier", "broad-access"), ("group", (SYSTEM, REWRITES_OUTSIDE))],
    "TranspileReversePatch": [("tier", "broad-access"), ("groups", {DEEP: [REWRITES]}), ("label", "Changes game saves")],
    "TranspileReverseStandin": [("tier", "broad-access"), ("groups", {DEEP: [REWRITES]}), ("label", "Changes game saves")],
    "TranspileOwnMethod": [("tier", "broad-access"), ("group", (SYSTEM, REWRITES_OUTSIDE))],
    # The same routes on string.Concat: without them a route that placed nothing would pass the game cases.
    "TranspilePatchCallFramework": [("tier", "broad-access"), ("group", (SYSTEM, REWRITES_OUTSIDE))],
    "TranspileTargetMethodFramework": [("tier", "broad-access"), ("group", (SYSTEM, REWRITES_OUTSIDE))],
    "TranspileReversePatchFramework": [("tier", "broad-access"), ("group", (SYSTEM, REWRITES_OUTSIDE))],
    "TranspileReverseStandinFramework": [("tier", "broad-access"), ("group", (SYSTEM, REWRITES_OUTSIDE))],
    "OperandByRef": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "OperandRefLocal": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "OperandByRefTraced": [("tier", "broad-access"), ("groups", {DEEP: [REWRITES]}), ("labels", ["Changes how the game works"])],
    "InstructionSubclass": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
    "GameDelegate": [("tier", "broad-access"), ("group", (SYSTEM, "Starts other programs"))],
    "DeepCopyGameType": [("tier", "limited-access"), ("label", "Changes game saves")],
    "DeepCopyUntraced": [("tier", "broad-access"), ("group", (SYSTEM, "Uses reflection the check cannot trace"))],
}

INTERNET = "Connects to the internet"
SAVES = "Changes game saves"
FILES_OUT = "Changes files outside the game"
INFO = "Reads information about you and your computer"
SETTINGS = "Changes system settings"
CLOSES = "Closes other programs"
WEBSITES = "Opens websites in your browser"
UNCLASSIFIED = "Uses a part of .NET the check does not classify"
UNANALYZED = "Calls code that was not analyzed"
RAW_MEMORY = "Reads or writes memory directly"
UNTRACED = "Uses reflection the check cannot trace"
CODE_FILES = "Changes files in its own or the game's folders"
EMBEDDED_BINARY = "Contains an embedded program, library or archive"


def expect(r, expected):
    """Whether a mod result meets a list of (kind, want): tier, label (present), labels (exact), groups (exact
    {group: reasons} of every Broad-access group), group ((group, reason) present), reason (in any group),
    evidence ((label, [method]): each method, "Type::Name", has a line of that label's evidence)."""
    def one(kind, want):
        if kind == "tier": return r["tier"] == want
        if kind == "label": return want in labels(r)
        if kind == "evidence":
            lines = [e for l in r["labels"] if l["text"] == want[0] for e in l["evidence"]]
            return all(any(f"<-  {m}  " in e for e in lines) for m in want[1])
        if kind == "labels": return labels(r) == want
        if kind == "groups": return groups(r) == want
        if kind == "group": return want[1] in groups(r).get(want[0], [])
        return want in reasons(r)
    return all(one(k, w) for k, w in (expected if isinstance(expected, list) else [expected]))


def check(name, ok, detail=""):
    _local.count = getattr(_local, "count", 0) + 1
    if name in PENDING:
        out(f"{'XPASS' if ok else 'PEND '}  {name}" + ("  (now passes: remove it from PENDING)" if ok else ""))
        if ok:
            failures.append(name)
        return
    out(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if not ok and detail != "" else ""))
    if not ok:
        failures.append(name)



# Set up once by tests(), before the groups run.
TFM = "net10.0"
TMP = None
tool = pipeline = corrupt = builtin = runtime_dir = None
_local = threading.local()


def out(text):
    """Print, or buffer when running inside a group (groups run in parallel and print in order)."""
    buf = getattr(_local, "buf", None)
    if buf is None:
        print(text, flush=True)
    else:
        buf.append(text)


def run(cmd, expect=0):
    p = subprocess.run(cmd, capture_output=True, text=True)
    if expect is not None and p.returncode != expect:
        raise RuntimeError(f"{' '.join(cmd)} exited {p.returncode}\n{p.stdout}\n{p.stderr}")
    return p


def sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def write_json(path, obj):
    with open(path, "w") as f:
        json.dump(obj, f)
    return path


def framework_dir():
    """Folder of the newest installed Microsoft.NETCore.App shared framework, or None."""
    rt = [l.split(" ", 2) for l in run(["dotnet", "--list-runtimes"]).stdout.splitlines() if l.startswith("Microsoft.NETCore.App ")]
    return os.path.join(rt[-1][2].strip("[]"), rt[-1][1]) if rt else None


def labels(mod):
    return [l["text"] for l in mod["labels"]]


def groups(mod):
    """Broad-access reasons by group: {group id: [reason text]}, only groups with a reason."""
    return {g["group"]: [r["text"] for r in g["reasons"]] for g in mod["broadAccess"]}


def reasons(mod):
    """Broad-access reasons of every group."""
    return [r["text"] for g in mod["broadAccess"] for r in g["reasons"]]


def evidence(mod):
    return [e for f in mod["labels"] + [r for g in mod["broadAccess"] for r in g["reasons"]] for e in f["evidence"]]


def j(*p):
    return os.path.join(TMP, *p)


def fx(project, dll):
    """Output of a single-build fixture (fixtures/<project>), built in place by build_all."""
    return os.path.join(REPO, "fixtures", project, "bin", "Release", TFM, dll)


def case_dll(project, case):
    """Output of one case of a multi-case fixture project (see MULTI), built by build_all."""
    _, _, prefix, _ = MULTI[project]
    return os.path.join(REPO, "fixtures", project, "bin", "case", case, f"{prefix}.{case}.dll")


def scratch(suffix):
    """A fresh file name in the build directory: groups run in parallel, so no two calls share one."""
    fd, path = tempfile.mkstemp(dir=TMP, suffix=suffix)
    os.close(fd)
    return path


def present(files):
    """The analyzer reports a path it cannot read as Broad access and exits 0, so a fixture or IL probe that was
    never written would meet any expectation that is only Broad access: every input must exist (H10b review)."""
    missing = [f for f in files if not os.path.exists(f[1:] if f.startswith("@") else f)]
    if missing:
        raise RuntimeError(f"input not found (not built or not generated): {', '.join(missing)}")
    return list(files)


def analyze(*files, allowlist=None, manifest=None, profile=None, libraries=None, policy=None, json_out=None):
    out = json_out or scratch(".result.json")
    cmd = ["dotnet", tool, "analyze", "--json", out]
    if allowlist: cmd += ["--allowlist", allowlist]
    if manifest: cmd += ["--manifest", manifest]
    if profile: cmd += ["--game-profile", profile]
    if libraries: cmd += ["--library-profile", libraries]
    if policy: cmd += ["--policy", policy]
    if manifest: present([manifest])
    run(cmd + present(files))
    with open(out) as f:
        result = json.load(f)
    return result["mods"] if manifest else result["mods"]["mod"]


def facts(*files, out=None):
    out = out or scratch(".facts.json")
    run(["dotnet", tool, "analyze", "--json", scratch(".result.json"), "--facts", out] + present(files))
    with open(out) as f:
        return json.load(f)["files"]


def once(fn):
    """Shared setup that several groups need: computed by the first group to ask, then reused."""
    lock, value = threading.Lock(), []
    def get():
        with lock:
            if not value:
                value.append(fn())
            return value[0]
    return get


@once
def game_profile():
    """The game-API map of the game stand-in (KSA)."""
    profile = j("game-profile.json")
    stub = fx("game-api/stub", "KSA.dll")
    if not runtime_dir:
        raise RuntimeError("no Microsoft.NETCore.App runtime found (dotnet --list-runtimes): the game profile is made with its System.Linq.dll")
    # A runtime assembly next to the game's: the profile must leave it out (checked in game-api).
    run(["dotnet", tool, "profile", "--out", profile, stub, os.path.join(runtime_dir, "System.Linq.dll")])
    return profile


@once
def harmony():
    """The Harmony stand-in (0Harmony) as a trusted library: (allowlist, library profile)."""
    harmony = fx("harmony-patch/stub", "0Harmony.dll")
    allow_harmony = write_json(j("allow-harmony.json"), {"libraries": {sha256(harmony): {"name": "0Harmony"}}})
    harmony_profile = j("library-profiles-harmony.json")
    run(["dotnet", tool, "profile", "--library", "--allowlist", allow_harmony, "--out", harmony_profile, harmony])
    return allow_harmony, harmony_profile


def g_policy():
    # policy: `darkmatter version` loads and validates the built-in policy (`darkmatter policy` only prints it)
    p = run(["dotnet", tool, "version"], expect=None)
    policy_file = os.path.join(REPO, "policy", "policy.jsonc")
    with open(policy_file) as f:
        want = re.search(r'^\s*"version":\s*"([^"]+)"', f.read(), re.M).group(1)
    stamp = json.loads(p.stdout) if p.returncode == 0 else {}
    check("policy: built-in policy loads and validates, and is policy/policy.jsonc",
          p.returncode == 0 and stamp["policy"]["version"] == want and stamp["policy"]["sha256"] == sha256(policy_file), (p.returncode, p.stdout, p.stderr))
    p = run(["dotnet", tool, "policy"])
    bad = j("bad-policy.jsonc")
    with open(bad, "w") as f:
        f.write(p.stdout.replace('"informational": [', '"informational": ["nonexistent", '))
    p = run(["dotnet", tool, "analyze", "--policy", bad, corrupt], expect=None)
    check("policy: a capability no rule produces is rejected", p.returncode != 0 and "nonexistent" in p.stderr, p.stderr)
    builtin = run(["dotnet", tool, "policy"]).stdout
    with open(bad, "w") as f:
        f.write(builtin.replace('"id": "clipboard"', '"id": "devices"', 1))
    p = run(["dotnet", tool, "analyze", "--policy", bad, corrupt], expect=None)
    check("policy: two labels with one id are rejected", p.returncode != 0 and "label id 'devices' is used more than once" in p.stderr, p.stderr)
    # A capability or finding must have exactly one home, and one group within "broadAccess".
    for what, old, new, error in [
        ("a capability in two broadAccess groups", '"native-code": "Runs native code",',
         '"native-code": "Runs native code",\n        "raw-memory": "Reads or writes raw memory",', "capability 'raw-memory' must appear in exactly one of"),
        ("a capability in both broadAccess and informational", '"informational": [', '"informational": ["raw-memory", ', "capability 'raw-memory' must appear in exactly one of"),
        ("a capability in both broadAccess and a label", '"native-code": "Runs native code",',
         '"native-code": "Runs native code",\n        "network": "Connects",', "capability 'network' must appear in exactly one of"),
        ("a finding in two broadAccess groups", '"native-code": "Runs native code",',
         '"native-code": "Runs native code",\n        "unanalyzed-call": "Calls other code",', "finding 'unanalyzed-call' must appear in exactly one broadAccess group"),
        ("a finding in no group", '"unanalyzed-call": "Calls code that was not analyzed"', '"raw-memory-other": "x"', "finding 'unanalyzed-call' must appear in exactly one broadAccess group"),
        ("a combination in a group that does not exist", '"group": "system-access", "text": "Connects to the internet and changes files where',
         '"group": "nowhere", "text": "Connects to the internet and changes files where', "names group 'nowhere', which is not a broadAccess group"),
        ("a tier without a summary", '"summary": "It can only do what\'s listed."', '"summary": ""', "tier 'limited-access' needs a name and a summary"),
    ]:
        twice = j("policy-twice.jsonc")
        with open(twice, "w") as f:
            f.write(builtin.replace(old, new, 1))
        p = run(["dotnet", tool, "analyze", "--policy", twice, corrupt], expect=None)
        check(f"policy: {what} is rejected", old in builtin and p.returncode != 0 and error in p.stderr, p.stderr)



def g_reflection():
    # reflection
    r = analyze(fx("reflection", "ReflectionFixture.dll"))
    check("reflection: constant type name is labelled", INTERNET in labels(r), r)
    check("reflection: runtime-built type name is Broad access",
          r["tier"] == "broad-access" and any("ByRuntimeName" in e for e in evidence(r)), r)
    check("reflection: constant type name is not reported as unresolved (the runtime-built one is)",
          not any("ByConstant" in e and "runtime value" in e for e in evidence(r))
          and any("ByRuntimeName" in e and "runtime value" in e for e in evidence(r)), r)



def g_impersonation():
    # impersonation and the allowlist
    fake = fx("impersonation", "0Harmony.dll")
    r = analyze(fake, allowlist=write_json(j("allow-fake.json"), {"libraries": {"0" * 64: {"name": "0Harmony"}}}))
    check("impersonation: trusted name with unknown hash is analyzed and Broad access",
          INTERNET in labels(r) and r["warnings"] and r["tier"] == "broad-access"
          and "Ships a file named like a part of .NET, the game or a trusted library" in reasons(r), r)
    r = analyze(fake, allowlist=write_json(j("allow-real.json"), {"libraries": {sha256(fake): {"name": "0Harmony"}}}))
    check("allowlist: matching hash is skipped", r["trusted"] == ["0Harmony"] and not r["labels"], r)



def g_library():
    # library propagation
    mod_dll = fx("library-propagation/mod", "PropagationMod.dll")
    lib_dll = os.path.join(os.path.dirname(mod_dll), "NetHelper.dll")
    r = analyze(mod_dll, lib_dll)
    check("propagation: a bundled library's network use labels the mod", INTERNET in labels(r), r)
    check("propagation: a call into a bundled library is accounted for", r["tier"] == "limited-access", r)
    r = analyze(mod_dll)
    check("boundary: a call into an assembly that was not analyzed is Broad access, not fully checked",
          r["tier"] == "broad-access" and groups(r) == {UNCHECKED: [UNANALYZED]}
          and any("NetHelper.Downloader::Fetch in NetHelper" in e for e in evidence(r)), r)
    allow_lib = write_json(j("allow-lib.json"), {"libraries": {sha256(lib_dll): {"name": "NetHelper"}}})
    r = analyze(mod_dll, lib_dll, allowlist=allow_lib)
    check("library: a trusted library without a profile is not analyzed (fails closed)",
          r["trusted"] == ["NetHelper"] and r["tier"] == "broad-access" and UNANALYZED in groups(r).get(UNCHECKED, [])
          and any("no library profile" in e for e in evidence(r)), r)
    tampered = j("tampered", "NetHelper.dll")
    os.makedirs(os.path.dirname(tampered))
    shutil.copy(lib_dll, tampered)
    with open(tampered, "ab") as f:
        f.write(b"\0")
    r = analyze(mod_dll, tampered, allowlist=allow_lib)
    check("propagation: a modified copy of a trusted library is analyzed", INTERNET in labels(r) and r["warnings"], r)

    # trusted-library profiles: the libraries are profiled by hash, and calls into them apply the profile
    full_dll = fx("library-propagation/mod-full", "PropagationModFull.dll")
    exempt_dll = fx("library-propagation/mod-exempt", "PropagationModExempt.dll")
    tools_dll = os.path.join(os.path.dirname(full_dll), "ToolHelper.dll")
    allow_lib = write_json(j("allow-libs.json"), {"libraries": {sha256(lib_dll): {"name": "NetHelper"}, sha256(tools_dll): {"name": "ToolHelper"}}})
    lib_profile = j("library-profiles.json")
    run(["dotnet", tool, "profile", "--library", "--allowlist", allow_lib, "--out", lib_profile, lib_dll, tools_dll, tampered])
    with open(lib_profile) as f:
        profiled = json.load(f)["libraries"]
    check("library: only allowlisted files are profiled, keyed by hash",
          sorted(profiled) == sorted([sha256(lib_dll), sha256(tools_dll)]), list(profiled))
    r = analyze(mod_dll, allowlist=allow_lib, libraries=lib_profile)
    check("library: a call into a trusted library applies its profile's labels",
          r["tier"] == "limited-access" and INTERNET in labels(r), r)
    r = analyze(mod_dll, lib_dll, allowlist=allow_lib, libraries=lib_profile)
    check("library: a shipped trusted copy resolves to its profile", r["tier"] == "limited-access" and INTERNET in labels(r), r)
    r = analyze(full_dll, allowlist=allow_lib, libraries=lib_profile)
    check("library: a member reaching a Broad-access capability (through an override) makes the mod Broad access",
          r["tier"] == "broad-access" and "Starts other programs" in reasons(r)
          and any("ToolHelper.Job::Run" in e and "StartJob::Run" in e for e in evidence(r)), r)
    r = analyze(exempt_dll, allowlist=allow_lib, libraries=lib_profile)
    check("library: code generation in a library member is Broad access", "Builds code at run time" in reasons(r), r)
    marker = '"libraries": {\n    "exempt": ['
    exempt_policy = j("policy-exempt.jsonc")
    with open(exempt_policy, "w") as f:
        f.write(builtin.replace(marker, marker + '\n      { "library": "ToolHelper", "member": "ToolHelper.Compiler::", '
                                '"caps": ["code-generation", "unresolved-reflection"], "reason": "test" },', 1))
    exempt_profile = j("library-profiles-exempt.json")
    run(["dotnet", tool, "profile", "--library", "--allowlist", allow_lib, "--policy", exempt_policy, "--out", exempt_profile, lib_dll, tools_dll])
    r = analyze(exempt_dll, allowlist=allow_lib, libraries=exempt_profile, policy=exempt_policy)
    check("library: an exempt member does not pass its Broad-access capability", marker in builtin and r["tier"] == "limited-access", r)
    r = analyze(full_dll, allowlist=allow_lib, libraries=exempt_profile, policy=exempt_policy)
    check("library: an exemption covers only the members and capabilities it names", r["tier"] == "broad-access", r)
    p = run(["dotnet", tool, "analyze", "--allowlist", allow_lib, "--library-profile", exempt_profile, mod_dll], expect=None)
    check("library: a profile made with another policy is refused", p.returncode != 0 and "different policy" in p.stderr, p.stderr)
    allow_two = write_json(j("allow-two.json"), {"libraries": {sha256(lib_dll): {"name": "NetHelper"}, "1" * 64: {"name": "NetHelper"}}})
    r = analyze(mod_dll, allowlist=allow_two, libraries=lib_profile)
    check("library: a trusted version without a profile fails closed",
          r["tier"] == "broad-access" and UNANALYZED in groups(r).get(UNCHECKED, []) and any("no library profile for trusted file 111111111111" in e for e in evidence(r)), r)



def g_game_api():
    # game-API map: emit from the game stub, then apply to the mod
    stub = fx("game-api/stub", "KSA.dll")
    game_mod = fx("game-api/mod", "GameApiMod.dll")
    profile = game_profile()
    with open(profile) as f:
        game = json.load(f)
    methods = game["methods"]
    check("game-api: profile maps the save method to game saves", methods.get("KSA.GameSaves::MakeSave") == ["file-saves"], methods)
    check("game-api: profile lists the game's assemblies and skips the runtime's", game.get("assemblies") == ["KSA"], game.get("assemblies"))
    check("game-api: profile keeps Broad-access capabilities", methods.get("KSA.Links::Open") == ["process-start"], methods)
    check("game-api: profile leaves out exempt capabilities, or maps them to a label",
          "KSA.Vec3::First" not in methods and methods.get("KSA.UpdateAvailablePopup::OpenBrowser") == ["shell-open"], methods)
    # C5 (policy 34): the map records the game's inline arrays; a span over one is checked against the recorded length.
    check("game-api: profile lists the game's inline arrays with their length and element",
          game.get("inlineArrays") == {"KSA.Slots7": {"length": 7, "element": "System.Int32"}}, game.get("inlineArrays"))
    # D2, D3 (policy 35, format 7): the map records the declared type of every member of every game type, and the
    # interfaces each game type implements.
    mt = game.get("memberTypes", {})
    check("game-api: profile records the declared types of game members (class types, '?' for anything else or two types)",
          mt.get("KSA.Universe", {}).get("field:Current") == "KSA.Craft|KSA" and mt["KSA.Universe"].get("property:Focus") == "KSA.Craft|KSA"
          and mt["KSA.Universe"].get("method:Find") == "KSA.Craft|KSA" and mt["KSA.Universe"].get("field:Anything") == "?"
          and mt.get("KSA.Craft", {}).get("method:Update") == "?" and "KSA.IPayload" in mt, {k: mt.get(k) for k in ("KSA.Universe", "KSA.Craft")})
    check("game-api: profile records the interfaces of game types",
          game.get("interfaces", {}).get("KSA.Satellite") == ["KSA.IPayload"], game.get("interfaces"))
    r = analyze(game_mod, profile=profile)
    check("game-api: mod inherits the label from the map", labels(r) == [SAVES] and r["tier"] == "limited-access", r)
    check("game-api: a span over a game inline array is not raw memory", RAW_MEMORY not in reasons(r), r)
    r = analyze(fx("game-api/mod-full", "GameApiModFull.dll"), profile=profile)
    check("game-api: a game member reaching a Broad-access capability makes the mod Broad access",
          r["tier"] == "broad-access" and "Starts other programs" in reasons(r) and any("KSA.Links::Open (game API)" in e for e in evidence(r)), r)
    check("game-api: foreach over a game inline array (its element reference taken with the loop variable) stays raw memory",
          RAW_MEMORY in reasons(r) and any("InlineArrayElementRef" in e and "index or length is not a constant" in e for e in evidence(r)), evidence(r))
    # A copy of the mod whose span over the game inline array asks for 8 elements (ldc.i4.7 before the helper
    # call becomes ldc.i4.8): one past the recorded length, raw memory. Without a game profile the game type is
    # one the check cannot lay out: raw memory too.
    with open(game_mod, "rb") as f:
        pe = f.read()
    hits = [m.start() for m in re.finditer(rb"\x1d\x28...\x2b", pe)]
    assert len(hits) == 1, hits
    long_mod = os.path.join(j("mod-long-span"), "GameApiMod.dll")
    os.makedirs(os.path.dirname(long_mod))
    with open(long_mod, "wb") as f:
        f.write(pe[:hits[0]] + b"\x1e" + pe[hits[0] + 1:])
    r = analyze(long_mod, profile=profile)
    check("game-api: a span of one more element than the game inline array has is raw memory",
          r["tier"] == "broad-access" and groups(r) == {DEEP: [RAW_MEMORY]} and any("constant 8 is outside the buffer length 7" in e for e in evidence(r)), r)
    r = analyze(game_mod)
    check("game-api: without a game profile, a span over a game inline array is raw memory",
          RAW_MEMORY in reasons(r) and any("a game type the game-API map does not list as an inline array" in e for e in evidence(r)), evidence(r))
    r = analyze(fx("game-api/mod-exempt", "GameApiModExempt.dll"), profile=profile)
    check("game-api: exempt game members do not make the mod Broad access", r["tier"] == "limited-access" and labels(r) == [WEBSITES], r)
    stale = dict(game)
    del stale["format"]
    p = run(["dotnet", tool, "analyze", "--game-profile", write_json(j("game-profile-stale.json"), stale), game_mod], expect=None)
    check("game-api: a profile from an older tool is refused", p.returncode != 0 and "older version" in p.stderr, p.stderr)
    del game["assemblies"]
    r = analyze(game_mod, profile=write_json(j("game-profile-old.json"), game))
    check("game-api: a profile without an assembly list falls back to the policy's game assemblies",
          labels(r) == [SAVES] and r["tier"] == "limited-access", r)
    r = analyze(game_mod)
    check("game-api: without a profile, a call into the game is still accounted for (the inline-array span is the only reason)",
          r["tier"] == "broad-access" and groups(r) == {DEEP: [RAW_MEMORY]} and not labels(r), r)
    other = dict(game, assemblies=["SomethingElse"])
    r = analyze(game_mod, profile=write_json(j("game-profile-other.json"), other))
    # H9: one named like the game's (KSA) that this build does not have is said as such, in the same group.
    check("game-api: an assembly the profile does not list is not the game, and one named like it is game code this version lacks",
          r["tier"] == "broad-access" and groups(r) == {DEEP: [RAW_MEMORY], UNCHECKED: ["Calls game code that this game version does not have"]}
          and any(e.startswith("KSA.GameSaves::MakeSave in KSA, an assembly named like the game's that this game build does not have") for e in evidence(r)), r)

    # What the map has not read (H5): a copy of the game stand-in with Unreadable.Run's marker
    # constant (ldc.i4 0x5EADBEEF) turned into an undefined opcode and Vanishing.RemovedInThisBuild
    # renamed, profiled with a game file that cannot be read.
    with open(stub, "rb") as f:
        pe = f.read()
    for old, new in [(b"\x20\xef\xbe\xad\x5e", b"\xa6\xef\xbe\xad\x5e"), (b"RemovedInThisBuild", b"RemovedInThisBuilt")]:
        assert pe.count(old) == 1, (old, pe.count(old))
        pe = pe.replace(old, new)
    patched = os.path.join(j("game-gaps"), "KSA.dll")
    os.makedirs(os.path.dirname(patched))
    with open(patched, "wb") as f:
        f.write(pe)
    broken = os.path.join(os.path.dirname(patched), "Broken.dll")
    with open(broken, "wb") as f:
        f.write(pe[:300])  # a game file cut short: it may be a .NET assembly, but cannot be read
    gaps_profile = j("game-profile-gaps.json")
    p = run(["dotnet", tool, "profile", "--out", gaps_profile, patched, broken])
    with open(gaps_profile) as f:
        gaps = json.load(f)
    check("game-api: a game method whose body cannot be decoded, and every game method reaching it, map to not analyzed",
          gaps["methods"].get("KSA.Unreadable::Run") == ["unanalyzed-call"] and gaps["methods"].get("KSA.Unreadable::Caller") == ["unanalyzed-call"]
          and "KSA.Unreadable::Run" not in methods and "1 game method could not be read (KSA.Unreadable::Run)" in p.stderr, (gaps["methods"], p.stderr))
    check("game-api: the profile lists every game member and base type, and a game file it cannot read as skipped, not as a game assembly",
          "Kept" in gaps["members"]["KSA.Vanishing"] and "X" in gaps["members"]["KSA.Vec3"] and "RemovedInThisBuild" not in gaps["members"]["KSA.Vanishing"]
          and gaps["bases"].get("KSA.StartsDerived") == "KSA.StartsBase" and "KSA.Vanishing" not in gaps["bases"]
          and [x["file"] for x in gaps["skipped"]] == ["Broken.dll"] and gaps["assemblies"] == ["KSA"] and "1 game file could not be read" in p.stderr,
          (gaps["skipped"], gaps["assemblies"], p.stderr))
    gaps_mod = fx("game-api/mod-gaps", "GameApiModGaps.dll")
    r = analyze(gaps_mod, profile=gaps_profile)
    ev = evidence(r)
    check("game-api: a call reaching game code the check cannot read is Broad access, not fully checked",
          r["tier"] == "broad-access" and groups(r) == {UNCHECKED: [UNANALYZED]}
          and any(e.startswith("KSA.Unreadable::Caller (game API)") for e in ev), r)
    check("game-api: a call to a game member this build does not define is not analyzed, unlike one it does",
          any(e.startswith("KSA.Vanishing::RemovedInThisBuild in KSA, which this game build does not define") for e in ev)
          and not any("Kept" in e for e in ev), ev)
    r = analyze(gaps_mod, profile=profile)
    check("game-api: against the game build the mod was compiled for, the same calls reach nothing", r["tier"] == "limited-access" and not r["labels"], r)

    # Members named through a derived game type (H5 review): a copy of the mod whose references to the
    # derived types' own members name a member of the game base type, of the framework base type, and
    # of neither instead (a mod built against a build where the derived types declared them; the
    # runtime looks a member reference up through the base types).
    with open(gaps_mod, "rb") as f:
        pe = f.read()
    for old, new in [(b"DeclaredHere", b"InheritedRun"), (b"OwnTrimmer", b"TrimExcess"), (b"OwnMissing", b"NoSuchName")]:
        assert pe.count(old) == 1, (old, pe.count(old))
        pe = pe.replace(old, new)
    inherited_mod = os.path.join(j("mod-inherited"), "GameApiModGaps.dll")
    os.makedirs(os.path.dirname(inherited_mod))
    with open(inherited_mod, "wb") as f:
        f.write(pe)
    r = analyze(inherited_mod, profile=profile)
    ev = evidence(r)
    check("game-api: a member named through a derived game type is the base type's: the game's map entry, the framework's rules, or not analyzed when neither has it",
          r["tier"] == "broad-access" and groups(r) == {SYSTEM: ["Starts other programs"], UNCHECKED: [UNANALYZED]}
          and any(e.startswith("KSA.StartsDerived::InheritedRun (game API KSA.StartsBase::InheritedRun, inherited)") for e in ev)
          and any(e.startswith("KSA.ListDerived::NoSuchName in KSA, which this game build does not define") for e in ev)
          and not any("TrimExcess" in e for e in ev), r)



def g_classification():
    # classification: framework members must match a policy rule
    r = analyze(fx("classification/safe", "ClassificationSafe.dll"))
    check("classification: safe-listed framework members are Limited access", r["tier"] == "limited-access" and not r["labels"], r)
    r = analyze(fx("classification/unclassified", "ClassificationUnclassified.dll"))
    check("classification: a framework member no rule matches is Broad access, not fully checked",
          r["tier"] == "broad-access" and groups(r) == {UNCHECKED: [UNCLASSIFIED]}
          and any("System.AppContext::SetSwitch" in e for e in evidence(r)), r)



def g_file_access():
    # labels and file access
    r = analyze(fx("labels", "LabelsFixture.dll"))
    check("labels: bundled labels", labels(r) == [INFO, SETTINGS, CLOSES] and r["tier"] == "limited-access", r)
    r = analyze(fx("file-access", "FileAccessFixture.dll"))
    check("file-access: writes are labelled by where they go", labels(r) == [CODE_FILES, FILES_OUT] and r["tier"] == "limited-access", r)
    by_label = {l["text"]: l["evidence"] for l in r["labels"]}
    check("results: each label has its id and every piece of its evidence, sorted, with the count",
          [l["id"] for l in r["labels"]] == ["game-folder-writes", "outside-writes"]
          and all(l["count"] == len(l["evidence"]) > 0 and l["evidence"] == sorted(set(l["evidence"])) for l in r["labels"]), r["labels"])
    check("results: each Broad-access reason has its id", all(x["id"] for g in r["broadAccess"] for x in g["reasons"]), r["broadAccess"])
    check("file-access: the write to the mod's own folder is a code-folder write, not an outside one",
          any("WriteOwnConfig" in e for e in by_label.get(CODE_FILES, []))
          and not any("WriteOwnConfig" in e for e in by_label.get(FILES_OUT, [])), r)
    r = analyze(fx("download", "DownloadFixture.dll"))
    check("file-access: a network connection and a write into the mod's own folder are Broad access",
          r["tier"] == "broad-access" and groups(r) == {SYSTEM: ["Connects to the internet and changes files where the game loads code from"]}
          and INTERNET in labels(r) and CODE_FILES in labels(r), r)
    p = run(["dotnet", tool, "policy"])
    combo = j("policy-combo.jsonc")
    with open(combo, "w") as f:
        f.write(p.stdout.replace('"caps": ["network", "file-write-code"]', '"caps": ["network", "native-code"]', 1))
    p = run(["dotnet", tool, "analyze", "--policy", combo, corrupt], expect=None)
    check("policy: a combination of a Broad-access capability is rejected", p.returncode != 0 and "Broad access on its own" in p.stderr, p.stderr)
    with open(combo, "w") as f:
        f.write(builtin.replace('"caps": ["network", "file-write-code"]', '"caps": ["network", "raw-memory"]', 1))
    p = run(["dotnet", tool, "analyze", "--policy", combo, corrupt], expect=None)
    check("policy: a combination of a deep-game-access capability is rejected",
          p.returncode != 0 and "Broad access on its own (Deep game access)" in p.stderr, p.stderr)



def g_shell_open():
    # opening websites vs starting programs
    r = analyze(fx("shell-open/link", "ShellOpenLink.dll"))
    check("shell-open: a fixed web address is Limited access", labels(r) == [WEBSITES] and r["tier"] == "limited-access", r)
    r = analyze(fx("shell-open/program", "ShellOpenProgram.dll"))
    check("shell-open: starting a program or an arbitrary target is Broad access",
          r["tier"] == "broad-access" and "Starts other programs" in groups(r).get(SYSTEM, [])
          and len(r["broadAccess"][0]["reasons"][0]["evidence"]) == 2, r)



def g_raw_memory():
    # raw memory
    r = analyze(fx("raw-memory/safe", "RawMemorySafe.dll"))
    check("raw-memory: compiler-generated span helpers are not raw memory", r["tier"] == "limited-access", r)
    unsafe_dll = fx("raw-memory/unsafe", "RawMemoryUnsafe.dll")
    r = analyze(unsafe_dll)
    check("raw-memory: pointer code is Broad access, deep game access only",
          r["tier"] == "broad-access" and groups(r) == {DEEP: [RAW_MEMORY]}, r)
    p = run(["dotnet", tool, "analyze", unsafe_dll])
    check("raw-memory: the text report gives the tier summary and the group",
          "It can do anything a program on your computer can." in p.stdout and "Why: Deep game access\n" in p.stdout
          and "Deep game access: Works with the game's code and memory directly" in p.stdout and "System access" not in p.stdout, p.stdout)
    # One mod with reasons in two groups: both groups are kept, in policy order.
    reflection_dll = fx("reflection", "ReflectionFixture.dll")
    r = analyze(unsafe_dll, reflection_dll)
    check("tiers: a mod with reasons in two groups is Broad access and lists both",
          r["tier"] == "broad-access" and r["tierName"] == "Broad access"
          and r["tierSummary"] == "It can do anything a program on your computer can."
          and [g["group"] for g in r["broadAccess"]] == [DEEP, SYSTEM] and r["broadAccess"][1]["name"] == "System access"
          and groups(r)[DEEP] == [RAW_MEMORY] and UNTRACED in groups(r)[SYSTEM] and INTERNET in labels(r), r)
    p = run(["dotnet", tool, "analyze", unsafe_dll, reflection_dll])
    check("tiers: the text report lists every group",
          "Why: Deep game access · System access\n" in p.stdout and "  System access: Uses features that can reach anything on your computer.\n" in p.stdout, p.stdout)
    r = analyze(fx("raw-memory/safe", "RawMemorySafe.dll"))
    check("tiers: a Limited-access mod has the tier's name and summary and no group",
          r["tierName"] == "Limited access" and r["tierSummary"] == "It can only do what's listed." and r["broadAccess"] == [], r)
    raw = facts(unsafe_dll)[0]["caps"].get("raw-memory", [])
    check("raw-memory: a pointer type in a referenced signature is recorded",
          any("pointer type in the signature of System.IntPtr::ToPointer" in e for e in raw), raw)
    check("raw-memory: a store through a non-managed address is recorded",
          any(e.startswith("stind.i8 through an address") for e in raw), raw)



def g_fail_open():
    # fail-open cases
    fail_open_dll = fx("fail-open", "FailOpenFixture.dll")
    r = analyze(fail_open_dll)
    check("fail-open: P/Invoke and COM activation are Broad access",
          "Runs native code" in reasons(r) and "Starts a COM component" in reasons(r), r)
    corrupted = j("Corrupted.dll")
    run(["dotnet", corrupt, fail_open_dll, corrupted])
    r = analyze(corrupted)
    check("fail-open: undecodable IL is Broad access", "Contains code the check cannot read" in reasons(r), r)
    junk = j("junk.dll")
    with open(junk, "wb") as f:
        f.write(b"not a PE file")
    r = analyze(junk)
    check("fail-open: an unreadable file is Broad access, not fully checked", groups(r) == {UNCHECKED: ["Contains a file the check cannot read"]}, r)
    # ELF and Mach-O libraries are native binaries, counted once as that, not as unreadable files. The
    # universal Mach-O is the 64-bit form in reversed byte order (0xBFBAFECA), which extraction also
    # counts as code (G2a, review A6).
    natives = []
    for name, magic in [("libnative.so", b"\x7fELF\x02\x01\x01"), ("libnative.dylib", b"\xcf\xfa\xed\xfe\x07\x00\x00\x01"),
                        ("libuniversal.dylib", b"\xbf\xba\xfe\xca\x00\x00\x00\x02")]:
        natives.append(j(name))
        with open(natives[-1], "wb") as f:
            f.write(magic + b"\0" * 64)
    r = analyze(*natives)
    check("fail-open: ELF and Mach-O files (thin and universal) are native binaries, not unreadable files",
          groups(r) == {SYSTEM: ["Ships a native program or library"]} and len(r["broadAccess"][0]["reasons"][0]["evidence"]) == 3, r)
    # precompiled native code: the shared framework's own assemblies are ReadyToRun images
    if not runtime_dir:
        check("fail-open: a ReadyToRun image is Broad access", False, "no Microsoft.NETCore.App runtime found (dotnet --list-runtimes)")
    else:
        r = analyze(os.path.join(runtime_dir, "System.Linq.dll"))
        native = [e for g in r["broadAccess"] if g["group"] == SYSTEM for x in g["reasons"] if x["text"] == "Runs native code" for e in x["evidence"]]
        check("fail-open: a ReadyToRun image is Broad access", r["tier"] == "broad-access" and any("precompiled native code" in e for e in native), groups(r))
    p = run(["dotnet", tool, "analyze", "--allowlist", j("missing.json"), fail_open_dll], expect=None)
    check("cli: a missing allowlist path is an error", p.returncode != 0)



def g_embedded():
    # embedded resources: one assembly per payload
    for payload, tier in EMBEDDED.items():
        r = analyze(case_dll("embedded", payload))
        ok = r["tier"] == tier and (tier == "limited-access" or EMBEDDED_BINARY in groups(r).get(UNCHECKED, []))
        if payload == "text":
            # The control must really carry its resource (name and bytes), or it tests a plain assembly.
            with open(case_dll("embedded", payload), "rb") as f:
                pe = f.read()
            with open(os.path.join(REPO, "fixtures", "embedded", "payload", "readme.txt"), "rb") as f:
                ok = ok and b"Embedded.readme.txt" in pe and f.read() in pe
        check(f"embedded: {payload} resource is {tier}", ok, {"tier": r["tier"], "broadAccess": r["broadAccess"]})



def g_harmony_patch():
    # Harmony patch attributes: the stand-in 0Harmony is a trusted library with a profile
    allow_harmony, harmony_profile = harmony()
    profile = game_profile()
    for case, expected in HARMONY_PATCH.items():
        r = analyze(case_dll("harmony-patch/mod", case), allowlist=allow_harmony, libraries=harmony_profile, profile=profile)
        check(f"harmony-patch: {case}", expect(r, expected), {"tier": r["tier"], "labels": labels(r), "broadAccess": groups(r)})
    r = analyze(case_dll("harmony-patch/mod", "GameFullTarget"), allowlist=allow_harmony, libraries=harmony_profile)
    check("harmony-patch: without a game profile, a patched game member adds nothing", r["tier"] == "limited-access", r)



def g_reflection_precision():
    allow_harmony, harmony_profile = harmony()
    profile = game_profile()
    # reflection the check traces: member arrays, parameters, iterators, expression trees, bounded types
    for case, expected in REFLECTION_PRECISION.items():
        r = analyze(case_dll("reflection-precision", case), allowlist=allow_harmony, libraries=harmony_profile, profile=profile)
        check(f"reflection-precision: {case}", expect(r, expected),
              {"tier": r["tier"], "labels": labels(r), "broadAccess": groups(r)})
    # The bounded reason is deep game access only: the same mod has no other group, and no unresolved reflection.
    r = analyze(case_dll("reflection-precision", "BoundedGameType"),
                allowlist=allow_harmony, libraries=harmony_profile, profile=profile)
    check("reflection-precision: bounded reflection is in the deep-game-access group only",
          groups(r) == {DEEP: [BOUNDED]} and UNTRACED not in reasons(r), r)
    # G5b: the other mod's assembly is named in the evidence; without the game profile's type list, a game type
    # found by name alone is code that was not analyzed (it fails closed).
    r = analyze(case_dll("reflection-precision", "OtherModType"), allowlist=allow_harmony, libraries=harmony_profile, profile=profile)
    check("reflection-precision: a type in another mod's assembly is named as not analyzed",
          any("OtherMod.Tools" in e and "(in OtherMod, which was not analyzed)" in e for e in evidence(r)), r)
    r = analyze(case_dll("reflection-precision", "GameTypeFoundByName"), allowlist=allow_harmony, libraries=harmony_profile)
    check("reflection-precision: without a game profile, a game type found by name is code that was not analyzed",
          r["tier"] == "broad-access" and groups(r) == {UNCHECKED: [UNANALYZED]} and any("KSA.Links::Open" in e for e in evidence(r)), r)
    # D5: a game type found by name is the game's only when nothing else the lookup can find has that name; with the
    # mod's other assembly defining one, the member typed from the game-API map is unresolved reflection.
    r = analyze(case_dll("reflection-precision", "ValueByName"), case_dll("reflection-precision", "ShadowUniverse"),
                allowlist=allow_harmony, libraries=harmony_profile, profile=profile)
    check("reflection-precision: a game type found by name that the mod also defines is not typed from the game-API map",
          r["tier"] == "broad-access" and UNTRACED in groups(r).get(SYSTEM, [])
          and any("KSA.Universe::Current (Field, a type found by name)" in e for e in evidence(r)), r)
    # D5: without a game profile, the declared type of a game field is not known: its value is untraced (fails closed).
    r = analyze(case_dll("reflection-precision", "ValueFieldGame"), allowlist=allow_harmony, libraries=harmony_profile)
    check("reflection-precision: without a game profile, a value read from a game field is untraced",
          r["tier"] == "broad-access" and UNTRACED in groups(r).get(SYSTEM, []), r)
    # H7: hand-written IL, written by the generator into this run's temp folder and only analyzed.
    probes = j("il-probes")
    os.makedirs(probes, exist_ok=True)
    run(["dotnet", fx("il-probes", "IlProbes.dll"), probes])
    for case, expected in IL_PROBES.items():
        r = analyze(os.path.join(probes, case + ".dll"))
        check(f"reflection-precision: IL probe {case}", expect(r, expected),
              {"tier": r["tier"], "labels": labels(r), "broadAccess": groups(r)})
    # H3: a trusted-library member found ignoring case is named as the member it is.
    r = analyze(case_dll("reflection-precision", "TrustedIgnoreCase"), allowlist=allow_harmony, libraries=harmony_profile, profile=profile)
    check("reflection-precision: a library member found ignoring case is the member found",
          any("HarmonyLib.Harmony::Patch traces its arguments only at a direct call" in e for e in evidence(r)), r)



def g_game_interaction():
    allow_harmony, harmony_profile = harmony()
    profile = game_profile()
    # game interaction: transpilers, observing patches, opening own folders, network values, named lookups, XML
    for case, expected in GAME_INTERACTION.items():
        r = analyze(case_dll("game-interaction", case), allowlist=allow_harmony, libraries=harmony_profile, profile=profile)
        check(f"game-interaction: {case}", expect(r, expected),
              {"tier": r["tier"], "labels": labels(r), "broadAccess": groups(r)})



def g_evasion():
    allow_harmony, harmony_profile = harmony()
    # evasion fixtures: one assembly per case
    for case, expected in EVASION.items():
        # The Harmony cases reference the trusted stand-in 0Harmony (see fixtures/evasion/evasion.csproj).
        r = analyze(case_dll("evasion", case), allowlist=allow_harmony, libraries=harmony_profile)
        check(f"evasion: {case}", expect(r, expected), {"tier": r["tier"], "labels": labels(r), "broadAccess": groups(r)})
    # H8: the unsafe compile flag is still recorded, as an informational capability.
    caps = facts(case_dll("evasion", "UnsafeFlagOnly"))[0]["caps"]
    check("evasion: the unsafe compile flag alone is recorded as informational, not raw memory",
          caps.get("unsafe-code") == ["assembly is compiled with unsafe code enabled"] and "raw-memory" not in caps, caps)



def g_pipeline():
    # extraction and manifests: darkmatter-pipeline extract
    sample_dll = fx("reflection", "ReflectionFixture.dll")
    with open(sample_dll, "rb") as f:
        sample = f.read()
    os.makedirs(j("downloads", "SampleMod"))
    with zipfile.ZipFile(j("downloads", "SampleMod", "SampleMod.zip"), "w") as z:
        z.write(fx("reflection", "ReflectionFixture.dll"), "SampleMod/ReflectionFixture.dll")
        z.writestr("../escape.txt", "x")
        z.writestr("/absolute.txt", "x")
    os.makedirs(j("downloads", "ContentMod"))
    with zipfile.ZipFile(j("downloads", "ContentMod", "ContentMod.zip"), "w") as z:
        z.writestr("ContentMod/parts.toml", "content")
    os.makedirs(j("downloads", "NestedMod"))
    inner = j("inner.zip")
    with zipfile.ZipFile(inner, "w") as z:
        z.write(fx("reflection", "ReflectionFixture.dll"), "ReflectionFixture.dll")
    with zipfile.ZipFile(j("downloads", "NestedMod", "NestedMod.zip"), "w") as z:
        z.write(inner, "NestedMod/payload.zip")
        z.writestr("NestedMod/hidden.7z", "7z\xbc\xaf\x27\x1c")
    os.makedirs(j("downloads", "ScriptMod"))
    with zipfile.ZipFile(j("downloads", "ScriptMod", "ScriptMod.zip"), "w") as z:
        z.writestr("ScriptMod/parts.toml", "content")
        z.writestr("ScriptMod/install.bat", "@echo off")
    os.makedirs(j("downloads", "ArchiveMod"))
    with open(j("downloads", "ArchiveMod", "ArchiveMod.7z"), "wb") as f:
        f.write(b"7z")
    # a tar.gz with links, a device, a pipe and traversal entries next to a real code file
    os.makedirs(j("downloads", "TarMod"))
    with tarfile.open(j("downloads", "TarMod", "TarMod.tar.gz"), "w:gz") as t:
        def add(name, kind=tarfile.REGTYPE, data=b"", link=""):
            info = tarfile.TarInfo(name)
            info.type, info.linkname, info.size = kind, link, len(data)
            t.addfile(info, io.BytesIO(data) if data else None)
        add("TarMod/ReflectionFixture.dll", data=sample)
        add("TarMod/link.dll", tarfile.SYMTYPE, link="/etc/passwd")
        add("TarMod/hard.dll", tarfile.LNKTYPE, link="TarMod/ReflectionFixture.dll")
        add("TarMod/pipe", tarfile.FIFOTYPE)
        add("TarMod/null", tarfile.CHRTYPE)
        add("../up.dll", data=sample)
        add("/abs.dll", data=sample)
    # two entries that are one file on Windows and macOS; a zip link entry holding a program
    os.makedirs(j("downloads", "CaseMod"))
    with zipfile.ZipFile(j("downloads", "CaseMod", "CaseMod.zip"), "w") as z:
        z.writestr("CaseMod/Mod.dll", sample)
        z.writestr("CaseMod/mod.dll", b"MZ other")
    os.makedirs(j("downloads", "ZipLinkMod"))
    with zipfile.ZipFile(j("downloads", "ZipLinkMod", "ZipLinkMod.zip"), "w") as z:
        z.writestr("ZipLinkMod/parts.toml", "content")
        link = zipfile.ZipInfo("ZipLinkMod/Evil.dll")
        link.create_system, link.external_attr = 3, 0o120777 << 16
        z.writestr(link, sample)
    # release assets that are not archives: a script, and a compressed file the check cannot open
    os.makedirs(j("downloads", "AssetMod"))
    with open(j("downloads", "AssetMod", "install.ps1"), "w") as f:
        f.write("Write-Host hi")
    with open(j("downloads", "AssetMod", "data.bin"), "wb") as f:
        f.write(b"\xfd7zXZ\x00" + b"\0" * 32)
    manifest = j("manifest.json")
    run(["dotnet", pipeline, "extract", j("downloads"), j("extracted"), "--manifest", manifest])
    escaped = [p for p in (j("escape.txt"), j("extracted", "escape.txt"), j("extracted", "SampleMod", "escape.txt"),
                           j("up.dll"), j("extracted", "up.dll"), j("extracted", "TarMod", "up.dll")) if os.path.exists(p)]
    check("extract: path-traversal entries are not written",
          not escaped and not os.path.exists("/absolute.txt") and not os.path.exists("/abs.dll"), escaped)
    links = [os.path.join(r, n) for r, ds, fs in os.walk(j("extracted")) for n in ds + fs if os.path.islink(os.path.join(r, n))]
    check("extract: links and devices are never written", not links and not os.path.exists(j("extracted", "TarMod", "TarMod", "TarMod", "pipe")), links)
    mods = analyze(manifest=manifest)
    check("manifest: each mod gets its tier",
          mods["SampleMod"]["tier"] == "broad-access" and mods["ContentMod"]["tier"] == "no-code"
          and mods["ArchiveMod"]["tier"] == "broad-access", {k: v["tier"] for k, v in mods.items()})
    nested = mods["NestedMod"]
    check("extract: an archive inside an archive is extracted and analyzed",
          any("ReflectionFixture" in (f.get("name") or "") for f in nested["files"]), nested["files"])
    check("extract: a nested archive that cannot be opened is Broad access",
          "Contains an archive the check cannot open" in reasons(nested), reasons(nested))
    check("extract: a shipped script is Broad access, not fully checked",
          mods["ScriptMod"]["tier"] == "broad-access" and "Ships a script or installer" in groups(mods["ScriptMod"]).get(UNCHECKED, []), mods["ScriptMod"])
    unopened = "Contains an archive the check cannot open"
    check("extract: an archive with unsafe entries counts as not extracted, and its other files are analyzed",
          unopened in reasons(mods["SampleMod"]) and unopened in reasons(mods["TarMod"])
          and any("ReflectionFixture" in (f.get("name") or "") for f in mods["TarMod"]["files"]),
          {k: (reasons(mods[k]), mods[k]["files"]) for k in ("SampleMod", "TarMod")})
    case_files = [n for _, _, fs in os.walk(j("extracted", "CaseMod")) for n in fs]
    check("extract: two entries whose names differ only in case are not both written, and the archive is Broad access",
          case_files == ["Mod.dll"] and unopened in reasons(mods["CaseMod"]), (case_files, reasons(mods["CaseMod"])))
    check("extract: a zip link entry is not written, and the archive is Broad access",
          not os.path.exists(j("extracted", "ZipLinkMod", "ZipLinkMod", "ZipLinkMod", "Evil.dll")) and mods["ZipLinkMod"]["tier"] == "broad-access",
          mods["ZipLinkMod"])
    check("extract: a script release asset ships a script, a compressed one is an archive the check cannot open",
          "Ships a script or installer" in reasons(mods["AssetMod"]) and unopened in reasons(mods["AssetMod"]), reasons(mods["AssetMod"]))
    # limits: bytes actually written, and nesting depth
    os.makedirs(j("downloads-limits", "BigMod"))
    with zipfile.ZipFile(j("downloads-limits", "BigMod", "BigMod.zip"), "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("zeros.bin", b"\0" * (4 << 20))
    os.makedirs(j("downloads-limits", "DeepMod"))
    blob = sample
    for level in range(3):
        b = io.BytesIO()
        with zipfile.ZipFile(b, "w") as z:
            z.writestr(f"level{level}.zip" if level else "Mod.dll", blob)
        blob = b.getvalue()
    with open(j("downloads-limits", "DeepMod", "DeepMod.zip"), "wb") as f:
        f.write(blob)
    limited = j("manifest-limits.json")
    run(["dotnet", pipeline, "extract", j("downloads-limits"), j("extracted-limits"), "--manifest", limited, "--max-bytes", "1000000", "--max-depth", "1"])
    with open(limited) as f:
        lm = json.load(f)["mods"]
    check("extract: an archive over the size limit counts as not extracted", lm["BigMod"]["unextracted"] == ["BigMod.zip"], lm["BigMod"])
    check("extract: an archive nested deeper than --max-depth counts as not extracted",
          not lm["DeepMod"]["files"] and len(lm["DeepMod"]["unextracted"]) == 1 and lm["DeepMod"]["unextracted"][0].endswith("level1.zip"), lm["DeepMod"])
    with open(manifest) as f:
        m = json.load(f)
    m["mods"]["SampleMod"]["files"][0]["sha256"] = "0" * 64
    mods = analyze(manifest=write_json(j("manifest-stale.json"), m))
    check("manifest: a file whose hash changed is not analyzed",
          "Lists a file that was not analyzed" in reasons(mods["SampleMod"]), mods["SampleMod"])

    # result tools
    analyze(manifest=manifest, json_out=j("result.json"))
    with open(j("result.json")) as f:
        changed = json.load(f)
    def group(gid, name, *texts):
        return {"group": gid, "name": name, "summary": "", "reasons": [{"text": t, "evidence": []} for t in texts]}
    changed["mods"]["ContentMod"].update(tier="broad-access", broadAccess=[group(SYSTEM, "System access", "Runs native code")])
    p = run(["dotnet", pipeline, "compare-results", j("result.json"), write_json(j("result-changed.json"), changed)])
    tier_changes, group_changes = p.stdout.split("## tier changes")[-1].split("## reason group changes (Broad access in both)")
    check("compare-results: lists the mod whose tier changed, with its new reasons",
          tier_changes.strip() == "ContentMod: no-code -> broad-access  (new: Runs native code)" and group_changes.strip() == "none", p.stdout)
    deep = json.loads(json.dumps(changed))
    deep["mods"]["ContentMod"].update(broadAccess=[group(DEEP, "Deep game access", RAW_MEMORY)])
    p = run(["dotnet", pipeline, "compare-results", write_json(j("result-deep.json"), deep), j("result-changed.json")])
    after = p.stdout.split("## ")[2]
    check("compare-results: counts three tiers and the reasons of each group, and lists a mod whose groups changed",
          "  broad-access   " in after and "  unverified" not in after
          and re.search(r"  system-access reasons \(\d+ mods\):\n(    .*\n)*       1  Runs native code\n", after)
          and p.stdout.split("## tier changes")[-1].split("## ")[0].strip() == "none"
          and p.stdout.split("(Broad access in both)")[-1].strip()
          == f"ContentMod: [{DEEP}] -> [{SYSTEM}]  (new: Runs native code)  (gone: {RAW_MEMORY})", p.stdout)
    # Results from before policy 36 name the top tier "full-access" and its groups "fullAccess": they
    # read as the new names, so a rename alone is no change.
    pre36 = json.loads(json.dumps(changed))
    for m in pre36["mods"].values():
        m["tier"] = {"broad-access": "full-access"}.get(m["tier"], m["tier"])
        m["fullAccess"] = m.pop("broadAccess")
    p = run(["dotnet", pipeline, "compare-results", write_json(j("result-pre36.json"), pre36), j("result-changed.json")])
    before = p.stdout.split("## ")[1]
    check("compare-results: reads results from before policy 36 (full-access, fullAccess) as Broad access",
          "  broad-access   " in before and "  full-access" not in before and "  system-access reasons (" in before
          and p.stdout.split("## tier changes")[-1].split("## ")[0].strip() == "none"
          and p.stdout.split("(Broad access in both)")[-1].strip() == "none", p.stdout)
    # Results from before policy 13 have four tiers and flat fullAccess and unverified lists (no
    # unverified list before policy 9): old tiers read as the new ones they became.
    old = json.loads(json.dumps(changed))
    for m in old["mods"].values():
        m["tier"] = {"no-code": "content-only", "limited-access": "known-access"}.get(m["tier"], m["tier"])
        m["fullAccess"] = [r for g in m.pop("broadAccess") for r in g["reasons"]]
    old["mods"]["ContentMod"].update(tier="unverified", fullAccess=[], unverified=[{"text": UNANALYZED, "evidence": []}])
    p = run(["dotnet", pipeline, "compare-results", write_json(j("result-old.json"), old), j("result-changed.json")])
    before = p.stdout.split("## ")[1]
    check("compare-results: reads results from before policy 13",
          "  content-only" not in before and "  unverified reasons (1 mods):\n       1  " + UNANALYZED in before
          and p.stdout.split("## tier changes")[-1].split("## ")[0].strip() == "none"
          and f"ContentMod: [unverified] -> [{SYSTEM}]" in p.stdout.split("(Broad access in both)")[-1], p.stdout)
    facts(fx("classification/unclassified", "ClassificationUnclassified.dll"), out=j("facts.json"))
    p = run(["dotnet", pipeline, "rank-unclassified", j("facts.json"), "--by", "type"])
    check("rank-unclassified: ranks the unclassified framework type", "System.AppContext" in p.stdout, p.stdout)



# The HTML report's template: its only tags, attributes and classes. A page made from hostile data
# must have no other (markup in the data shows as text).
REPORT_TAGS = {"html", "head", "meta", "title", "style", "body", "main", "header", "h1", "h2", "h3", "h4", "p", "section", "div", "span", "strong",
               "em", "table", "thead", "tbody", "tr", "th", "td", "ul", "li", "a", "article", "details", "summary", "code", "footer", "dl", "dt", "dd"}
REPORT_ATTRS = {"lang", "charset", "http-equiv", "content", "name", "class", "id", "href"}
REPORT_CLASSES = {"meta", "explainer", "badge", "t-none", "t-limited", "t-broad", "tiles", "tile", "n", "changes", "index", "card", "head", "summary",
                  "group-summary", "findings", "none", "count", "evidence", "files", "more", "warnings"}


class ReportPage(html.parser.HTMLParser):
    """A report page as a browser's parser sees it: tags with attributes, text, style sheets, and anything else."""
    def __init__(self, page):
        super().__init__(convert_charrefs=True)
        self.tags, self.text, self.styles, self.other, self.in_style = [], [], [], [], False
        self.feed(page)
        self.close()

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, attrs))
        self.in_style = tag == "style"
        if self.in_style:
            self.styles.append("")

    def handle_startendtag(self, tag, attrs):
        self.tags.append((tag, attrs))

    def handle_endtag(self, tag):
        self.in_style = False

    def handle_data(self, data):
        if self.in_style:
            self.styles[-1] += data
        else:
            self.text.append(data)

    def handle_comment(self, data):
        self.other.append("comment " + data)

    def handle_decl(self, decl):
        if decl.lower() != "doctype html":
            self.other.append("declaration " + decl)

    def handle_pi(self, data):
        self.other.append("processing instruction " + data)

    def unknown_decl(self, data):
        self.other.append("declaration " + data)


def report_problems(page):
    """What in a report page the template does not make: other tags, attributes, links or classes, a second
    style sheet or policy, a policy that is not the first thing after the charset or not exactly the strict one."""
    p = ReportPage(page)
    problems = list(p.other)
    ids = {v for _, attrs in p.tags for k, v in attrs if k == "id"}
    for tag, attrs in p.tags:
        if tag not in REPORT_TAGS:
            problems.append(f"tag <{tag}>")
        for k, v in attrs:
            if k not in REPORT_ATTRS:
                problems.append(f"attribute {k} on <{tag}>")
            elif k == "href" and not (re.fullmatch(r"#m\d+", v or "") and v[1:] in ids):
                problems.append(f"link {v!r}")
            elif k == "id" and not re.fullmatch(r"m\d+", v or ""):
                problems.append(f"id {v!r}")
            elif k == "class" and not set((v or "").split()) <= REPORT_CLASSES:
                problems.append(f"class {v!r}")
            elif k == "name" and v not in ("viewport", "referrer"):
                problems.append(f"meta name {v!r}")
    if len(p.styles) != 1:
        problems.append(f"{len(p.styles)} style sheets")
    policies = [(i, dict(attrs)) for i, (tag, attrs) in enumerate(p.tags) if tag == "meta" and "http-equiv" in dict(attrs)]
    style_hash = base64.b64encode(hashlib.sha256(p.styles[0].encode()).digest()).decode() if p.styles else ""
    strict = f"default-src 'none'; style-src 'sha256-{style_hash}'; img-src 'none'; script-src 'none'; base-uri 'none'; form-action 'none'"
    if [i for i, _ in policies] != [3] or [t for t, _ in p.tags[:3]] != ["html", "head", "meta"] or dict(p.tags[2][1]).get("charset") != "utf-8":
        problems.append(f"the policy is not the one element right after the charset: {[t for t, _ in p.tags[:5]]}")
    for _, attrs in policies:
        if attrs.get("http-equiv") != "Content-Security-Policy" or attrs.get("content") != strict:
            problems.append(f"policy {attrs!r}, not {strict!r}")
    return problems, "".join(p.text)


# Markup names for the report-markup fixture: placeholder name in the built assembly -> its replacement,
# the same length in bytes (see fixtures/report-markup/M.cs).
MARKUP_NAMES = {b"MarkupTypeNameXXXXXXXXXXX": b"<script>alert(1)</script>",
                b"MarkupMethodNameXXXXXXXXXXXXXX": b'"><img src=x onerror=alert(2)>',
                b"MarkupBidiXXXX": "Safe\u202eexe.lld".encode()}
# Appended to every string of a run document by the report's hostile-data check.
SPOOF = '<img src=x onerror=alert(3)><a href="javascript:alert(4)">x</a><!-- \'\u202e\u200b'


def poisoned(node, top=True):
    """A run document with SPOOF appended to every string, except the document's own kind."""
    if isinstance(node, dict):
        return {k: (v if top and k == "kind" else poisoned(v, False)) for k, v in node.items()}
    if isinstance(node, list):
        return [poisoned(x, False) for x in node]
    return node + SPOOF if isinstance(node, str) else node


def g_scan():
    # scan: the index snapshot, verified archives, stored results, changes, reports. Offline: every
    # archive is put in the store under its stamped hash first, and URLs point at example.invalid,
    # so a download is attempted only where a check wants one to fail.
    T = j("scan")
    state = os.path.join(T, "state")
    store = os.path.join(state, "archives")
    os.makedirs(store)
    game = os.path.join(T, "game")
    os.makedirs(game)
    shutil.copy(fx("game-api/stub", "KSA.dll"), game)
    harmony_dll = fx("harmony-patch/stub", "0Harmony.dll")
    unclassified_dll = fx("classification/unclassified", "ClassificationUnclassified.dll")
    patch_dll = case_dll("harmony-patch/mod", "GameTarget")

    def archive(name, files):
        path = os.path.join(T, name)
        with zipfile.ZipFile(path, "w") as z:
            for arc, src in files:
                z.write(src, arc)
        return path

    def release(rid, version, path, status="stable", yanked=False, seed=True, asset=None):
        h = sha256(path)
        if seed:
            shutil.copy(path, os.path.join(store, h + ".zip"))
        r = {"id": rid, "version": version, "release_status": status, "release_date": f"2026-11-0{version[-1]}T00:00:00Z",
             "download": {"url": f"https://example.invalid/{rid}/{asset or os.path.basename(path)}", "sha256": h.upper(), "size": os.path.getsize(path)}}
        if yanked:
            r.update(yanked=True, yanked_reason="replaced")
        return r

    # The markup fixture with its placeholder names replaced in the metadata.
    with open(fx("report-markup", "ReportMarkup.dll"), "rb") as f:
        pe = f.read()
    for old, new in MARKUP_NAMES.items():
        assert len(old) == len(new) and pe.count(old) == 1, (old, len(new), pe.count(old))
        pe = pe.replace(old, new)
    markup_dll = os.path.join(T, "ReportMarkup.dll")
    with open(markup_dll, "wb") as f:
        f.write(pe)

    loader = archive("Loader-1.0.0.zip", [("Loader/0Harmony.dll", harmony_dll)])
    sample = archive("Sample-1.0.0.zip", [("Sample/ReflectionFixture.dll", fx("reflection", "ReflectionFixture.dll"))])
    newer = archive("Sample-1.2.0.zip", [("Sample/Unclassified.dll", unclassified_dll)])
    content = archive("Content-2.0.0.zip", [("Content/readme.txt", os.path.join(REPO, "LICENSE"))])
    patch = archive("Patch-1.0.0.zip", [("Patch/HarmonyPatch.GameTarget.dll", patch_dll)])
    fake = archive("Fake-1.0.0.zip", [("Fake/0Harmony.dll", fx("impersonation", "0Harmony.dll"))])
    markup = archive("Markup-1.0.0.zip", [("Markup/ReportMarkup.dll", markup_dll)])
    listing = lambda lid, name, releases, kind="mod": {"id": lid, "authored": {"type": kind, "name": name}, "releases": releases}
    snapshot = {"snapshot_version": 1, "sources": {"generated": {"repository": "test/releases", "commit": "0123456789abcdef"}}, "listings": [
        listing("Loader", "Loader", [release("Loader", "1.0.0", loader)], kind="mod-loader"),
        # A name with markup: the report must show it as text.
        listing("Sample", "<script>alert(1)</script>Sample", [
            release("Sample", "1.1.0-beta", newer, status="testing"), release("Sample", "0.9.0", sample), release("Sample", "1.0.0", sample)]),
        listing("Content", "Content", [release("Content", "2.0.0", content)]),
        listing("Patch", "Patch", [release("Patch", "1.0.0", patch)]),
        listing("Fake", "Fake", [release("Fake", "1.0.0", fake)]),
        # A name with a bidirectional override and a zero-width space: the report must not render them.
        listing("Markup", "Safe\u202eexe.lld\u200bMod", [release("Markup", "1.0.0", markup)]),
        listing("Yanked", "Yanked", [release("Yanked", "1.0.0", content, yanked=True)])]}
    lst = {l["id"]: l for l in snapshot["listings"]}
    snap = write_json(os.path.join(T, "snapshot.json"), snapshot)
    docs = [0]  # run documents written so far

    def scan(*args, snapshot_file=snap, expect=0, analyzer=None):
        out = scratch(".run.json")
        p = run(["dotnet", pipeline, "scan", *args, "--analyzer", analyzer or tool, "--game", game, "--state", state, "--snapshot", snapshot_file,
                 "--retries", "0", "--format", "json", "--out", out], expect=expect)
        with open(out) as f:
            text = f.read()
        docs[0] += bool(text)
        return (json.loads(text) if text else None), p, out

    def snapshot_now(name):
        return write_json(os.path.join(T, name), snapshot)

    def stored(lid, archive_path):
        path = os.path.join(state, "results", lid, sha256(archive_path) + ".json")
        return path, (json.load(open(path)) if os.path.exists(path) else None)

    SCANNED = ["Content", "Fake", "Loader", "Markup", "Patch", "Sample"]
    doc, p, first_out = scan("index")
    by = {r["id"]: r for r in doc["releases"]}
    check("scan: the newest stable release is scanned, not a newer prerelease or an older version",
          by["Sample"]["release"]["version"] == "1.0.0" and by["Sample"]["status"] == "scanned", by["Sample"].get("release"))
    check("scan: a listing whose every release is yanked is skipped", by["Yanked"]["status"] == "skipped" and "yanked" in by["Yanked"]["reason"], by["Yanked"])
    check("scan: each release gets its tier, and the first scan reports every listing as new",
          by["Sample"]["result"]["tier"] == "broad-access" and by["Content"]["result"]["tier"] == "no-code"
          and sorted(i for i in by if by[i].get("change", {}).get("kind") == "new") == SCANNED, {i: by[i].get("change") for i in by})
    check("scan: the snapshot's mod loaders are trusted by hash",
          by["Loader"]["result"]["trusted"] == ["0Harmony"] and by["Loader"]["result"]["tier"] == "limited-access", by["Loader"].get("result"))
    library_profiles = glob.glob(os.path.join(state, "profiles", "libraries-*.json"))
    game_profiles = glob.glob(os.path.join(state, "profiles", "game-*.json"))
    r = by["Patch"]["result"]
    bare = analyze(patch_dll, allowlist=os.path.join(state, "allowlist.json"), profile=game_profiles[0]) if game_profiles else {"tier": "?", "broadAccess": []}
    check("scan: a mod calling into a loader's library is analyzed with that library's profile (without it, Broad access)",
          r["tier"] == "limited-access" and labels(r) == ["Changes how the game works"] and len(library_profiles) == 1
          and bare["tier"] == "broad-access" and UNANALYZED in reasons(bare), (r, library_profiles, bare.get("broadAccess")))
    check("scan: a file named like a loader's library, with another hash, is Broad access",
          by["Fake"]["result"]["tier"] == "broad-access" and "Ships a file named like a part of .NET, the game or a trusted library" in reasons(by["Fake"]["result"]),
          by["Fake"].get("result"))
    check("scan: result files are named relative to the release's archive, not where it was extracted",
          [f["path"] for f in by["Sample"]["result"]["files"]] == ["Sample-1.0.0/Sample/ReflectionFixture.dll"], by["Sample"]["result"]["files"])
    _, rd = stored("Sample", sample)
    check("scan: the result is stored by release with its stamp", rd["kind"] == "result" and rd["release"]["sha256"] == sha256(sample)
          and rd["stamp"]["key"] == doc["stamp"]["key"] and rd["stamp"]["policy"]["version"], rd.get("stamp"))
    check("scan: the stamp names the analyzer and the pipeline that ran by their hashes",
          doc["stamp"].get("build") == {"analyzer": sha256(tool), "pipeline": sha256(pipeline)}, doc["stamp"])

    # The report of this run (the document scan wrote with --out): the markup fixture's type and
    # member names and the snapshot's names render as text, and nothing else gets into the page.
    html_page = os.path.join(T, "report.html")
    run(["dotnet", pipeline, "report", first_out, "--out", html_page])
    with open(html_page, encoding="utf-8") as f:
        page = f.read()
    problems, text = report_problems(page)
    shown = ['HttpClient::GetAsync  <-  Markup.<script>alert(1)</script>::"><img src=x onerror=alert(2)>',  # type and member names, in evidence
             "HttpClient::GetAsync  <-  Markup.<script>alert(1)</script>::Safe\\u202eexe.lld",
             "<script>alert(1)</script>Sample", "Safe\\u202eexe.lld\\u200bMod"]  # listing names
    check("report: type and member names from an archive, and names from the snapshot, render as text and add no markup",
          not problems and all(s in text for s in shown) and "\u202e" not in page and "\u200b" not in page and "&#x202e;" not in page.lower(),
          (problems, [s for s in shown if s not in text]))
    check("report: the page's only policy is the strict one, first in the head, allowing only its own style sheet", not [x for x in problems if "policy" in x or "style" in x], problems)
    with open(first_out) as f:
        hostile = write_json(os.path.join(T, "run-hostile.json"), poisoned(json.load(f)))
    run(["dotnet", pipeline, "report", hostile, "--out", html_page])
    with open(html_page, encoding="utf-8") as f:
        page = f.read()
    problems, text = report_problems(page)
    spoof_shown = SPOOF.replace("\u202e", "\\u202e").replace("\u200b", "\\u200b")
    check("report: markup, links, comments and bidirectional characters in every field of a run document render as text",
          not problems and text.count(spoof_shown) >= 30 and "\u202e" not in page and "&#x202e;" not in page.lower(), (problems, text.count(spoof_shown)))

    doc, p, _ = scan("index")
    check("scan: a second run rescans nothing, reports no changes, and reuses the cached profiles",
          doc["summary"]["scanned"] == 0 and doc["summary"]["cached"] == len(SCANNED) and doc["summary"]["changed"] == 0
          and "game profile" not in p.stderr and "library profile" not in p.stderr, (doc["summary"], p.stderr[-1500:]))
    doc, p, _ = scan("index", "--full")
    check("scan: --full rescans every release and makes the profiles again, and reports no change when the results are the same",
          doc["summary"]["scanned"] == len(SCANNED) and doc["summary"]["changed"] == 0
          and "game profile: made again (--full)" in p.stderr and "library profile: made again (--full)" in p.stderr, (doc["summary"], p.stderr[-1500:]))
    # Stored results from before policy 36 name the top tier "full-access" and its groups "fullAccess":
    # rescanned with the new names, the rename alone is not a change.
    renamed = []
    for lid, entry in json.load(open(os.path.join(state, "latest.json"))).items():
        path = os.path.join(state, "results", lid, entry["sha256"] + ".json")
        with open(path) as f:
            saved = json.load(f)
        res = saved.get("result")
        if not isinstance(res, dict) or res.get("tier") != "broad-access":
            continue
        res["tier"], res["tierName"], res["fullAccess"] = "full-access", "Full access", res.pop("broadAccess")
        write_json(path, saved)
        renamed.append(lid)
    doc, p, _ = scan("index", "--full")
    check("scan: a stored result from before policy 36 (full-access, fullAccess) is the same as its rescan under the new names",
          renamed and doc["summary"]["scanned"] == len(SCANNED) and doc["summary"]["changed"] == 0, (renamed, doc["summary"], p.stderr[-1500:]))

    # A new release, and one whose stored archive is not what its stamp names (the download then fails).
    lst["Sample"]["releases"].insert(0, release("Sample", "1.2.0", newer))
    stamped = release("Content", "2.1.0", archive("Content-2.1.0.zip", [("Content/notes.txt", os.path.join(REPO, "LICENSE"))]), seed=False)
    with open(os.path.join(store, stamped["download"]["sha256"].lower() + ".zip"), "wb") as f:
        f.write(b"not the bytes the stamp names")
    lst["Content"]["releases"].insert(0, stamped)
    snap2 = snapshot_now("snapshot2.json")
    doc, _, _ = scan("index", snapshot_file=snap2, expect=1)
    by = {r["id"]: r for r in doc["releases"]}
    change = by["Sample"].get("change") or {}
    check("scan: a new release is reported with what changed",
          change.get("kind") == "updated" and change.get("from") == "1.0.0" and change.get("to") == "1.2.0"
          and UNTRACED in change["difference"]["reasons"]["removed"] and UNCLASSIFIED in change["difference"]["reasons"]["added"], change)
    check("scan: an archive that does not match its stamp is not scanned in its place, and the run exits 1",
          by["Content"]["status"] == "failed" and by["Content"]["release"]["version"] == "2.1.0" and "result" not in by["Content"]
          and not os.path.exists(os.path.join(store, stamped["download"]["sha256"].lower() + ".zip")), by["Content"])
    lst["Content"]["releases"].pop(0)
    snap3 = snapshot_now("snapshot3.json")

    doc, _, _ = scan("mod", "Sample@1.0.0", snapshot_file=snap3)
    r1 = doc["releases"]
    doc, _, _ = scan("mod", "Sample@1.0.0", "--full", snapshot_file=snap3)
    r2 = doc["releases"]
    check("scan mod: ID@VERSION gives that version's result, and --full scans it again",
          [(r["release"]["version"], r["status"], r["result"]["tier"]) for r in r1] == [("1.0.0", "cached", "broad-access")]
          and [(r["release"]["version"], r["status"], r["result"]["tier"]) for r in r2] == [("1.0.0", "scanned", "broad-access")], (r1, r2))
    _, p, _ = scan("mod", "Yanked@1.0.0", snapshot_file=snap3, expect=2)
    check("scan mod: a yanked version is refused", "yanked" in p.stderr, p.stderr)
    doc, _, _ = scan("mod", sample, snapshot_file=snap3)
    r = doc["releases"][0]
    check("scan mod: local files are scanned and identified by their hashes",
          r["result"]["tier"] == "broad-access" and r["local"]["files"][0]["sha256"] == sha256(fx("reflection", "ReflectionFixture.dll"))
          and not os.path.exists(os.path.join(state, "results", r["id"])), r.get("local"))
    key = doc["stamp"]["key"]

    # A loader release that ships the trusted file under another name: the analyzer uses the names,
    # so the key changes, and the first name stays trusted (the impersonating file stays Broad access).
    lst["Loader"]["releases"].insert(0, release("Loader", "1.1.0", archive("Loader-1.1.0.zip", [("Loader/Renamed.dll", harmony_dll)])))
    doc, _, _ = scan("index", snapshot_file=snapshot_now("snapshot4.json"))
    by = {r["id"]: r for r in doc["releases"]}
    with open(os.path.join(state, "allowlist.json")) as f:
        entry = json.load(f)["libraries"].get(sha256(harmony_dll), {})
    check("scan: a trusted file published under a second name changes the key and keeps both names trusted",
          doc["stamp"]["key"] != key and by["Fake"]["status"] == "scanned" and by["Fake"]["result"]["tier"] == "broad-access"
          and "Ships a file named like a part of .NET, the game or a trusted library" in reasons(by["Fake"]["result"])
          and entry.get("names") == ["0Harmony", "Renamed"], (by["Fake"]["status"], by["Fake"].get("result", {}).get("tier"), entry))

    # A second loader trusts Sample 1.2.0's file: the same release, rescanned under the new key, is
    # reported with its tier change (compared with its own earlier result, not overwritten first).
    snapshot["listings"].insert(1, listing("Loader2", "Loader2", [release("Loader2", "1.0.0", archive("Loader2-1.0.0.zip", [("Loader2/Unclassified.dll", unclassified_dll)]))],
                                           kind="mod-loader"))
    doc, _, _ = scan("index", snapshot_file=snapshot_now("snapshot5.json"))
    by = {r["id"]: r for r in doc["releases"]}
    change = by["Sample"].get("change") or {}
    check("scan: an unchanged release rescanned under a new key is reported with what changed",
          by["Sample"]["status"] == "scanned" and change.get("kind") == "rescanned"
          and change.get("difference", {}).get("tier") == {"from": "broad-access", "to": "limited-access"}, (by["Sample"]["status"], change))

    # The same archive hosted under another file name: the result's paths name the download, so it is scanned again.
    lst["Patch"]["releases"][0] = release("Patch", "1.0.0", patch, asset="Patch-renamed.zip")
    doc, _, _ = scan("index", snapshot_file=snapshot_now("snapshot6.json"))
    by = {r["id"]: r for r in doc["releases"]}
    check("scan: a release whose download has another file name is scanned again, its files named after it",
          by["Patch"]["status"] == "scanned" and [f["path"] for f in by["Patch"]["result"]["files"]] == ["Patch-renamed/Patch/HarmonyPatch.GameTarget.dll"]
          and doc["summary"]["scanned"] == 1, (by["Patch"]["status"], by["Patch"].get("result", {}).get("files"), doc["summary"]))
    snap7 = snapshot_now("snapshot7.json")
    n = sum(1 for r in doc["releases"] if "result" in r)
    key, tool_version = doc["stamp"]["key"], doc["stamp"]["tool"]

    # Another game DLL, and another analyzer build of the same version: each is a new key, and every release is scanned again.
    shutil.copy(fx("reflection", "ReflectionFixture.dll"), os.path.join(game, "Extra.dll"))
    doc, _, _ = scan("index", snapshot_file=snap7)
    os.remove(os.path.join(game, "Extra.dll"))
    check("scan: a change of the game's DLLs rescans every release",
          doc["stamp"]["key"] != key and doc["summary"]["scanned"] == n and doc["summary"]["cached"] == 0, doc["summary"])
    # A game DLL the analyzer cannot read (cut short): its warnings are shown, the profile made without
    # it is used for this run but not kept, and every result made with it is marked for retry.
    with open(fx("game-api/stub", "KSA.dll"), "rb") as f:
        head = f.read(300)
    with open(os.path.join(game, "Broken.dll"), "wb") as f:
        f.write(head)
    kept = sorted(glob.glob(os.path.join(state, "profiles", "*-*.json")))
    doc, p, _ = scan("index", snapshot_file=snap7)
    os.remove(os.path.join(game, "Broken.dll"))
    results = [r for r in doc["releases"] if "result" in r]
    check("scan: a game DLL the profile cannot read is reported, the profile is not kept, and its results are retried",
          "analyzer: warning: " in p.stderr and "Broken.dll" in p.stderr and "the profile is not kept" in p.stderr
          and sorted(glob.glob(os.path.join(state, "profiles", "*-*.json"))) == kept
          and len(results) == n and all("game profile could not read 1 game file: Broken.dll" in r.get("retry", "") for r in results),
          (p.stderr[-2000:], [r.get("retry") for r in results]))
    doc, _, _ = scan("index", snapshot_file=snap7)  # the game as before: back to the earlier key
    key = doc["stamp"]["key"]
    other = os.path.join(T, "analyzer")
    shutil.copytree(os.path.dirname(tool), other)
    with open(os.path.join(other, os.path.basename(tool)), "ab") as f:
        f.write(b"\0" * 16)  # same code and version, other bytes
    doc, _, _ = scan("index", snapshot_file=snap7, analyzer=os.path.join(other, os.path.basename(tool)))
    check("scan: another analyzer build with the same version rescans every release",
          doc["stamp"]["key"] != key and doc["summary"]["scanned"] == n and doc["stamp"]["tool"] == tool_version, (doc["summary"], doc["stamp"]["tool"]))
    doc, _, _ = scan("index", snapshot_file=snap7)

    # The analyzer fails (a cached profile that passes the pipeline's structural check but names a
    # capability the analyzer does not know): nothing is stored, the release is not scanned, and the run exits 1.
    lst["Content"]["releases"].insert(0, release("Content", "2.2.0", archive("Content-2.2.0.zip", [("Content/Content.dll", fx("reflection", "ReflectionFixture.dll"))])))
    snap8 = snapshot_now("snapshot8.json")
    new_path, _ = stored("Content", os.path.join(T, "Content-2.2.0.zip"))
    game_profiles = glob.glob(os.path.join(state, "profiles", "game-*.json"))
    for profile in game_profiles:
        with open(profile) as f:
            gp = json.load(f)
        next(iter(gp["methods"].values())).append("no-such-capability")
        write_json(profile, gp)
    doc, _, _ = scan("index", snapshot_file=snap8, expect=1)
    by = {r["id"]: r for r in doc["releases"]}
    # The profile this key uses (the state keeps one per key, the analyzer's message names it).
    current = re.search(r"game profile (\S+\.json)", by["Content"].get("reason", ""))
    current = current.group(1) if current else game_profiles[0]
    check("scan: when the analyzer fails, the release is not scanned, nothing is stored, the run exits 1, and the reason names --full (a kept profile was used)",
          current in game_profiles and by["Content"]["status"] == "failed" and "the analyzer failed" in by["Content"].get("reason", "")
          and "run again with --full" in by["Content"].get("reason", "")
          and "result" not in by["Content"] and not os.path.exists(new_path), by["Content"])

    # A cached game profile cut short is deleted and made again, with a warning (and the library
    # profiles made with it too), and the scan succeeds.
    with open(current, "w") as f:
        f.write('{"format": 7, "stamp": {"policy"')
    doc, p, _ = scan("index", snapshot_file=snap8)
    by = {r["id"]: r for r in doc["releases"]}
    with open(current) as f:
        remade = json.load(f)
    check("scan: a truncated cached game profile is made again with a warning (the library profile with it), and the scan succeeds",
          by["Content"]["status"] == "scanned" and by["Content"]["result"]["tier"] == "broad-access" and os.path.exists(new_path)
          and "warning: the cached game profile" in p.stderr and "not valid JSON" in p.stderr and "it is deleted and made again" in p.stderr
          and "library profile: made again (the game profile was made again)" in p.stderr
          and remade["methods"] and "no-such-capability" not in json.dumps(remade["methods"]), (by["Content"], p.stderr[-2000:]))

    # A result marked for retry (a file-system error, an unreadable file) is not reused. A cached
    # library profile of another format is made again (alone: the game profile is reused).
    with open(new_path) as f:
        rd = json.load(f)
    rd["retry"] = "a file could not be read"
    write_json(new_path, rd)
    library_profile = max(glob.glob(os.path.join(state, "profiles", "libraries-*.json")), key=os.path.getmtime)  # just made again
    with open(library_profile) as f:
        lp = json.load(f)
    lp["format"] = 5
    write_json(library_profile, lp)
    doc, p, _ = scan("index", snapshot_file=snap8)
    by = {r["id"]: r for r in doc["releases"]}
    check("scan: a result marked for retry is scanned again, the others are reused",
          by["Content"]["status"] == "scanned" and "retry" not in by["Content"] and doc["summary"]["scanned"] == 1, doc["summary"])
    check("scan: a cached library profile of another format is made again with a warning, the game profile is reused",
          "warning: the cached library profile" in p.stderr and "format 5, not 7" in p.stderr
          and "game profile" not in p.stderr and json.load(open(library_profile))["format"] == 7, p.stderr[-1500:])

    # Stored results that cannot be used as they are: a duplicate key (which a JSON reader accepts
    # and then fails on), no tier, no result at all. Each is scanned again, none ends the run.
    damaged = {"Sample": lambda t: t.replace('{\n  "schema": 1,', '{\n  "schema": 1,\n  "schema": 1,', 1),
               "Loader": lambda t: json.dumps({k: ({kk: vv for kk, vv in v.items() if kk != "tier"} if k == "result" else v) for k, v in json.loads(t).items()}),
               "Patch": lambda t: json.dumps({k: v for k, v in json.loads(t).items() if k != "result"})}
    for lid, edit in damaged.items():
        latest_sha = json.load(open(os.path.join(state, "latest.json")))[lid]["sha256"]
        path = os.path.join(state, "results", lid, latest_sha + ".json")
        with open(path) as f:
            text = f.read()
        with open(path, "w") as f:
            f.write(edit(text))
    doc, p, _ = scan("index", snapshot_file=snap8)
    by = {r["id"]: r for r in doc["releases"]}
    check("scan: a stored result with a duplicate key, without a tier or without a result is scanned again, not reused or reported without a tier",
          all(by[i]["status"] == "scanned" and by[i]["result"]["tier"] for i in damaged) and doc["summary"]["scanned"] == len(damaged)
          and "duplicate" in p.stderr.lower(),
          ({i: (by[i]["status"], by[i].get("change")) for i in damaged}, doc["summary"], p.stderr[-1500:]))
    # The earlier result of the same release cannot be read: that is reported (nothing to compare
    # with), never taken for "no change", which would hide a higher tier.
    check("scan: a release scanned again whose earlier result cannot be read is reported as a change with nothing compared, not as unchanged",
          all(by[i].get("change", {}).get("kind") == "rescanned" and by[i]["change"].get("previous") == "unreadable" and by[i]["change"].get("difference") is None
              for i in damaged), {i: by[i].get("change") for i in damaged})

    # latest.json damaged: scan mod ID@VERSION does not read it; scan index moves it aside and starts again.
    latest_path = os.path.join(state, "latest.json")
    with open(latest_path) as f:
        good_latest = json.load(f)
    with open(latest_path, "w") as f:
        f.write('{"Sample": {"version": "1.2.0"}, "Sample": {}}')  # a duplicate key
    doc, p, _ = scan("mod", "Sample@1.0.0", snapshot_file=snap8)
    check("scan mod: ID@VERSION works with a damaged latest.json and leaves it alone",
          [(r["release"]["version"], r["result"]["tier"]) for r in doc["releases"]] == [("1.0.0", "broad-access")]
          and open(latest_path).read().startswith('{"Sample"') and not glob.glob(latest_path + ".damaged-*"), (doc["releases"], p.stderr[-1000:]))
    doc, p, _ = scan("index", snapshot_file=snap8)
    aside = glob.glob(latest_path + ".damaged-*")
    with_result = sorted(r["id"] for r in doc["releases"] if "result" in r)
    check("scan: a damaged latest.json is moved aside with a warning, the scan succeeds, and every listing is reported as new",
          len(aside) == 1 and open(aside[0]).read().startswith('{"Sample"') and "moved to" in p.stderr
          and doc["summary"]["failed"] == 0 and sorted(r["id"] for r in doc["releases"] if r.get("change", {}).get("kind") == "new") == with_result
          and sorted(json.load(open(latest_path))) == with_result, (aside, p.stderr[-1000:], doc["summary"]))
    os.remove(aside[0])
    # A sha in latest.json that is not a SHA-256 is never used in a path: the entry is ignored.
    bad_latest = json.load(open(latest_path))
    bad_latest["Sample"]["sha256"] = "../Loader/" + good_latest["Loader"]["sha256"]
    write_json(latest_path, bad_latest)
    doc, p, _ = scan("index", snapshot_file=snap8)
    by = {r["id"]: r for r in doc["releases"]}
    check("scan: a latest.json entry whose sha256 is not a SHA-256 is ignored (the listing is new), and the next record is right",
          by["Sample"]["status"] == "cached" and by["Sample"].get("change") == {"kind": "new"} and "no usable sha256" in p.stderr
          and json.load(open(latest_path))["Sample"]["sha256"] == good_latest["Sample"]["sha256"] and doc["summary"]["changed"] == 1,
          (by["Sample"].get("change"), doc["summary"], p.stderr[-1000:]))
    unreadable = os.path.join(T, "unreadable")
    os.makedirs(unreadable)
    shutil.copy(fx("reflection", "ReflectionFixture.dll"), os.path.join(unreadable, "Mod.dll"))
    os.chmod(os.path.join(unreadable, "Mod.dll"), 0)
    try:
        doc, _, _ = scan("mod", unreadable, snapshot_file=snap8)
    finally:
        os.chmod(os.path.join(unreadable, "Mod.dll"), stat.S_IRUSR | stat.S_IWUSR)
    r = doc["releases"][0]
    check("scan: a file-system error while extracting gives Broad access and marks the result for retry",
          r["result"]["tier"] == "broad-access" and "Mod.dll" in r.get("retry", ""), {k: r.get(k) for k in ("retry", "result")})

    # Names that version-control tools, editors and coding agents act on are written as _dm_NAME (any
    # case), and a renamed path that collides with a real entry makes the archive unextracted. Listing
    # ids that cannot name a folder, and download URLs that do not end in one file name, fail only
    # their own listing. Benign contents only.
    defuse = os.path.join(T, "Defuse-1.0.0.zip")
    with zipfile.ZipFile(defuse, "w") as z:
        z.writestr("Defuse/.git/config", "[core]\n\tbare = false\n")
        z.writestr("Defuse/.git/HEAD", "ref: refs/heads/main\n")
        z.writestr("Defuse/.GıT/HEAD", "ref: refs/heads/main\n")  # dotless i: ".git" on NTFS
        z.write(fx("reflection", "ReflectionFixture.dll"), "Defuse/.git/objects/ReflectionFixture.dll")
        z.writestr("Defuse/.vscode/settings.json", "{}\n")
        z.writestr("Defuse/.mcp.json", "{}\n")
        z.writestr("Defuse/.Cursor/rules/notes.mdc", "notes\n")
        z.writestr("Defuse/CLAUDE.md", "# notes\n")
        z.writestr("Defuse/docs/claude.md", "# notes\n")
        z.writestr("Defuse/AGENTS.override.md", "# notes\n")
        z.writestr("Defuse/.gemini/settings.json", "{}\n")
        z.writestr("Defuse/readme.txt", "content\n")
    collide = os.path.join(T, "Collide-1.0.0.zip")
    with zipfile.ZipFile(collide, "w") as z:
        z.writestr("Collide/.git/config", "[core]\n")
        z.writestr("Collide/_dm_.git/config", "[core]\n")
        z.writestr("Collide/readme.txt", "content\n")
    bad = json.loads(json.dumps(snapshot))
    bad["listings"] += [
        listing("Defuse", "Defuse", [release("Defuse", "1.0.0", defuse)]),
        listing("Collide", "Collide", [release("Collide", "1.0.0", collide)]),
        # Another listing with Collide's id in other case: it would share Collide's folders.
        listing("collide", "collide", [release("collide", "1.0.0", content)]),
        listing("Slash", "Slash", [release("Slash", "1.0.0", content, asset="Slash-1.0.0.zip/")]),
        listing("Encoded", "Encoded", [release("Encoded", "1.0.0", content, asset="Encoded-1.0.0.zip%2F")]),
        listing("Blocked", "Blocked", [release("Blocked", "1.0.0", content)]),
        listing("Unstorable", "Unstorable", [release("Unstorable", "1.0.0", sample)]),
        {"id": "../escape", "authored": {"type": "mod"}, "releases": [release("../escape", "1.0.0", content)]},
        listing("CON", "Device", [release("CON", "1.0.0", content)]),
        listing("nul.txt", "Device", [release("nul.txt", "1.0.0", content)]),
        listing("Trailing.", "Trailing", [release("Trailing.", "1.0.0", content)]),
        listing("CLAUDE.md", "Renamed", [release("CLAUDE.md", "1.0.0", content)])]
    bad_snap = write_json(os.path.join(T, "snapshot-bad.json"), bad)
    with open(os.path.join(state, "extracted", "Blocked"), "w") as f:
        f.write("a file where the listing's extraction folder goes")
    with open(os.path.join(state, "results", "Unstorable"), "w") as f:
        f.write("a file where the listing's results folder goes")
    doc, p, _ = scan("index", snapshot_file=bad_snap, expect=1)
    by = {r["id"]: r for r in doc["releases"]}
    tree = os.path.join(state, "extracted", "Defuse")
    on_disk = sorted(os.path.relpath(os.path.join(d, n), tree).replace(os.sep, "/") for d, ds, fs in os.walk(tree) for n in ds + fs)
    plain = [x for x in on_disk if any(c.lower().replace("ı", "i") in (".git", ".vscode", "claude.md", ".mcp.json", ".cursor", "agents.override.md", ".gemini") for c in x.split("/"))]
    check("scan: .git, .vscode, .cursor, .gemini, .mcp.json, CLAUDE.md and AGENTS.override.md entries (any case) are written as _dm_NAME, nothing under the original names, and the archive counts as extracted",
          by["Defuse"]["status"] == "scanned" and not plain
          and all(x in on_disk for x in ["Defuse-1.0.0/Defuse/_dm_.git/config", "Defuse-1.0.0/Defuse/_dm_.git/HEAD", "Defuse-1.0.0/Defuse/_dm_.GıT/HEAD", "Defuse-1.0.0/Defuse/_dm_.vscode/settings.json",
                                         "Defuse-1.0.0/Defuse/_dm_.mcp.json", "Defuse-1.0.0/Defuse/_dm_.Cursor/rules/notes.mdc",
                                         "Defuse-1.0.0/Defuse/_dm_CLAUDE.md", "Defuse-1.0.0/Defuse/docs/_dm_claude.md",
                                         "Defuse-1.0.0/Defuse/_dm_AGENTS.override.md", "Defuse-1.0.0/Defuse/_dm_.gemini/settings.json"])
          and [f["path"] for f in by["Defuse"]["result"]["files"]] == ["Defuse-1.0.0/Defuse/_dm_.git/objects/ReflectionFixture.dll"]
          and "Contains an archive the check cannot open" not in reasons(by["Defuse"]["result"]) and "as '_dm_.git'" in p.stderr,
          (on_disk, by["Defuse"].get("result", {}).get("files"), p.stderr[-1500:]))
    check("scan: a renamed entry that collides with a real one makes the archive unextracted (Broad access)",
          by["Collide"]["status"] == "scanned" and by["Collide"]["result"]["tier"] == "broad-access"
          and "Contains an archive the check cannot open" in reasons(by["Collide"]["result"]), by["Collide"].get("result"))
    rejected = ["../escape", "CLAUDE.md", "CON", "Trailing.", "nul.txt"]
    check("scan: a listing id that is not a usable folder name fails that listing only, and no folder is made for it",
          all(by.get(i, {}).get("status") == "failed" and "not usable as a folder name" in by[i].get("reason", "") and "result" not in by[i] for i in rejected)
          and all(by[i]["status"] in ("scanned", "cached") for i in SCANNED + ["Defuse", "Collide"])
          and not [x for x in os.listdir(os.path.join(state, "extracted")) + os.listdir(os.path.join(state, "results")) if x in rejected + ["escape", "_dm_CLAUDE.md"]]
          and not os.path.exists(os.path.join(state, "escape")),
          {i: by.get(i) for i in rejected})
    # H10b review: before pipeline 0.3.5 the second listing was left out of the run with exit 0.
    check("scan: a listing whose id another listing already has (ignoring case) fails, and the first is scanned as before",
          by.get("collide", {}).get("status") == "failed" and "already used by another listing" in by["collide"].get("reason", "")
          and "result" not in by["collide"] and by["Collide"]["status"] in ("scanned", "cached") and by["Collide"]["result"]["tier"] == "broad-access",
          (by.get("collide"), by["Collide"].get("status")))
    check("scan: a download URL ending in '/' (or an encoded '/') fails that listing, nothing is extracted for it",
          all(by[i]["status"] == "failed" and "usable file name" in by[i].get("reason", "") and "result" not in by[i]
              and not os.path.exists(os.path.join(state, "extracted", i)) for i in ["Slash", "Encoded"])
          and doc["summary"]["failed"] == len(rejected) + 5, ({i: by[i] for i in ["Slash", "Encoded"]}, doc["summary"]))
    check("scan: a file-system error while extracting one listing (a file where its folder goes) fails that listing, not the run",
          by["Blocked"]["status"] == "failed" and "could not be read or extracted" in by["Blocked"].get("reason", "") and "result" not in by["Blocked"],
          by["Blocked"])
    check("scan: an error with one listing after its analysis (its result cannot be stored) fails that listing with the error's type, and nothing is recorded for it",
          by["Unstorable"]["status"] == "failed" and "could not be stored: IOException" in by["Unstorable"].get("reason", "") and "result" not in by["Unstorable"]
          and "Unstorable" not in json.load(open(os.path.join(state, "latest.json"))) and all(by[i]["status"] in ("scanned", "cached") for i in SCANNED),
          by["Unstorable"])
    check("scan: the stamp records the extraction limits (4 GiB of extracted files per mod by default)",
          doc["stamp"].get("extraction") == {"maxDepth": 3, "maxBytes": 4 << 30, "maxFiles": 100000}, doc["stamp"].get("extraction"))
    key = doc["stamp"]["key"]
    doc, _, _ = scan("index", "--max-extracted-bytes", "1000", snapshot_file=bad_snap, expect=1)
    by = {r["id"]: r for r in doc["releases"]}
    check("scan: another extracted-size limit is a new key: every release is scanned again, and one over the limit is unextracted",
          doc["stamp"]["key"] != key and doc["stamp"]["extraction"]["maxBytes"] == 1000 and doc["summary"]["cached"] == 0
          and "Contains an archive the check cannot open" in reasons(by["Defuse"]["result"]), (doc["summary"], by["Defuse"].get("result", {}).get("tier")))

    # The snapshot from a URL that cannot be downloaded: the copy an earlier run kept is used, with a
    # warning that it may be out of date (offline: example.invalid is refused at once).
    shutil.copy(snap8, os.path.join(state, "snapshot.json"))
    doc, p, _ = scan("index", snapshot_file="https://example.invalid/index.json")
    check("scan: when the snapshot cannot be downloaded, the kept copy is used with a warning that it may be out of date",
          doc["snapshot"]["source"] == os.path.join(state, "snapshot.json") and "may be out of date" in p.stderr and "yanked since then is still trusted" in p.stderr
          and doc["summary"]["failed"] == 0 and not os.path.exists(os.path.join(state, "snapshot.json.download"))
          and "may be out of date" in doc["snapshot"].get("stale", ""), (doc["snapshot"], p.stderr[-1000:]))

    # A profile the analyzer has just made that fails the check (here: a game folder whose only DLL
    # cannot be read gives a profile with no methods) ends the run: it is neither used nor made again in a loop.
    junk_game = os.path.join(T, "junk-game")
    os.makedirs(junk_game, exist_ok=True)
    with open(os.path.join(junk_game, "Junk.dll"), "w") as f:
        f.write("not a dll")
    before_profiles = sorted(glob.glob(os.path.join(state, "profiles", "game-*.json")))
    p = run(["dotnet", pipeline, "scan", "index", "--analyzer", tool, "--game", junk_game, "--state", state, "--snapshot", snap8,
             "--retries", "0", "--format", "json", "--out", scratch(".run.json")], expect=1)
    check("scan: a game profile just made that fails the check ends the run with an error, and is not kept",
          "the game profile the analyzer just made" in p.stderr and "methods is empty" in p.stderr and "Junk.dll" in p.stderr
          and sorted(glob.glob(os.path.join(state, "profiles", "game-*.json"))) == before_profiles, p.stderr[-1500:])

    # One scan at a time per state folder.
    with open(os.path.join(state, "lock"), "a+") as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        doc, p, _ = scan("index", snapshot_file=snap8, expect=1)
    check("scan: a second scan on the same state folder is refused while one runs",
          doc is None and "another scan is using the state folder" in p.stderr, p.stderr)

    runs = os.listdir(os.path.join(state, "runs"))
    check("scan: every run keeps its own run document", len(runs) == docs[0] == len(set(runs)), (len(runs), docs[0]))

    allow = j("scan-allowlist.json")
    run(["dotnet", pipeline, "build-allowlist", "--snapshot", snap, "--cache-dir", store, "--out", allow, "--retries", "0"])
    with open(allow) as f:
        a = json.load(f)
    check("build-allowlist: trusts every file of the snapshot's mod loaders by hash",
          list(a["libraries"]) == [sha256(harmony_dll)] and a["libraries"][sha256(harmony_dll)]["anchor"] == "Loader", a)



# Multi-case fixture projects: fixtures/<project>/<csproj>, one assembly per case, selected with an
# MSBuild property. Every case stays its own assembly: mod-level results (tier, combinations, reach,
# field provenance, collection and node tracing) combine across a whole assembly, so cases sharing
# one could change each other's results. They are built together in one MSBuild run instead.
MULTI = {
    "embedded": ("embedded.csproj", "Payload", "Embedded", EMBEDDED),
    "harmony-patch/mod": ("harmony-patch-mod.csproj", "Case", "HarmonyPatch", HARMONY_PATCH),
    "reflection-precision": ("reflection-precision.csproj", "Case", "ReflectionPrecision", REFLECTION_PRECISION),
    "game-interaction": ("game-interaction.csproj", "Case", "GameInteraction", GAME_INTERACTION),
    "evasion": ("evasion.csproj", "Case", "Evasion", EVASION),
}

# Check groups, in report order: name, checks, single-build fixtures and multi-case projects they use.
# Shared setup (the tool, the game profile, the trusted Harmony stand-in) is made on first use.
STUBS = ["harmony-patch/stub", "game-api/stub"]
GROUPS = [
    ("policy", g_policy, ["fail-open/corrupt"], []),
    ("reflection", g_reflection, ["reflection"], []),
    ("impersonation", g_impersonation, ["impersonation"], []),
    ("library", g_library, ["library-propagation/mod", "library-propagation/mod-full", "library-propagation/mod-exempt"], []),
    ("game-api", g_game_api, ["game-api/stub", "game-api/mod", "game-api/mod-full", "game-api/mod-exempt", "game-api/mod-gaps"], []),
    ("classification", g_classification, ["classification/safe", "classification/unclassified"], []),
    ("file-access", g_file_access, ["labels", "file-access", "download", "fail-open/corrupt"], []),
    ("shell-open", g_shell_open, ["shell-open/link", "shell-open/program"], []),
    ("raw-memory", g_raw_memory, ["raw-memory/safe", "raw-memory/unsafe", "reflection"], []),
    ("fail-open", g_fail_open, ["fail-open", "fail-open/corrupt"], []),
    ("embedded", g_embedded, [], ["embedded"]),
    ("harmony-patch", g_harmony_patch, STUBS, ["harmony-patch/mod"]),
    ("reflection-precision", g_reflection_precision, STUBS + ["il-probes"], ["reflection-precision"]),
    ("game-interaction", g_game_interaction, STUBS, ["game-interaction"]),
    ("evasion", g_evasion, ["harmony-patch/stub"], ["evasion"]),
    ("pipeline", g_pipeline, ["reflection", "classification/unclassified"], []),
    ("scan", g_scan, ["reflection", "classification/unclassified", "harmony-patch/stub", "game-api/stub", "impersonation", "report-markup"], ["harmony-patch/mod"]),
]


def project_file(rel):
    """The one project file in REPO/rel."""
    d = os.path.join(REPO, rel)
    found = [f for f in os.listdir(d) if f.endswith(".csproj")]
    if len(found) != 1:
        raise RuntimeError(f"expected one .csproj in {d}, found {found}")
    return os.path.join(d, found[0])


def build_all(projects, multis, rebuild):
    """Build everything in one MSBuild run, in parallel and incrementally.

    Outputs stay in each project's own bin/ and obj/ (gitignored), so a run after a small change
    recompiles only what changed. Single-build projects use their default output folder, the same
    instance their project references build, so a stub is compiled once, not once per case. Cases
    get their own bin/case/<case>/ and obj/case/<case>/; the case projects keep their per-case
    properties away from the stubs they reference (GlobalPropertiesToRemove)."""
    items = [(project_file(p), {"Configuration": "Release"}) for p in projects]
    for project in multis:
        csproj, prop, _, cases = MULTI[project]
        d = os.path.join(REPO, "fixtures", project)
        for case in cases:
            items.append((os.path.join(d, csproj), {
                "Configuration": "Release", prop: case,
                "OutDir": os.path.join(d, "bin", "case", case) + "/",
                "IntermediateOutputPath": os.path.join(d, "obj", "case", case) + "/"}))
    attr = lambda s: xml.sax.saxutils.quoteattr(s)
    lines = ['<Project DefaultTargets="Build">', "  <ItemGroup>"]
    for path in sorted({p for p, _ in items}):
        lines.append(f"    <RestoreProject Include={attr(path)} />")
    for path, props in items:
        lines.append(f"    <Fixture Include={attr(path)} Properties={attr(';'.join(f'{k}={v}' for k, v in props.items()))} />")
    lines += ["  </ItemGroup>",
              '  <Target Name="Restore">',
              '    <MSBuild Projects="@(RestoreProject)" Targets="Restore" />',
              "  </Target>",
              '  <Target Name="Build">',
              f'    <MSBuild Projects="@(Fixture)" Targets="{"Rebuild" if rebuild else "Build"}" BuildInParallel="true" />',
              "  </Target>",
              "</Project>", ""]
    proj = j("build.proj")
    with open(proj, "w") as f:
        f.write("\n".join(lines))
    run(["dotnet", "msbuild", proj, "-restore", "-m:1", "-nologo", "-v:q", "-clp:ErrorsOnly;NoSummary"])


def run_group(name, fn):
    _local.buf, _local.count = [], 0
    try:
        fn()
    except Exception:
        out(f"ERROR {name}: the group stopped before its remaining checks\n" + traceback.format_exc())
        failures.append(f"{name}: error")
    if _local.count == 0:
        out(f"FAIL  {name}: the group ran no checks")
        failures.append(f"{name}: no checks")
    return _local.buf, _local.count


def tests(groups, a):
    global tool, pipeline, corrupt, builtin, runtime_dir
    t0 = time.monotonic()
    projects = ["src/DarkMatter"] + (["src/DarkMatter.Pipeline"] if any(g[0] in ("pipeline", "scan") for g in groups) else [])
    projects += sorted({"fixtures/" + d for g in groups for d in g[2]})
    build_all(projects, sorted({m for g in groups for m in g[3]}), a.rebuild)
    t1 = time.monotonic()
    tool = os.path.join(REPO, "src", "DarkMatter", "bin", "Release", TFM, "darkmatter.dll")
    pipeline = os.path.join(REPO, "src", "DarkMatter.Pipeline", "bin", "Release", TFM, "darkmatter-pipeline.dll")
    corrupt = fx("fail-open/corrupt", "corrupt.dll")
    builtin = run(["dotnet", tool, "policy"]).stdout
    runtime_dir = framework_dir()
    total = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, a.jobs)) as ex:
        futures = [ex.submit(run_group, name, fn) for name, fn, *_ in groups]
        for fut in futures:
            texts, count = fut.result()
            total += count
            for text in texts:
                print(text, flush=True)
    print(f"\nbuild {t1 - t0:.0f}s, checks {time.monotonic() - t1:.0f}s")
    return total


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--keep", action="store_true", help="leave the build directory (profiles, results, archives) in place")
    ap.add_argument("--only", metavar="GROUP[,GROUP...]", help="run only these check groups (see --list)")
    ap.add_argument("--list", action="store_true", help="print the check group names and exit")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 4, help="check groups run at once (default: CPU count)")
    ap.add_argument("--rebuild", action="store_true", help="rebuild the tool and fixtures from scratch")
    a = ap.parse_args()
    names = [g[0] for g in GROUPS]
    if a.list:
        print("\n".join(names))
        return 0
    selected = [n.strip() for n in a.only.split(",") if n.strip()] if a.only else names
    unknown = [n for n in selected if n not in names]
    if unknown:
        ap.error(f"unknown group(s): {', '.join(unknown)} (see --list)")
    os.environ.setdefault("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
    os.environ.setdefault("DOTNET_NOLOGO", "1")
    os.environ.setdefault("UseSharedCompilation", "false")
    global TMP
    TMP = tempfile.mkdtemp(prefix="dark-matter-test-")
    total = 0
    try:
        total = tests([g for g in GROUPS if g[0] in selected], a)
    finally:
        if a.keep:
            print(f"build directory: {TMP}")
        else:
            shutil.rmtree(TMP, ignore_errors=True)
    skipped = len(GROUPS) - len(set(selected))
    print(f"\n{len(failures)} failure(s) in {total} checks" if failures else f"\nall {total} checks passed", end="")
    print(f" in {len(set(selected))} of {len(GROUPS)} groups ({skipped} groups skipped: not a full run)" if skipped else "")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
