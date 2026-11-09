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
import argparse, concurrent.futures, hashlib, io, json, os, re, shutil, subprocess, sys, tarfile, tempfile, threading, time, traceback
import xml.sax.saxutils, zipfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
failures = []

# Checks expected to fail until the hardening phase that fixes them lands. A pending check
# that fails is reported but does not fail the run; one that passes fails the run, so the
# entry gets removed and any later regression turns the suite red.
PENDING = set()

# Full-access reason groups (policy "fullAccess").
DEEP, SYSTEM, UNCHECKED = "deep-game-access", "system-access", "not-fully-checked"

# Evasion fixtures (fixtures/evasion/cases/<case>.cs), each built into its own assembly.
# Expected result: a tier, or a label the mod must carry (or a list of both).
EVASION = {
    "EnumerateAndInvoke": ("tier", "full-access"),
    "ViaGetType": ("tier", "full-access"),
    "ViaGenericType": ("tier", "full-access"),
    "DelegateByName": ("tier", "full-access"),
    "UnsafeAccessor": ("tier", "full-access"),
    "FieldUntracked": ("tier", "full-access"),
    "FieldOpen": ("tier", "full-access"),
    "FieldViaReflection": ("tier", "full-access"),
    "HarmonyByRuntimeName": ("tier", "full-access"),
    "HarmonyPatchMethod": ("tier", "full-access"),
    "TraverseByRuntimeName": ("tier", "full-access"),
    "Dyn": ("tier", "full-access"),
    "Unzip": ("label", "Changes files outside the game"),
    "DeleteViaBase": ("label", "Changes files outside the game"),
    # Raw memory is deep game access as a whole since policy 9. Reading through an address the mod
    # is handed is a forged-address case: system access once raw memory is split (task R2).
    "Peek": [("tier", "full-access"), ("group", (DEEP, "Reads or writes memory directly"))],
    "TypeNames": ("tier", "full-access"),
    "TypeNamesNone": ("tier", "limited-access"),
    "ProvenInvoke": ("tier", "limited-access"),
    "ProvenField": ("tier", "limited-access"),
    "ProvenBranch": ("tier", "limited-access"),
    "HarmonyByName": [("tier", "limited-access"), ("label", "Connects to the internet")],
    "TraverseByName": ("tier", "limited-access"),
    "MethodGroupDelete": ("label", "Changes files outside the game"),
}

# Embedded-resource fixtures (fixtures/embedded, one assembly per payload): expected tier.
EMBEDDED = {"text": "limited-access", "pe": "full-access", "zip": "full-access", "costura": "full-access", "linked": "full-access"}

# Harmony patch-attribute fixtures (fixtures/harmony-patch/mod/cases/<case>.cs), analyzed with the
# Harmony stand-in allowlisted and profiled, and the game stand-in's profile. Same form as EVASION.
HARMONY_PATCH = {
    "GameTarget": [("tier", "limited-access"), ("labels", ["Changes how the game works"])],
    "GameFullTarget": [("tier", "full-access"), ("reason", "Starts other programs")],
    "FrameworkTarget": [("tier", "limited-access"), ("label", "Changes files outside the game")],
    "ProcessTarget": [("tier", "full-access"), ("reason", "Starts other programs")],
    "ByName": [("tier", "full-access"), ("reason", "Starts other programs")],
    "CustomAttribute": [("tier", "full-access"), ("reason", "Uses reflection the check cannot trace")],
    "TargetMethodUntraced": [("tier", "full-access"), ("reason", "Uses reflection the check cannot trace")],
    "TargetMethodTraced": [("tier", "limited-access"), ("labels", ["Changes how the game works"])],
    "Delegate": [("tier", "full-access"), ("reason", "Starts other programs")],
    "ReversePatch": [("tier", "limited-access"), ("label", "Changes game saves")],
    "PatchAll": [("tier", "full-access"), ("reason", "Starts other programs")],
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
    "BoundedGameType": [("tier", "full-access"), ("groups", {DEEP: [BOUNDED]})],
}

# Ordinary game interaction that policy 11 no longer counts as Full access (fixtures/game-interaction/
# cases/<case>.cs): benign controls, and the real APIs next to them that still are. Analyzed like the
# Harmony patch fixtures. Same form as EVASION.
REWRITES = "Rewrites the game's code with a Harmony transpiler, which the check cannot follow instruction by instruction"
XML_TYPES = "Reads or writes XML into objects whose types the check does not follow"
GAME_INTERACTION = {
    "TranspilerOperand": [("tier", "full-access"), ("groups", {DEEP: [REWRITES]}), ("labels", ["Changes how the game works"])],
    "DynamicMethodEmit": [("tier", "full-access"), ("reason", "Builds code at run time")],
    "TranspileFramework": [("tier", "full-access"), ("group", (SYSTEM, "Rewrites code other than the game's with a Harmony transpiler"))],
    "ObservingPostfix": [("tier", "limited-access"), ("labels", ["Changes how the game works"])],
    "OpenOwnFolder": [("tier", "limited-access"), ("labels", ["Changes files in its own or the game's folders", "Opens its own or the game's folders"])],
    "NetworkValues": [("tier", "limited-access"), ("labels", ["Reads information about you and your computer"])],
    "NamedMemberLookup": [("tier", "limited-access"), ("labels", [])],
    "AnyMemberLookup": [("tier", "limited-access"), ("labels", ["Uses your clipboard"])],
    "XmlSettings": [("tier", "full-access"), ("groups", {DEEP: [XML_TYPES]}), ("labels", [])],
    "XmlOwnFolder": [("tier", "limited-access"), ("labels", ["Reads files outside the game"])],
    "XmlUntraced": [("tier", "limited-access"), ("label", "Connects to the internet")],
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
    {group: reasons} of every Full-access group), group ((group, reason) present), reason (in any group)."""
    def one(kind, want):
        if kind == "tier": return r["tier"] == want
        if kind == "label": return want in labels(r)
        if kind == "labels": return labels(r) == want
        if kind == "groups": return groups(r) == want
        if kind == "group": return want[1] in groups(r).get(want[0], [])
        return want in reasons(r)
    return all(one(k, w) for k, w in (expected if isinstance(expected, list) else [expected]))


def check(name, ok, detail=""):
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
    """Full-access reasons by group: {group id: [reason text]}, only groups with a reason."""
    return {g["group"]: [r["text"] for r in g["reasons"]] for g in mod["fullAccess"]}


def reasons(mod):
    """Full-access reasons of every group."""
    return [r["text"] for g in mod["fullAccess"] for r in g["reasons"]]


def evidence(mod):
    return [e for f in mod["labels"] + [r for g in mod["fullAccess"] for r in g["reasons"]] for e in f["evidence"]]


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


def analyze(*files, allowlist=None, manifest=None, profile=None, libraries=None, policy=None, json_out=None):
    out = json_out or scratch(".result.json")
    cmd = ["dotnet", tool, "analyze", "--json", out]
    if allowlist: cmd += ["--allowlist", allowlist]
    if manifest: cmd += ["--manifest", manifest]
    if profile: cmd += ["--game-profile", profile]
    if libraries: cmd += ["--library-profile", libraries]
    if policy: cmd += ["--policy", policy]
    run(cmd + list(files))
    with open(out) as f:
        result = json.load(f)
    return result["mods"] if manifest else result["mods"]["mod"]


def facts(*files, out=None):
    out = out or scratch(".facts.json")
    run(["dotnet", tool, "analyze", "--json", scratch(".result.json"), "--facts", out] + list(files))
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
    run(["dotnet", tool, "profile", "--out", profile, stub] + ([os.path.join(runtime_dir, "System.Linq.dll")] if runtime_dir else []))
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
    # policy
    p = run(["dotnet", tool, "policy"])
    check("policy: built-in policy loads and validates", '"version"' in p.stdout)
    bad = j("bad-policy.jsonc")
    with open(bad, "w") as f:
        f.write(p.stdout.replace('"informational": [', '"informational": ["nonexistent", '))
    p = run(["dotnet", tool, "analyze", "--policy", bad, corrupt], expect=None)
    check("policy: a capability no rule produces is rejected", p.returncode != 0 and "nonexistent" in p.stderr, p.stderr)
    builtin = run(["dotnet", tool, "policy"]).stdout
    # A capability or finding must have exactly one home, and one group within "fullAccess".
    for what, old, new, error in [
        ("a capability in two fullAccess groups", '"native-code": "Runs native code",',
         '"native-code": "Runs native code",\n        "raw-memory": "Reads or writes raw memory",', "capability 'raw-memory' must appear in exactly one of"),
        ("a capability in both fullAccess and informational", '"informational": [', '"informational": ["raw-memory", ', "capability 'raw-memory' must appear in exactly one of"),
        ("a capability in both fullAccess and a label", '"native-code": "Runs native code",',
         '"native-code": "Runs native code",\n        "network": "Connects",', "capability 'network' must appear in exactly one of"),
        ("a finding in two fullAccess groups", '"native-code": "Runs native code",',
         '"native-code": "Runs native code",\n        "unanalyzed-call": "Calls other code",', "finding 'unanalyzed-call' must appear in exactly one fullAccess group"),
        ("a finding in no group", '"unanalyzed-call": "Calls code that was not analyzed"', '"raw-memory-other": "x"', "finding 'unanalyzed-call' must appear in exactly one fullAccess group"),
        ("a combination in a group that does not exist", '"group": "system-access", "text": "Connects to the internet and changes files where',
         '"group": "nowhere", "text": "Connects to the internet and changes files where', "names group 'nowhere', which is not a fullAccess group"),
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
    check("reflection: runtime-built type name is Full access",
          r["tier"] == "full-access" and any("ByRuntimeName" in e for e in evidence(r)), r)
    check("reflection: constant type name is not reported as unresolved",
          not any("ByConstant" in e and "runtime value" in e for e in evidence(r)), r)



def g_impersonation():
    # impersonation and the allowlist
    fake = fx("impersonation", "0Harmony.dll")
    r = analyze(fake, allowlist=write_json(j("allow-fake.json"), {"libraries": {"0" * 64: {"name": "0Harmony"}}}))
    check("impersonation: trusted name with unknown hash is analyzed and Full access",
          INTERNET in labels(r) and r["warnings"] and r["tier"] == "full-access"
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
    check("boundary: a call into an assembly that was not analyzed is Full access, not fully checked",
          r["tier"] == "full-access" and groups(r) == {UNCHECKED: [UNANALYZED]}
          and any("NetHelper.Downloader::Fetch in NetHelper" in e for e in evidence(r)), r)
    allow_lib = write_json(j("allow-lib.json"), {"libraries": {sha256(lib_dll): {"name": "NetHelper"}}})
    r = analyze(mod_dll, lib_dll, allowlist=allow_lib)
    check("library: a trusted library without a profile is not analyzed (fails closed)",
          r["trusted"] == ["NetHelper"] and r["tier"] == "full-access" and UNANALYZED in groups(r).get(UNCHECKED, [])
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
    check("library: a member reaching a Full-access capability (through an override) makes the mod Full access",
          r["tier"] == "full-access" and "Starts other programs" in reasons(r)
          and any("ToolHelper.Job::Run" in e and "StartJob::Run" in e for e in evidence(r)), r)
    r = analyze(exempt_dll, allowlist=allow_lib, libraries=lib_profile)
    check("library: code generation in a library member is Full access", "Builds code at run time" in reasons(r), r)
    marker = '"libraries": {\n    "exempt": ['
    exempt_policy = j("policy-exempt.jsonc")
    with open(exempt_policy, "w") as f:
        f.write(builtin.replace(marker, marker + '\n      { "library": "ToolHelper", "member": "ToolHelper.Compiler::", '
                                '"caps": ["code-generation", "unresolved-reflection"], "reason": "test" },', 1))
    exempt_profile = j("library-profiles-exempt.json")
    run(["dotnet", tool, "profile", "--library", "--allowlist", allow_lib, "--policy", exempt_policy, "--out", exempt_profile, lib_dll, tools_dll])
    r = analyze(exempt_dll, allowlist=allow_lib, libraries=exempt_profile, policy=exempt_policy)
    check("library: an exempt member does not pass its Full-access capability", marker in builtin and r["tier"] == "limited-access", r)
    r = analyze(full_dll, allowlist=allow_lib, libraries=exempt_profile, policy=exempt_policy)
    check("library: an exemption covers only the members and capabilities it names", r["tier"] == "full-access", r)
    p = run(["dotnet", tool, "analyze", "--allowlist", allow_lib, "--library-profile", exempt_profile, mod_dll], expect=None)
    check("library: a profile made with another policy is refused", p.returncode != 0 and "different policy" in p.stderr, p.stderr)
    allow_two = write_json(j("allow-two.json"), {"libraries": {sha256(lib_dll): {"name": "NetHelper"}, "1" * 64: {"name": "NetHelper"}}})
    r = analyze(mod_dll, allowlist=allow_two, libraries=lib_profile)
    check("library: a trusted version without a profile fails closed",
          r["tier"] == "full-access" and UNANALYZED in groups(r).get(UNCHECKED, []) and any("no library profile for trusted file 111111111111" in e for e in evidence(r)), r)



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
    check("game-api: profile keeps Full-access capabilities", methods.get("KSA.Links::Open") == ["process-start"], methods)
    check("game-api: profile leaves out exempt capabilities, or maps them to a label",
          "KSA.Vec3::First" not in methods and methods.get("KSA.UpdateAvailablePopup::OpenBrowser") == ["shell-open"], methods)
    r = analyze(game_mod, profile=profile)
    check("game-api: mod inherits the label from the map", labels(r) == [SAVES] and r["tier"] == "limited-access", r)
    r = analyze(fx("game-api/mod-full", "GameApiModFull.dll"), profile=profile)
    check("game-api: a game member reaching a Full-access capability makes the mod Full access",
          r["tier"] == "full-access" and "Starts other programs" in reasons(r) and any("KSA.Links::Open (game API)" in e for e in evidence(r)), r)
    r = analyze(fx("game-api/mod-exempt", "GameApiModExempt.dll"), profile=profile)
    check("game-api: exempt game members do not make the mod Full access", r["tier"] == "limited-access" and labels(r) == [WEBSITES], r)
    stale = dict(game)
    del stale["format"]
    p = run(["dotnet", tool, "analyze", "--game-profile", write_json(j("game-profile-stale.json"), stale), game_mod], expect=None)
    check("game-api: a profile from an older tool is refused", p.returncode != 0 and "older version" in p.stderr, p.stderr)
    del game["assemblies"]
    r = analyze(game_mod, profile=write_json(j("game-profile-old.json"), game))
    check("game-api: a profile without an assembly list falls back to the policy's game assemblies",
          labels(r) == [SAVES] and r["tier"] == "limited-access", r)
    r = analyze(game_mod)
    check("game-api: without a profile, a call into the game is still accounted for", r["tier"] == "limited-access", r)
    other = dict(game, assemblies=["SomethingElse"])
    r = analyze(game_mod, profile=write_json(j("game-profile-other.json"), other))
    check("game-api: an assembly the profile does not list is not the game", UNANALYZED in reasons(r), r)



def g_classification():
    # classification: framework members must match a policy rule
    r = analyze(fx("classification/safe", "ClassificationSafe.dll"))
    check("classification: safe-listed framework members are Limited access", r["tier"] == "limited-access" and not r["labels"], r)
    r = analyze(fx("classification/unclassified", "ClassificationUnclassified.dll"))
    check("classification: a framework member no rule matches is Full access, not fully checked",
          r["tier"] == "full-access" and groups(r) == {UNCHECKED: [UNCLASSIFIED]}
          and any("System.AppContext::SetSwitch" in e for e in evidence(r)), r)



def g_file_access():
    # labels and file access
    r = analyze(fx("labels", "LabelsFixture.dll"))
    check("labels: bundled labels", labels(r) == [INFO, SETTINGS, CLOSES] and r["tier"] == "limited-access", r)
    r = analyze(fx("file-access", "FileAccessFixture.dll"))
    check("file-access: writes are labelled by where they go", labels(r) == [CODE_FILES, FILES_OUT] and r["tier"] == "limited-access", r)
    by_label = {l["text"]: l["evidence"] for l in r["labels"]}
    check("file-access: the write to the mod's own folder is a code-folder write, not an outside one",
          any("WriteOwnConfig" in e for e in by_label.get(CODE_FILES, []))
          and not any("WriteOwnConfig" in e for e in by_label.get(FILES_OUT, [])), r)
    r = analyze(fx("download", "DownloadFixture.dll"))
    check("file-access: a network connection and a write into the mod's own folder are Full access",
          r["tier"] == "full-access" and groups(r) == {SYSTEM: ["Connects to the internet and changes files where the game loads code from"]}
          and INTERNET in labels(r) and CODE_FILES in labels(r), r)
    p = run(["dotnet", tool, "policy"])
    combo = j("policy-combo.jsonc")
    with open(combo, "w") as f:
        f.write(p.stdout.replace('"caps": ["network", "file-write-code"]', '"caps": ["network", "native-code"]', 1))
    p = run(["dotnet", tool, "analyze", "--policy", combo, corrupt], expect=None)
    check("policy: a combination of a Full-access capability is rejected", p.returncode != 0 and "Full access on its own" in p.stderr, p.stderr)
    with open(combo, "w") as f:
        f.write(builtin.replace('"caps": ["network", "file-write-code"]', '"caps": ["network", "raw-memory"]', 1))
    p = run(["dotnet", tool, "analyze", "--policy", combo, corrupt], expect=None)
    check("policy: a combination of a deep-game-access capability is rejected",
          p.returncode != 0 and "Full access on its own (Deep game access)" in p.stderr, p.stderr)



def g_shell_open():
    # opening websites vs starting programs
    r = analyze(fx("shell-open/link", "ShellOpenLink.dll"))
    check("shell-open: a fixed web address is Limited access", labels(r) == [WEBSITES] and r["tier"] == "limited-access", r)
    r = analyze(fx("shell-open/program", "ShellOpenProgram.dll"))
    check("shell-open: starting a program or an arbitrary target is Full access",
          r["tier"] == "full-access" and "Starts other programs" in groups(r).get(SYSTEM, [])
          and len(r["fullAccess"][0]["reasons"][0]["evidence"]) == 2, r)



def g_raw_memory():
    # raw memory
    r = analyze(fx("raw-memory/safe", "RawMemorySafe.dll"))
    check("raw-memory: compiler-generated span helpers are not raw memory", r["tier"] == "limited-access", r)
    unsafe_dll = fx("raw-memory/unsafe", "RawMemoryUnsafe.dll")
    r = analyze(unsafe_dll)
    check("raw-memory: pointer code is Full access, deep game access only",
          r["tier"] == "full-access" and groups(r) == {DEEP: [RAW_MEMORY]}, r)
    p = run(["dotnet", tool, "analyze", unsafe_dll])
    check("raw-memory: the text report gives the tier summary and the group",
          "It can do anything a program on your computer can." in p.stdout and "Why: Deep game access\n" in p.stdout
          and "Deep game access: Works with the game's code and memory directly" in p.stdout and "System access" not in p.stdout, p.stdout)
    # One mod with reasons in two groups: both groups are kept, in policy order.
    reflection_dll = fx("reflection", "ReflectionFixture.dll")
    r = analyze(unsafe_dll, reflection_dll)
    check("tiers: a mod with reasons in two groups is Full access and lists both",
          r["tier"] == "full-access" and r["tierName"] == "Full access"
          and r["tierSummary"] == "It can do anything a program on your computer can."
          and [g["group"] for g in r["fullAccess"]] == [DEEP, SYSTEM] and r["fullAccess"][1]["name"] == "System access"
          and groups(r)[DEEP] == [RAW_MEMORY] and UNTRACED in groups(r)[SYSTEM] and INTERNET in labels(r), r)
    p = run(["dotnet", tool, "analyze", unsafe_dll, reflection_dll])
    check("tiers: the text report lists every group",
          "Why: Deep game access · System access\n" in p.stdout and "  System access: Uses features that can reach anything on your computer.\n" in p.stdout, p.stdout)
    r = analyze(fx("raw-memory/safe", "RawMemorySafe.dll"))
    check("tiers: a Limited-access mod has the tier's name and summary and no group",
          r["tierName"] == "Limited access" and r["tierSummary"] == "It can only do what's listed." and r["fullAccess"] == [], r)
    raw = facts(unsafe_dll)[0]["caps"].get("raw-memory", [])
    check("raw-memory: a pointer type in a referenced signature is recorded",
          any("pointer type in the signature of System.IntPtr::ToPointer" in e for e in raw), raw)
    check("raw-memory: a store through a non-managed address is recorded",
          any(e.startswith("stind.i8 through an address") for e in raw), raw)



def g_fail_open():
    # fail-open cases
    fail_open_dll = fx("fail-open", "FailOpenFixture.dll")
    r = analyze(fail_open_dll)
    check("fail-open: P/Invoke and COM activation are Full access",
          "Runs native code" in reasons(r) and "Starts a COM component" in reasons(r), r)
    corrupted = j("Corrupted.dll")
    run(["dotnet", corrupt, fail_open_dll, corrupted])
    r = analyze(corrupted)
    check("fail-open: undecodable IL is Full access", "Contains code the check cannot read" in reasons(r), r)
    junk = j("junk.dll")
    with open(junk, "wb") as f:
        f.write(b"not a PE file")
    r = analyze(junk)
    check("fail-open: an unreadable file is Full access, not fully checked", groups(r) == {UNCHECKED: ["Contains a file the check cannot read"]}, r)
    # ELF and Mach-O libraries are native binaries, counted once as that, not as unreadable files.
    natives = []
    for name, magic in [("libnative.so", b"\x7fELF\x02\x01\x01"), ("libnative.dylib", b"\xcf\xfa\xed\xfe\x07\x00\x00\x01")]:
        natives.append(j(name))
        with open(natives[-1], "wb") as f:
            f.write(magic + b"\0" * 64)
    r = analyze(*natives)
    check("fail-open: ELF and Mach-O files are native binaries, not unreadable files",
          groups(r) == {SYSTEM: ["Ships a native program or library"]} and len(r["fullAccess"][0]["reasons"][0]["evidence"]) == 2, r)
    # precompiled native code: the shared framework's own assemblies are ReadyToRun images
    if runtime_dir:
        r2r = os.path.join(runtime_dir, "System.Linq.dll")
        r = analyze(r2r)
        check("fail-open: a ReadyToRun image is Full access", any("precompiled native code" in e for e in evidence(r)), reasons(r))
    p = run(["dotnet", tool, "analyze", "--allowlist", j("missing.json"), fail_open_dll], expect=None)
    check("cli: a missing allowlist path is an error", p.returncode != 0)



def g_embedded():
    # embedded resources: one assembly per payload
    for payload, tier in EMBEDDED.items():
        r = analyze(case_dll("embedded", payload))
        ok = r["tier"] == tier and (tier == "limited-access" or EMBEDDED_BINARY in groups(r).get(UNCHECKED, []))
        check(f"embedded: {payload} resource is {tier}", ok, {"tier": r["tier"], "fullAccess": r["fullAccess"]})



def g_harmony_patch():
    # Harmony patch attributes: the stand-in 0Harmony is a trusted library with a profile
    allow_harmony, harmony_profile = harmony()
    profile = game_profile()
    for case, expected in HARMONY_PATCH.items():
        r = analyze(case_dll("harmony-patch/mod", case), allowlist=allow_harmony, libraries=harmony_profile, profile=profile)
        check(f"harmony-patch: {case}", expect(r, expected), {"tier": r["tier"], "labels": labels(r), "fullAccess": groups(r)})
    r = analyze(case_dll("harmony-patch/mod", "GameFullTarget"), allowlist=allow_harmony, libraries=harmony_profile)
    check("harmony-patch: without a game profile, a patched game member adds nothing", r["tier"] == "limited-access", r)



def g_reflection_precision():
    allow_harmony, harmony_profile = harmony()
    profile = game_profile()
    # reflection the check traces: member arrays, parameters, iterators, expression trees, bounded types
    for case, expected in REFLECTION_PRECISION.items():
        r = analyze(case_dll("reflection-precision", case), allowlist=allow_harmony, libraries=harmony_profile, profile=profile)
        check(f"reflection-precision: {case}", expect(r, expected),
              {"tier": r["tier"], "labels": labels(r), "fullAccess": groups(r)})
    # The bounded reason is deep game access only: the same mod has no other group, and no unresolved reflection.
    r = analyze(case_dll("reflection-precision", "BoundedGameType"),
                allowlist=allow_harmony, libraries=harmony_profile, profile=profile)
    check("reflection-precision: bounded reflection is in the deep-game-access group only",
          groups(r) == {DEEP: [BOUNDED]} and UNTRACED not in reasons(r), r)



def g_game_interaction():
    allow_harmony, harmony_profile = harmony()
    profile = game_profile()
    # game interaction: transpilers, observing patches, opening own folders, network values, named lookups, XML
    for case, expected in GAME_INTERACTION.items():
        r = analyze(case_dll("game-interaction", case), allowlist=allow_harmony, libraries=harmony_profile, profile=profile)
        check(f"game-interaction: {case}", expect(r, expected),
              {"tier": r["tier"], "labels": labels(r), "fullAccess": groups(r)})



def g_evasion():
    allow_harmony, harmony_profile = harmony()
    # evasion fixtures: one assembly per case
    for case, expected in EVASION.items():
        # The Harmony cases reference the trusted stand-in 0Harmony (see fixtures/evasion/evasion.csproj).
        r = analyze(case_dll("evasion", case), allowlist=allow_harmony, libraries=harmony_profile)
        check(f"evasion: {case}", expect(r, expected), {"tier": r["tier"], "labels": labels(r), "fullAccess": groups(r)})



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
          mods["SampleMod"]["tier"] == "full-access" and mods["ContentMod"]["tier"] == "no-code"
          and mods["ArchiveMod"]["tier"] == "full-access", {k: v["tier"] for k, v in mods.items()})
    nested = mods["NestedMod"]
    check("extract: an archive inside an archive is extracted and analyzed",
          any("ReflectionFixture" in (f.get("name") or "") for f in nested["files"]), nested["files"])
    check("extract: a nested archive that cannot be opened is Full access",
          "Contains an archive the check cannot open" in reasons(nested), reasons(nested))
    check("extract: a shipped script is Full access, not fully checked",
          mods["ScriptMod"]["tier"] == "full-access" and "Ships a script or installer" in groups(mods["ScriptMod"]).get(UNCHECKED, []), mods["ScriptMod"])
    unopened = "Contains an archive the check cannot open"
    check("extract: an archive with unsafe entries counts as not extracted, and its other files are analyzed",
          unopened in reasons(mods["SampleMod"]) and unopened in reasons(mods["TarMod"])
          and any("ReflectionFixture" in (f.get("name") or "") for f in mods["TarMod"]["files"]),
          {k: (reasons(mods[k]), mods[k]["files"]) for k in ("SampleMod", "TarMod")})
    case_files = [n for _, _, fs in os.walk(j("extracted", "CaseMod")) for n in fs]
    check("extract: two entries whose names differ only in case are not both written, and the archive is Full access",
          case_files == ["Mod.dll"] and unopened in reasons(mods["CaseMod"]), (case_files, reasons(mods["CaseMod"])))
    check("extract: a zip link entry is not written, and the archive is Full access",
          not os.path.exists(j("extracted", "ZipLinkMod", "ZipLinkMod", "ZipLinkMod", "Evil.dll")) and mods["ZipLinkMod"]["tier"] == "full-access",
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
    changed["mods"]["ContentMod"].update(tier="full-access", fullAccess=[group(SYSTEM, "System access", "Runs native code")])
    p = run(["dotnet", pipeline, "compare-results", j("result.json"), write_json(j("result-changed.json"), changed)])
    tier_changes, group_changes = p.stdout.split("## tier changes")[-1].split("## reason group changes (Full access in both)")
    check("compare-results: lists the mod whose tier changed, with its new reasons",
          tier_changes.strip() == "ContentMod: no-code -> full-access  (new: Runs native code)" and group_changes.strip() == "none", p.stdout)
    deep = json.loads(json.dumps(changed))
    deep["mods"]["ContentMod"].update(fullAccess=[group(DEEP, "Deep game access", RAW_MEMORY)])
    p = run(["dotnet", pipeline, "compare-results", write_json(j("result-deep.json"), deep), j("result-changed.json")])
    after = p.stdout.split("## ")[2]
    check("compare-results: counts three tiers and the reasons of each group, and lists a mod whose groups changed",
          "  full-access    " in after and "  unverified" not in after
          and re.search(r"  system-access reasons \(\d+ mods\):\n(    .*\n)*       1  Runs native code\n", after)
          and p.stdout.split("## tier changes")[-1].split("## ")[0].strip() == "none"
          and p.stdout.split("(Full access in both)")[-1].strip()
          == f"ContentMod: [{DEEP}] -> [{SYSTEM}]  (new: Runs native code)  (gone: {RAW_MEMORY})", p.stdout)
    # Results from before policy 13 have four tiers and flat fullAccess and unverified lists (no
    # unverified list before policy 9): old tiers read as the new ones they became.
    old = json.loads(json.dumps(changed))
    for m in old["mods"].values():
        m["tier"] = {"no-code": "content-only", "limited-access": "known-access"}.get(m["tier"], m["tier"])
        m["fullAccess"] = [r for g in m["fullAccess"] for r in g["reasons"]]
    old["mods"]["ContentMod"].update(tier="unverified", fullAccess=[], unverified=[{"text": UNANALYZED, "evidence": []}])
    p = run(["dotnet", pipeline, "compare-results", write_json(j("result-old.json"), old), j("result-changed.json")])
    before = p.stdout.split("## ")[1]
    check("compare-results: reads results from before policy 13",
          "  content-only" not in before and "  unverified reasons (1 mods):\n       1  " + UNANALYZED in before
          and p.stdout.split("## tier changes")[-1].split("## ")[0].strip() == "none"
          and f"ContentMod: [unverified] -> [{SYSTEM}]" in p.stdout.split("(Full access in both)")[-1], p.stdout)
    facts(fx("classification/unclassified", "ClassificationUnclassified.dll"), out=j("facts.json"))
    p = run(["dotnet", pipeline, "rank-unclassified", j("facts.json"), "--by", "type"])
    check("rank-unclassified: ranks the unclassified framework type", "System.AppContext" in p.stdout, p.stdout)



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
    ("game-api", g_game_api, ["game-api/stub", "game-api/mod", "game-api/mod-full", "game-api/mod-exempt"], []),
    ("classification", g_classification, ["classification/safe", "classification/unclassified"], []),
    ("file-access", g_file_access, ["labels", "file-access", "download", "fail-open/corrupt"], []),
    ("shell-open", g_shell_open, ["shell-open/link", "shell-open/program"], []),
    ("raw-memory", g_raw_memory, ["raw-memory/safe", "raw-memory/unsafe", "reflection"], []),
    ("fail-open", g_fail_open, ["fail-open", "fail-open/corrupt"], []),
    ("embedded", g_embedded, [], ["embedded"]),
    ("harmony-patch", g_harmony_patch, STUBS, ["harmony-patch/mod"]),
    ("reflection-precision", g_reflection_precision, STUBS, ["reflection-precision"]),
    ("game-interaction", g_game_interaction, STUBS, ["game-interaction"]),
    ("evasion", g_evasion, ["harmony-patch/stub"], ["evasion"]),
    ("pipeline", g_pipeline, ["reflection", "classification/unclassified"], []),
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
    _local.buf = []
    try:
        fn()
    except Exception:
        out(f"ERROR {name}: the group stopped before its remaining checks\n" + traceback.format_exc())
        failures.append(f"{name}: error")
    return _local.buf


def tests(groups, a):
    global tool, pipeline, corrupt, builtin, runtime_dir
    t0 = time.monotonic()
    projects = ["src/DarkMatter"] + (["src/DarkMatter.Pipeline"] if any(g[0] == "pipeline" for g in groups) else [])
    projects += sorted({"fixtures/" + d for g in groups for d in g[2]})
    build_all(projects, sorted({m for g in groups for m in g[3]}), a.rebuild)
    t1 = time.monotonic()
    tool = os.path.join(REPO, "src", "DarkMatter", "bin", "Release", TFM, "darkmatter.dll")
    pipeline = os.path.join(REPO, "src", "DarkMatter.Pipeline", "bin", "Release", TFM, "darkmatter-pipeline.dll")
    corrupt = fx("fail-open/corrupt", "corrupt.dll")
    builtin = run(["dotnet", tool, "policy"]).stdout
    runtime_dir = framework_dir()
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, a.jobs)) as ex:
        futures = [ex.submit(run_group, name, fn) for name, fn, *_ in groups]
        for fut in futures:
            for text in fut.result():
                print(text, flush=True)
    print(f"\nbuild {t1 - t0:.0f}s, checks {time.monotonic() - t1:.0f}s")


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
    try:
        tests([g for g in GROUPS if g[0] in selected], a)
    finally:
        if a.keep:
            print(f"build directory: {TMP}")
        else:
            shutil.rmtree(TMP, ignore_errors=True)
    skipped = len(GROUPS) - len(set(selected))
    print(f"\n{len(failures)} failure(s)" if failures else "\nall checks passed", end="")
    print(f" in {len(set(selected))} of {len(GROUPS)} groups ({skipped} groups skipped: not a full run)" if skipped else "")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
