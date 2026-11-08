#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the fixtures and check the analyzer and the pipeline's extraction against them.

  test_fixtures.py [--keep]

Requires the .NET 10 SDK and Python 3.9 or later (standard library only). Builds into a
temporary directory and exits non-zero if any check fails. --keep leaves the build directory
in place for inspection.
"""
import argparse, hashlib, io, json, os, shutil, subprocess, sys, tarfile, tempfile, zipfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
failures = []

# Checks expected to fail until the hardening phase that fixes them lands. A pending check
# that fails is reported but does not fail the run; one that passes fails the run, so the
# entry gets removed and any later regression turns the suite red.
PENDING = set()

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
    # Raw memory is Unverified as a whole since policy 9. Reading through an address the mod is
    # handed is a forged-address case: Full access again once raw memory is split (task R2).
    "Peek": [("tier", "unverified"), ("reason", "Reads or writes memory directly")],
    "TypeNames": ("tier", "full-access"),
    "TypeNamesNone": ("tier", "known-access"),
    "ProvenInvoke": ("tier", "known-access"),
    "ProvenField": ("tier", "known-access"),
    "ProvenBranch": ("tier", "known-access"),
    "HarmonyByName": [("tier", "known-access"), ("label", "Connects to the internet")],
    "TraverseByName": ("tier", "known-access"),
    "MethodGroupDelete": ("label", "Changes files outside the game"),
}

# Embedded-resource fixtures (fixtures/embedded, one assembly per payload): expected tier.
EMBEDDED = {"text": "known-access", "pe": "full-access", "zip": "full-access", "costura": "full-access", "linked": "full-access"}

# Harmony patch-attribute fixtures (fixtures/harmony-patch/mod/cases/<case>.cs), analyzed with the
# Harmony stand-in allowlisted and profiled, and the game stand-in's profile. Same form as EVASION.
HARMONY_PATCH = {
    "GameTarget": [("tier", "known-access"), ("labels", ["Changes how the game works"])],
    "GameFullTarget": [("tier", "full-access"), ("reason", "Starts other programs")],
    "FrameworkTarget": [("tier", "known-access"), ("label", "Changes files outside the game")],
    "ProcessTarget": [("tier", "full-access"), ("reason", "Starts other programs")],
    "ByName": [("tier", "full-access"), ("reason", "Starts other programs")],
    "CustomAttribute": [("tier", "full-access"), ("reason", "Uses reflection the check cannot trace")],
    "TargetMethodUntraced": [("tier", "full-access"), ("reason", "Uses reflection the check cannot trace")],
    "TargetMethodTraced": [("tier", "known-access"), ("labels", ["Changes how the game works"])],
    "Delegate": [("tier", "full-access"), ("reason", "Starts other programs")],
    "ReversePatch": [("tier", "known-access"), ("label", "Changes game saves")],
    "PatchAll": [("tier", "full-access"), ("reason", "Starts other programs")],
}

# Reflection the check traces since policy 10 (fixtures/reflection-precision/cases/<case>.cs): benign
# controls, analyzed like the Harmony patch fixtures. Same form as EVASION.
BOUNDED = "Uses reflection on the game's or its own code that the check cannot fully follow"
REFLECTION_PRECISION = {
    "MemberArrayMod": [("tier", "known-access"), ("labels", [])],
    "MemberArrayGame": [("tier", "known-access"), ("labels", ["Changes game saves"])],
    "MemberParameter": [("tier", "known-access"), ("labels", [])],
    "TargetMethodsIterator": [("tier", "known-access"), ("labels", ["Changes how the game works"])],
    "ExpressionCompiled": [("tier", "known-access"), ("labels", [])],
    "BoundedGameType": [("tier", "unverified"), ("reason", BOUNDED)],
}

# Ordinary game interaction that policy 11 no longer counts as Full access (fixtures/game-interaction/
# cases/<case>.cs): benign controls, and the real APIs next to them that still are. Analyzed like the
# Harmony patch fixtures. Same form as EVASION.
REWRITES = "Rewrites the game's code with a Harmony transpiler, which the check cannot follow instruction by instruction"
XML_TYPES = "Reads or writes XML into objects whose types the check does not follow"
GAME_INTERACTION = {
    "TranspilerOperand": [("tier", "unverified"), ("unverified", [REWRITES]), ("labels", ["Changes how the game works"])],
    "DynamicMethodEmit": [("tier", "full-access"), ("reason", "Builds code at run time")],
    "TranspileFramework": [("tier", "full-access"), ("reason", "Rewrites code other than the game's with a Harmony transpiler")],
    "ObservingPostfix": [("tier", "known-access"), ("labels", ["Changes how the game works"])],
    "OpenOwnFolder": [("tier", "known-access"), ("labels", ["Changes files in its own or the game's folders", "Opens its own or the game's folders"])],
    "NetworkValues": [("tier", "known-access"), ("labels", ["Reads information about you and your computer"])],
    "NamedMemberLookup": [("tier", "known-access"), ("labels", [])],
    "AnyMemberLookup": [("tier", "known-access"), ("labels", ["Uses your clipboard"])],
    "XmlSettings": [("tier", "unverified"), ("unverified", [XML_TYPES]), ("labels", [])],
    "XmlOwnFolder": [("tier", "known-access"), ("labels", ["Reads files outside the game"])],
    "XmlUntraced": [("tier", "known-access"), ("label", "Connects to the internet")],
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
    """Whether a mod result meets a list of (kind, want): tier, label (present), labels (exact), unverified (exact
    Unverified reasons, and no Full-access ones), reason (of either tier)."""
    def one(kind, want):
        if kind == "tier": return r["tier"] == want
        if kind == "label": return want in labels(r)
        if kind == "labels": return labels(r) == want
        if kind == "unverified": return unverified_reasons(r) == want and not r["fullAccess"]
        return want in reasons(r)
    return all(one(k, w) for k, w in (expected if isinstance(expected, list) else [expected]))


def check(name, ok, detail=""):
    if name in PENDING:
        print(f"{'XPASS' if ok else 'PEND '}  {name}" + ("  (now passes: remove it from PENDING)" if ok else ""))
        if ok:
            failures.append(name)
        return
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if not ok and detail != "" else ""))
    if not ok:
        failures.append(name)


def run(cmd, expect=0):
    p = subprocess.run(cmd, capture_output=True, text=True)
    if expect is not None and p.returncode != expect:
        raise RuntimeError(f"{' '.join(cmd)} exited {p.returncode}\n{p.stdout}\n{p.stderr}")
    return p


def build(project, out):
    run(["dotnet", "build", os.path.join(REPO, project), "-c", "Release", "-o", out, "--nologo", "-v", "q"])
    return out


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


def reasons(mod):
    """Full-access and Unverified reasons."""
    return full_reasons(mod) + unverified_reasons(mod)


def full_reasons(mod):
    return [r["text"] for r in mod["fullAccess"]]


def unverified_reasons(mod):
    return [r["text"] for r in mod["unverified"]]


def evidence(mod):
    return [e for f in mod["labels"] + mod["fullAccess"] + mod["unverified"] for e in f["evidence"]]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args()
    os.environ.setdefault("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
    os.environ.setdefault("DOTNET_NOLOGO", "1")
    tmp = tempfile.mkdtemp(prefix="dark-matter-test-")
    try:
        tests(tmp)
    finally:
        if a.keep:
            print(f"build directory: {tmp}")
        else:
            shutil.rmtree(tmp, ignore_errors=True)
    print(f"\n{len(failures)} failure(s)" if failures else "\nall checks passed")
    return 1 if failures else 0


def tests(tmp):
    j = lambda *p: os.path.join(tmp, *p)
    tool = os.path.join(build("src/DarkMatter", j("tool")), "darkmatter.dll")
    corrupt = os.path.join(build("fixtures/fail-open/corrupt", j("corrupt")), "corrupt.dll")
    fx = lambda project, dll: os.path.join(build(f"fixtures/{project}", j("fx", project.replace("/", "-"))), dll)

    def analyze(*files, allowlist=None, manifest=None, profile=None, libraries=None, policy=None):
        out = j("result.json")
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

    def facts(*files):
        out = j("facts.json")
        run(["dotnet", tool, "analyze", "--json", j("result.json"), "--facts", out] + list(files))
        with open(out) as f:
            return json.load(f)["files"]

    # policy
    p = run(["dotnet", tool, "policy"])
    check("policy: built-in policy loads and validates", '"version"' in p.stdout)
    bad = j("bad-policy.jsonc")
    with open(bad, "w") as f:
        f.write(p.stdout.replace('"informational": [', '"informational": ["nonexistent", '))
    p = run(["dotnet", tool, "analyze", "--policy", bad, corrupt], expect=None)
    check("policy: a capability no rule produces is rejected", p.returncode != 0 and "nonexistent" in p.stderr, p.stderr)
    builtin = run(["dotnet", tool, "policy"]).stdout
    # A capability or finding must have exactly one home, the "unverified" section included.
    for what, old, new, error in [
        ("a capability in both fullAccess and unverified", '"native-code": "Runs native code",',
         '"native-code": "Runs native code",\n    "raw-memory": "Reads or writes raw memory",', "capability 'raw-memory' must appear in exactly one of"),
        ("a capability in both unverified and informational", '"informational": [', '"informational": ["raw-memory", ', "capability 'raw-memory' must appear in exactly one of"),
        ("a capability in both fullAccess and a label", '"native-code": "Runs native code",',
         '"native-code": "Runs native code",\n    "network": "Connects",', "capability 'network' must appear in exactly one of"),
        ("a finding in both fullAccess and unverified", '"native-code": "Runs native code",',
         '"native-code": "Runs native code",\n    "unanalyzed-call": "Calls other code",', "finding 'unanalyzed-call' must appear in exactly one of"),
        ("a finding in neither", '"unanalyzed-call": "Calls code that was not analyzed"', '"raw-memory-other": "x"', "finding 'unanalyzed-call' must appear in exactly one of"),
    ]:
        twice = j("policy-twice.jsonc")
        with open(twice, "w") as f:
            f.write(builtin.replace(old, new, 1))
        p = run(["dotnet", tool, "analyze", "--policy", twice, corrupt], expect=None)
        check(f"policy: {what} is rejected", old in builtin and p.returncode != 0 and error in p.stderr, p.stderr)

    # reflection
    r = analyze(fx("reflection", "ReflectionFixture.dll"))
    check("reflection: constant type name is labelled", INTERNET in labels(r), r)
    check("reflection: runtime-built type name is Full access",
          r["tier"] == "full-access" and any("ByRuntimeName" in e for e in evidence(r)), r)
    check("reflection: constant type name is not reported as unresolved",
          not any("ByConstant" in e and "runtime value" in e for e in evidence(r)), r)

    # impersonation and the allowlist
    fake = fx("impersonation", "0Harmony.dll")
    r = analyze(fake, allowlist=write_json(j("allow-fake.json"), {"libraries": {"0" * 64: {"name": "0Harmony"}}}))
    check("impersonation: trusted name with unknown hash is analyzed and Full access",
          INTERNET in labels(r) and r["warnings"] and r["tier"] == "full-access"
          and "Ships a file named like a part of .NET, the game or a trusted library" in reasons(r), r)
    r = analyze(fake, allowlist=write_json(j("allow-real.json"), {"libraries": {sha256(fake): {"name": "0Harmony"}}}))
    check("allowlist: matching hash is skipped", r["trusted"] == ["0Harmony"] and not r["labels"], r)

    # library propagation
    mod_dll = fx("library-propagation/mod", "PropagationMod.dll")
    lib_dll = os.path.join(os.path.dirname(mod_dll), "NetHelper.dll")
    r = analyze(mod_dll, lib_dll)
    check("propagation: a bundled library's network use labels the mod", INTERNET in labels(r), r)
    check("propagation: a call into a bundled library is accounted for", r["tier"] == "known-access", r)
    r = analyze(mod_dll)
    check("boundary: a call into an assembly that was not analyzed is Unverified",
          r["tier"] == "unverified" and unverified_reasons(r) == [UNANALYZED] and not r["fullAccess"]
          and any("NetHelper.Downloader::Fetch in NetHelper" in e for e in evidence(r)), r)
    allow_lib = write_json(j("allow-lib.json"), {"libraries": {sha256(lib_dll): {"name": "NetHelper"}}})
    r = analyze(mod_dll, lib_dll, allowlist=allow_lib)
    check("library: a trusted library without a profile is not analyzed (fails closed)",
          r["trusted"] == ["NetHelper"] and r["tier"] == "unverified" and UNANALYZED in unverified_reasons(r)
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
          r["tier"] == "known-access" and INTERNET in labels(r), r)
    r = analyze(mod_dll, lib_dll, allowlist=allow_lib, libraries=lib_profile)
    check("library: a shipped trusted copy resolves to its profile", r["tier"] == "known-access" and INTERNET in labels(r), r)
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
    check("library: an exempt member does not pass its Full-access capability", marker in builtin and r["tier"] == "known-access", r)
    r = analyze(full_dll, allowlist=allow_lib, libraries=exempt_profile, policy=exempt_policy)
    check("library: an exemption covers only the members and capabilities it names", r["tier"] == "full-access", r)
    p = run(["dotnet", tool, "analyze", "--allowlist", allow_lib, "--library-profile", exempt_profile, mod_dll], expect=None)
    check("library: a profile made with another policy is refused", p.returncode != 0 and "different policy" in p.stderr, p.stderr)
    allow_two = write_json(j("allow-two.json"), {"libraries": {sha256(lib_dll): {"name": "NetHelper"}, "1" * 64: {"name": "NetHelper"}}})
    r = analyze(mod_dll, allowlist=allow_two, libraries=lib_profile)
    check("library: a trusted version without a profile fails closed",
          r["tier"] == "unverified" and UNANALYZED in unverified_reasons(r) and any("no library profile for trusted file 111111111111" in e for e in evidence(r)), r)

    # game-API map: emit from the game stub, then apply to the mod
    stub = fx("game-api/stub", "KSA.dll")
    game_mod = fx("game-api/mod", "GameApiMod.dll")
    profile = j("game-profile.json")
    runtime_dir = framework_dir()
    run(["dotnet", tool, "profile", "--out", profile, stub] + ([os.path.join(runtime_dir, "System.Linq.dll")] if runtime_dir else []))
    with open(profile) as f:
        game = json.load(f)
    methods = game["methods"]
    check("game-api: profile maps the save method to game saves", methods.get("KSA.GameSaves::MakeSave") == ["file-saves"], methods)
    check("game-api: profile lists the game's assemblies and skips the runtime's", game.get("assemblies") == ["KSA"], game.get("assemblies"))
    check("game-api: profile keeps Full-access capabilities", methods.get("KSA.Links::Open") == ["process-start"], methods)
    check("game-api: profile leaves out exempt capabilities, or maps them to a label",
          "KSA.Vec3::First" not in methods and methods.get("KSA.UpdateAvailablePopup::OpenBrowser") == ["shell-open"], methods)
    r = analyze(game_mod, profile=profile)
    check("game-api: mod inherits the label from the map", labels(r) == [SAVES] and r["tier"] == "known-access", r)
    r = analyze(fx("game-api/mod-full", "GameApiModFull.dll"), profile=profile)
    check("game-api: a game member reaching a Full-access capability makes the mod Full access",
          r["tier"] == "full-access" and "Starts other programs" in reasons(r) and any("KSA.Links::Open (game API)" in e for e in evidence(r)), r)
    r = analyze(fx("game-api/mod-exempt", "GameApiModExempt.dll"), profile=profile)
    check("game-api: exempt game members do not make the mod Full access", r["tier"] == "known-access" and labels(r) == [WEBSITES], r)
    stale = dict(game)
    del stale["format"]
    p = run(["dotnet", tool, "analyze", "--game-profile", write_json(j("game-profile-stale.json"), stale), game_mod], expect=None)
    check("game-api: a profile from an older tool is refused", p.returncode != 0 and "older version" in p.stderr, p.stderr)
    del game["assemblies"]
    r = analyze(game_mod, profile=write_json(j("game-profile-old.json"), game))
    check("game-api: a profile without an assembly list falls back to the policy's game assemblies",
          labels(r) == [SAVES] and r["tier"] == "known-access", r)
    r = analyze(game_mod)
    check("game-api: without a profile, a call into the game is still accounted for", r["tier"] == "known-access", r)
    other = dict(game, assemblies=["SomethingElse"])
    r = analyze(game_mod, profile=write_json(j("game-profile-other.json"), other))
    check("game-api: an assembly the profile does not list is not the game", UNANALYZED in reasons(r), r)

    # classification: framework members must match a policy rule
    r = analyze(fx("classification/safe", "ClassificationSafe.dll"))
    check("classification: safe-listed framework members are Known access", r["tier"] == "known-access" and not r["labels"], r)
    r = analyze(fx("classification/unclassified", "ClassificationUnclassified.dll"))
    check("classification: a framework member no rule matches is Unverified",
          r["tier"] == "unverified" and unverified_reasons(r) == [UNCLASSIFIED] and not r["fullAccess"]
          and any("System.AppContext::SetSwitch" in e for e in evidence(r)), r)

    # labels and file access
    r = analyze(fx("labels", "LabelsFixture.dll"))
    check("labels: bundled labels", labels(r) == [INFO, SETTINGS, CLOSES] and r["tier"] == "known-access", r)
    r = analyze(fx("file-access", "FileAccessFixture.dll"))
    check("file-access: writes are labelled by where they go", labels(r) == [CODE_FILES, FILES_OUT] and r["tier"] == "known-access", r)
    by_label = {l["text"]: l["evidence"] for l in r["labels"]}
    check("file-access: the write to the mod's own folder is a code-folder write, not an outside one",
          any("WriteOwnConfig" in e for e in by_label.get(CODE_FILES, []))
          and not any("WriteOwnConfig" in e for e in by_label.get(FILES_OUT, [])), r)
    r = analyze(fx("download", "DownloadFixture.dll"))
    check("file-access: a network connection and a write into the mod's own folder are Full access",
          r["tier"] == "full-access" and full_reasons(r) == ["Connects to the internet and changes files where the game loads code from"]
          and not r["unverified"]
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
    check("policy: a combination of an Unverified capability is rejected", p.returncode != 0 and "Unverified on its own" in p.stderr, p.stderr)

    # opening websites vs starting programs
    r = analyze(fx("shell-open/link", "ShellOpenLink.dll"))
    check("shell-open: a fixed web address is Known access", labels(r) == [WEBSITES] and r["tier"] == "known-access", r)
    r = analyze(fx("shell-open/program", "ShellOpenProgram.dll"))
    check("shell-open: starting a program or an arbitrary target is Full access",
          r["tier"] == "full-access" and "Starts other programs" in reasons(r) and len(r["fullAccess"][0]["evidence"]) == 2, r)

    # raw memory
    r = analyze(fx("raw-memory/safe", "RawMemorySafe.dll"))
    check("raw-memory: compiler-generated span helpers are not raw memory", r["tier"] == "known-access", r)
    unsafe_dll = fx("raw-memory/unsafe", "RawMemoryUnsafe.dll")
    r = analyze(unsafe_dll)
    check("raw-memory: pointer code is Unverified",
          r["tier"] == "unverified" and unverified_reasons(r) == [RAW_MEMORY] and not r["fullAccess"], r)
    p = run(["dotnet", tool, "analyze", unsafe_dll])
    check("raw-memory: the text report says what Unverified means",
          "Unverified because it:" in p.stdout and "cannot rule that out" in p.stdout and "Full access because it:" not in p.stdout, p.stdout)
    # One mod with reasons of both tiers: the higher tier wins and both lists are kept.
    reflection_dll = fx("reflection", "ReflectionFixture.dll")
    r = analyze(unsafe_dll, reflection_dll)
    check("tiers: a mod with Unverified and Full-access reasons is Full access and lists both",
          r["tier"] == "full-access" and r["tierName"] == "Full access" and unverified_reasons(r) == [RAW_MEMORY]
          and UNTRACED in full_reasons(r) and RAW_MEMORY not in full_reasons(r) and INTERNET in labels(r), r)
    p = run(["dotnet", tool, "analyze", unsafe_dll, reflection_dll])
    check("tiers: the text report lists the reasons of both tiers",
          "Full access because it:" in p.stdout and "Also unverified because it:" in p.stdout and "cannot rule that out" not in p.stdout, p.stdout)
    raw = facts(unsafe_dll)[0]["caps"].get("raw-memory", [])
    check("raw-memory: a pointer type in a referenced signature is recorded",
          any("pointer type in the signature of System.IntPtr::ToPointer" in e for e in raw), raw)
    check("raw-memory: a store through a non-managed address is recorded",
          any(e.startswith("stind.i8 through an address") for e in raw), raw)

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
    check("fail-open: an unreadable file is Full access", "Contains a file the check cannot read" in reasons(r), r)
    # ELF and Mach-O libraries are native binaries, counted once as that, not as unreadable files.
    natives = []
    for name, magic in [("libnative.so", b"\x7fELF\x02\x01\x01"), ("libnative.dylib", b"\xcf\xfa\xed\xfe\x07\x00\x00\x01")]:
        natives.append(j(name))
        with open(natives[-1], "wb") as f:
            f.write(magic + b"\0" * 64)
    r = analyze(*natives)
    check("fail-open: ELF and Mach-O files are native binaries, not unreadable files",
          full_reasons(r) == ["Ships a native program or library"] and len(r["fullAccess"][0]["evidence"]) == 2, r)
    # precompiled native code: the shared framework's own assemblies are ReadyToRun images
    if runtime_dir:
        r2r = os.path.join(runtime_dir, "System.Linq.dll")
        r = analyze(r2r)
        check("fail-open: a ReadyToRun image is Full access", any("precompiled native code" in e for e in evidence(r)), reasons(r))
    p = run(["dotnet", tool, "analyze", "--allowlist", j("missing.json"), fail_open_dll], expect=None)
    check("cli: a missing allowlist path is an error", p.returncode != 0)

    # embedded resources: one assembly per payload
    for payload, tier in EMBEDDED.items():
        out = j("fx", "embedded", payload)
        run(["dotnet", "build", os.path.join(REPO, "fixtures/embedded/embedded.csproj"), "-c", "Release", "-o", out,
             f"-p:Payload={payload}", f"-p:IntermediateOutputPath={j('obj', 'embedded', payload)}/", "--nologo", "-v", "q"])
        r = analyze(os.path.join(out, f"Embedded.{payload}.dll"))
        ok = r["tier"] == tier and (tier == "known-access" or EMBEDDED_BINARY in reasons(r))
        check(f"embedded: {payload} resource is {tier}", ok, {"tier": r["tier"], "fullAccess": r["fullAccess"]})

    # Harmony patch attributes: the stand-in 0Harmony is a trusted library with a profile
    harmony = fx("harmony-patch/stub", "0Harmony.dll")
    allow_harmony = write_json(j("allow-harmony.json"), {"libraries": {sha256(harmony): {"name": "0Harmony"}}})
    harmony_profile = j("library-profiles-harmony.json")
    run(["dotnet", tool, "profile", "--library", "--allowlist", allow_harmony, "--out", harmony_profile, harmony])
    for case, expected in HARMONY_PATCH.items():
        out = j("fx", "harmony-patch", case)
        # One build node: restoring a project with two project references in parallel worker
        # nodes can hang where the node pipes are not available (sandboxed runs).
        run(["dotnet", "build", os.path.join(REPO, "fixtures/harmony-patch/mod/harmony-patch-mod.csproj"), "-c", "Release", "-o", out,
             f"-p:Case={case}", f"-p:IntermediateOutputPath={j('obj', 'harmony-patch', case)}/", "-m:1", "--nologo", "-v", "q"])
        r = analyze(os.path.join(out, f"HarmonyPatch.{case}.dll"), allowlist=allow_harmony, libraries=harmony_profile, profile=profile)
        check(f"harmony-patch: {case}", expect(r, expected), {"tier": r["tier"], "labels": labels(r), "fullAccess": r["fullAccess"]})
    r = analyze(os.path.join(j("fx", "harmony-patch", "GameFullTarget"), "HarmonyPatch.GameFullTarget.dll"), allowlist=allow_harmony, libraries=harmony_profile)
    check("harmony-patch: without a game profile, a patched game member adds nothing", r["tier"] == "known-access", r)

    # reflection the check traces: member arrays, parameters, iterators, expression trees, bounded types
    for case, expected in REFLECTION_PRECISION.items():
        out = j("fx", "reflection-precision", case)
        run(["dotnet", "build", os.path.join(REPO, "fixtures/reflection-precision/reflection-precision.csproj"), "-c", "Release", "-o", out,
             f"-p:Case={case}", f"-p:IntermediateOutputPath={j('obj', 'reflection-precision', case)}/", "-m:1", "--nologo", "-v", "q"])
        r = analyze(os.path.join(out, f"ReflectionPrecision.{case}.dll"), allowlist=allow_harmony, libraries=harmony_profile, profile=profile)
        check(f"reflection-precision: {case}", expect(r, expected),
              {"tier": r["tier"], "labels": labels(r), "fullAccess": r["fullAccess"], "unverified": r["unverified"]})
    # The bounded reason is Unverified only: the same mod has no Full-access reason, and no unresolved reflection.
    r = analyze(os.path.join(j("fx", "reflection-precision", "BoundedGameType"), "ReflectionPrecision.BoundedGameType.dll"),
                allowlist=allow_harmony, libraries=harmony_profile, profile=profile)
    check("reflection-precision: bounded reflection is in the Unverified list only",
          BOUNDED in unverified_reasons(r) and not r["fullAccess"] and UNTRACED not in reasons(r), r)

    # game interaction: transpilers, observing patches, opening own folders, network values, named lookups, XML
    for case, expected in GAME_INTERACTION.items():
        out = j("fx", "game-interaction", case)
        run(["dotnet", "build", os.path.join(REPO, "fixtures/game-interaction/game-interaction.csproj"), "-c", "Release", "-o", out,
             f"-p:Case={case}", f"-p:IntermediateOutputPath={j('obj', 'game-interaction', case)}/", "-m:1", "--nologo", "-v", "q"])
        r = analyze(os.path.join(out, f"GameInteraction.{case}.dll"), allowlist=allow_harmony, libraries=harmony_profile, profile=profile)
        check(f"game-interaction: {case}", expect(r, expected),
              {"tier": r["tier"], "labels": labels(r), "fullAccess": r["fullAccess"], "unverified": r["unverified"]})


    # evasion fixtures: one assembly per case
    for case, expected in EVASION.items():
        out = j("fx", "evasion", case)
        run(["dotnet", "build", os.path.join(REPO, "fixtures/evasion/evasion.csproj"), "-c", "Release", "-o", out,
             f"-p:Case={case}", f"-p:IntermediateOutputPath={j('obj', 'evasion', case)}/", "-m:1", "--nologo", "-v", "q"])
        # The Harmony cases reference the trusted stand-in 0Harmony (see fixtures/evasion/evasion.csproj).
        r = analyze(os.path.join(out, f"Evasion.{case}.dll"), allowlist=allow_harmony, libraries=harmony_profile)
        check(f"evasion: {case}", expect(r, expected), {"tier": r["tier"], "labels": labels(r), "fullAccess": reasons(r)})

    # extraction and manifests: darkmatter-pipeline extract
    pipeline = os.path.join(build("src/DarkMatter.Pipeline", j("pipeline")), "darkmatter-pipeline.dll")
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
          mods["SampleMod"]["tier"] == "full-access" and mods["ContentMod"]["tier"] == "content-only"
          and mods["ArchiveMod"]["tier"] == "full-access", {k: v["tier"] for k, v in mods.items()})
    nested = mods["NestedMod"]
    check("extract: an archive inside an archive is extracted and analyzed",
          any("ReflectionFixture" in (f.get("name") or "") for f in nested["files"]), nested["files"])
    check("extract: a nested archive that cannot be opened is Full access",
          "Contains an archive the check cannot open" in reasons(nested), reasons(nested))
    check("extract: a shipped script is Full access",
          mods["ScriptMod"]["tier"] == "full-access" and "Ships a script or installer" in reasons(mods["ScriptMod"]), mods["ScriptMod"])
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
    analyze(manifest=manifest)
    with open(j("result.json")) as f:
        changed = json.load(f)
    changed["mods"]["ContentMod"].update(tier="full-access", fullAccess=[{"text": "Runs native code", "evidence": []}])
    p = run(["dotnet", pipeline, "compare-results", j("result.json"), write_json(j("result-changed.json"), changed)])
    check("compare-results: lists the mod whose tier changed, with its new reasons",
          p.stdout.split("## tier changes")[-1].strip() == "ContentMod: content-only -> full-access  (new: Runs native code)", p.stdout)
    changed["mods"]["ContentMod"].update(tier="unverified", fullAccess=[], unverified=[{"text": "Calls code that was not analyzed", "evidence": []}])
    # Results from before policy 9 have no "unverified" list.
    old = json.loads(json.dumps(changed))
    for m in old["mods"].values():
        m.pop("unverified", None)
    old["mods"]["ContentMod"].update(tier="full-access", fullAccess=[{"text": "Calls code that was not analyzed", "evidence": []}])
    p = run(["dotnet", pipeline, "compare-results", write_json(j("result-old.json"), old), write_json(j("result-changed.json"), changed)])
    after = p.stdout.split("## ")[2]
    check("compare-results: counts four tiers and the reasons of both, and reads results without an unverified list",
          "  unverified     1\n" in after and "  unverified reasons:\n       1  Calls code that was not analyzed" in after
          and "  unverified     0\n" in p.stdout.split("## ")[1]
          and p.stdout.split("## tier changes")[-1].strip() == "ContentMod: full-access -> unverified", p.stdout)
    facts(fx("classification/unclassified", "ClassificationUnclassified.dll"))
    p = run(["dotnet", pipeline, "rank-unclassified", j("facts.json"), "--by", "type"])
    check("rank-unclassified: ranks the unclassified framework type", "System.AppContext" in p.stdout, p.stdout)


if __name__ == "__main__":
    sys.exit(main())
