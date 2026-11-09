// SPDX-License-Identifier: MIT
// Stand-in for a game assembly: a public API method that writes to the save folder, a wrapper
// that starts whatever its caller names (Full access for the mod that calls it), a math type
// that reads its own memory (exempt by the policy's "KSA." entry), a browser opener (exempt
// as "opens websites" by the policy), types mods use through reflection (one member of UiText
// uses the clipboard; a nested type of Tools starts programs), and an XML helper.
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace KSA {
    // An inline array of the game's (C5): a mod indexing or spanning it uses the compiler's inline-array
    // helpers over a game type, whose length and element the game-API map records.
    [InlineArray(7)]
    public struct Slots7 { int _element; }

    public static class GameSaves {
        public static string SaveFolderPath => "saves";
        public static void MakeSave() => System.IO.File.WriteAllText(System.IO.Path.Combine(SaveFolderPath, "save.dat"), "");
    }

    public static class Links {
        public static void Open(string target) => Process.Start(target);
    }

    public static class UpdateAvailablePopup {
        public static void OpenBrowser(string url) => Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
    }

    // Options a mod reads by reflection: one setter saves the game.
    public class VesselOptions {
        public int Throttle { get; set; }
        public bool AutoSave { get => true; set { if (value) GameSaves.MakeSave(); } }
    }

    // A game object with a private field a mod reads, and a method a mod patches.
    public class Vehicle {
        float mass = 1;
        public float Mass => mass;
        public void Update() { }
    }

    // A UI type a mod reaches by reflection: one member copies to the clipboard, the other draws text.
    public static class UiText {
        public static void Draw(string text) { }
        public static void CopyName(string text) => Native.SetClipboardText(text);
    }

    public static class Native {
        public static void SetClipboardText(string text) { }
    }

    // A game type with a nested helper that starts what it is given (reached by reflection through
    // the outer type's GetMember and GetMembers).
    public static class Tools {
        public static void Hello() { }
        public static class Shell {
            public static void Run(string file) => Process.Start(file);
        }
    }

    // The settings popup that restarts the game: the policy exempts every nested type of it
    // ("KSA.RequiresRestartPopup/") from process-start, the game restarting itself.
    public static class RequiresRestartPopup {
        public static void Show() { }
        public static class Restarter {
            public static void Now() => Process.Start("example.invalid");
        }
    }

    // The game's own XML helper, for a type its caller chooses (and one for a game type).
    public static class XmlStore {
        public static T Load<T>(string name) {
            using var r = System.IO.File.OpenRead(System.IO.Path.Combine(GameSaves.SaveFolderPath, name));
            return (T)new System.Xml.Serialization.XmlSerializer(typeof(T)).Deserialize(r)!;
        }
        public static object LoadAs(System.Type type, string name) {
            using var r = System.IO.File.OpenRead(System.IO.Path.Combine(GameSaves.SaveFolderPath, name));
            return new System.Xml.Serialization.XmlSerializer(type).Deserialize(r)!;
        }
    }

    // What the game-API map cannot have read (H5). The harness patches a copy of this assembly: the
    // marker constant's ldc.i4 in Unreadable.Run becomes an undefined opcode (a body the check cannot
    // decode), and RemovedInThisBuild is renamed (a member the build a mod was compiled against had).
    public static class Unreadable {
        public static int Run(int x) => x + 0x5EADBEEF;
        public static int Caller(int x) => Run(x) + 1;
    }

    public static class Vanishing {
        public static void RemovedInThisBuild() { }
        public static void Kept() { }
    }

    // Members inherited from a base type (H5 review): a game base type's that starts what it is given,
    // and a game type deriving from a framework type. The harness renames a mod's references to the
    // derived types' own members in a copy of the mod (a mod built against a build where the derived
    // type declared them: the runtime looks a member reference up through the base types).
    public class StartsBase {
        public static void InheritedRun(string file) => Process.Start(file);
    }

    public class StartsDerived : StartsBase {
        public static void DeclaredHere(string file) { }
    }

    // A game type with a nested type that inherits the program-starting method (H7b review): a lookup on a
    // nested type found from NestedStarts finds what the nested type inherits.
    public static class NestedStarts {
        public class Starter : StartsBase { }
    }

    public class ListDerived : System.Collections.Generic.List<int> {
        public void OwnTrimmer() { }
        public void OwnMissing() { }
    }

    // Indexers a mod finds by reflection (H7 review): one renamed with [IndexerName], whose accessors are
    // get_Program and set_Program, not get_Item, and whose getter starts what it is given; a conventional
    // one that only reads, next to a method that starts a program (which an indexer lookup does not reach).
    public class Launcher {
        [IndexerName("Program")]
        public int this[string file] { get { Process.Start(file); return 0; } }
    }

    // A game type whose constructor starts a program (H9 review): created by name (Assembly.CreateInstance,
    // Activator.CreateInstance(assembly, type)), that constructor runs.
    public class StartsOnCreate {
        public StartsOnCreate() => Process.Start("example.invalid");
    }

    public class Slots {
        public int this[int i] => i;
        public static void Reset() => Process.Start("example.invalid");
    }

    public struct Vec3 {
        public float X, Y, Z;
        public float First() => Unsafe.As<Vec3, float>(ref this);
    }

    // Typed reflection (D, policy 35): a game object graph a mod reads by reflection. Universe's members are
    // declared as game types (a field, a property, a method's return), as object, and twice under one name in
    // two casings; Craft has a game subclass with a member of its own, IPayload a game implementer; Terminal
    // starts what it is given; Hiding hides a base field with one of another type.
    public class Universe {
        public static Universe Instance = new();
        public Craft Current = new();
        public Craft Focus => Current;
        public Craft Find(string name) => Current;
        public object Anything = new();
        public Terminal Console = new();
        public IPayload Payload = new Satellite();
        public Terminal item = new();
        public Craft Item = new();
    }

    public class Craft {
        public void Rename(string name) => Native.SetClipboardText(name);
        public void Update() { }
    }

    public class Rover : Craft {
        public void Launch(string file) => Process.Start(file);
    }

    public interface IPayload { void Deploy(); }

    public class Satellite : IPayload {
        public void Deploy() => GameSaves.MakeSave();
    }

    public class Terminal {
        public void Print(string text) { }
        public void Run(string file) => Process.Start(file);
    }

    public class HiddenBase { public Craft Slot = new(); }
    public class Hiding : HiddenBase { public new Terminal Slot = new(); }
}
