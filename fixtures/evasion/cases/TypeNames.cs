// SPDX-License-Identifier: MIT
// Newtonsoft.Json with type names read from the input. Expected: Broad access.
// The Newtonsoft types are stubs; the check matches them by name.
namespace Newtonsoft.Json {
    public enum TypeNameHandling { None, Objects, Arrays, All, Auto }
    public class JsonSerializerSettings { public TypeNameHandling TypeNameHandling { get; set; } }
}

public class TypeNamesCase {
    public static object Run() => new Newtonsoft.Json.JsonSerializerSettings { TypeNameHandling = Newtonsoft.Json.TypeNameHandling.Auto };
}
