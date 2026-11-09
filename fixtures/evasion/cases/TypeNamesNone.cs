// SPDX-License-Identifier: MIT
// Control: Newtonsoft.Json with TypeNameHandling.None. Expected: Limited access.
namespace Newtonsoft.Json {
    public enum TypeNameHandling { None, Objects, Arrays, All, Auto }
    public class JsonSerializerSettings { public TypeNameHandling TypeNameHandling { get; set; } }
}

public class TypeNamesNoneCase {
    public static object Run() => new Newtonsoft.Json.JsonSerializerSettings { TypeNameHandling = Newtonsoft.Json.TypeNameHandling.None };
}
