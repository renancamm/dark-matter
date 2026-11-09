// SPDX-License-Identifier: MIT
// Control: a private helper takes the field to read as a parameter; every call passes a field
// looked up by a constant name. Expected: Limited access.
using System.Reflection;

public class Physics {
    public float speed = 1, drag = 2;
}

public static class Tuning {
    static float Read(FieldInfo field, object target) => (float)field.GetValue(target)!;

    public static float Speed(Physics physics) => Read(typeof(Physics).GetField("speed")!, physics);
    public static float Drag(Physics physics) => Read(typeof(Physics).GetField("drag")!, physics);
}
