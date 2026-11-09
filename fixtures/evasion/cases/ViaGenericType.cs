// SPDX-License-Identifier: MIT
// Probe case: typeof(T) is whatever type the caller picks. Expected: Broad access.
public class ViaGenericTypeCase {
    public static object Run<T>(string method) => typeof(T).GetMethod(method).Invoke(null, null);
}
