using System;

namespace Layer2Discovery;

public static class Utils
{
    internal static int ProcessByteArrayToInt(byte[] bytes)
    {
        if (BitConverter.IsLittleEndian) { Array.Reverse(bytes); }
        return bytes.Length switch
        {
            1 => bytes[0], // Directly return the single byte as an int
            2 => BitConverter.ToInt16(bytes, 0),
            4 => BitConverter.ToInt32(bytes, 0),
            _ => throw new ArgumentException($"Unsupported byte array of length {bytes.Length}") //throw new ArgumentException("Byte array must contain 1, 2, or 4 bytes.", nameof(bytes))
        };
    }

}
