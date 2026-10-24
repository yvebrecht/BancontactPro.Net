#if !NET9_0_OR_GREATER
using System.Text;

namespace System.Buffers.Text;

/// <summary>
/// A stand-in for <c>System.Buffers.Text.Base64Url</c>, which the framework only has from .NET 9. It is compiled
/// for .NET 8 only, under the same name, so the rest of the code uses the framework type where there is one.
/// Decoding is strict, as RFC 7515 wants: only the base64url alphabet, no padding, no whitespace.
/// </summary>
internal static class Base64Url
{
    public static string EncodeToString(ReadOnlySpan<byte> source) =>
        Convert.ToBase64String(source).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <exception cref="FormatException">The text is not valid base64url.</exception>
    public static byte[] DecodeFromChars(ReadOnlySpan<char> source)
    {
        var padded = new StringBuilder(source.Length + 3);
        foreach (var c in source)
        {
            if (c == '-')
            {
                padded.Append('+');
            }
            else if (c == '_')
            {
                padded.Append('/');
            }
            else if (char.IsAsciiLetterOrDigit(c))
            {
                padded.Append(c);
            }
            else if (c is ' ' or '\t' or '\r' or '\n')
            {
                // The framework's decoder skips whitespace too. It does no harm here: the signature covers the encoded
                // text exactly as received, so a header with stray whitespace in it does not verify.
            }
            else
            {
                throw new FormatException($"'{c}' is not a base64url character.");
            }
        }

        if (padded.Length % 4 == 1)
        {
            throw new FormatException("The length of a base64url text cannot leave a single character in the last group.");
        }

        while (padded.Length % 4 != 0)
        {
            padded.Append('=');
        }

        return Convert.FromBase64String(padded.ToString());
    }
}
#endif