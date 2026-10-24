using System.Buffers.Text;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace BancontactPro.Signing;

/// <summary>
/// Computes Bancontact Pro's detached JWS request signature (RFC 7797, ES256).
/// </summary>
/// <remarks>
/// Per docs/research-notes.md, the signature value is <c>base64url(header) + "." + signature</c>,
/// where <c>signature = ES256(base64url(header) + "." + base64url(body))</c> — a genuinely
/// two-segment value, not the usual three-part compact JWS with an empty payload segment. That is what this
/// class writes. Bancontact itself writes callbacks as <c>header..signature</c> (the empty payload segment), as its
/// callback guide documents, so <see cref="TrySplit"/> accepts both forms when verifying. Which form Bancontact
/// accepts on requests is still to be confirmed (see the open spec-discrepancy issues).
/// </remarks>
public static class DetachedJwsSigner
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        // The header carries literal URI-shaped claim names (e.g. "https://payconiq.com/sub");
        // they must round-trip byte-for-byte, not get escaped.
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    /// <summary>
    /// Builds the JOSE header and signs <paramref name="body"/> with <paramref name="privateKey"/>,
    /// returning the two-segment <c>base64url(header).base64url(signature)</c> value for the
    /// <c>Signature</c> header.
    /// </summary>
    /// <param name="header">The claims to embed in the JOSE header.</param>
    /// <param name="body">
    /// The exact request (or response) bytes being signed. Empty for bodyless requests
    /// (GET/DELETE) — never omit this parameter in that case, pass an empty span instead.
    /// </param>
    /// <param name="privateKey">An ES256 (P-256) private key.</param>
    public static string Sign(JoseHeader header, ReadOnlySpan<byte> body, ECDsa privateKey)
    {
        var headerJson = new JoseHeaderJson
        {
            Kid = header.Kid,
            Sub = header.MerchantProfileId,
            Iss = header.Issuer,
            Iat = header.IssuedAt.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture),
            Jti = header.RequestId,
            Path = header.Path,
        };

        var headerBytes = JsonSerializer.SerializeToUtf8Bytes(headerJson, JsonOptions);
        var encodedHeader = Base64Url.EncodeToString(headerBytes);

        var signingInput = ComputeSigningInput(encodedHeader, body);
        var signature = privateKey.SignData(signingInput, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        return $"{encodedHeader}.{Base64Url.EncodeToString(signature)}";
    }

    /// <summary>
    /// Verifies a value produced by <see cref="Sign"/> against the signer's public key. Exposed
    /// primarily for testing the signer itself; verifying inbound Bancontact-signed callbacks is
    /// a separate concern (different key, different header claim expectations, additional
    /// structural validation) — see <c>BancontactCallbackVerifier</c>.
    /// </summary>
    public static bool Verify(string detachedJws, ReadOnlySpan<byte> body, ECDsa publicKey)
    {
        if (!TrySplit(detachedJws, out var encodedHeader, out var encodedSignature))
        {
            return false;
        }

        byte[] signature;
        try
        {
            signature = Base64Url.DecodeFromChars(encodedSignature);
        }
        catch (FormatException)
        {
            return false;
        }

        var signingInput = ComputeSigningInput(encodedHeader, body);
        return publicKey.VerifyData(signingInput, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    /// <summary>
    /// Splits a detached JWS into its header/signature segments. Accepts both <c>header.signature</c> and
    /// <c>header..signature</c> (RFC 7797 compact form with an empty payload segment). Bancontact sends the
    /// second form on callbacks, as its callback guide documents, so verifying must accept it; anything else,
    /// including a non-empty middle segment, is rejected.
    /// </summary>
    internal static bool TrySplit(string detachedJws, out string encodedHeader, out string encodedSignature)
    {
        var parts = detachedJws.Split('.');
        if (parts.Length == 2 || (parts.Length == 3 && parts[1].Length == 0))
        {
            encodedHeader = parts[0];
            encodedSignature = parts[^1];
            return true;
        }

        encodedHeader = "";
        encodedSignature = "";
        return false;
    }

    internal static byte[] ComputeSigningInput(string encodedHeader, ReadOnlySpan<byte> body) =>
        Encoding.ASCII.GetBytes($"{encodedHeader}.{Base64Url.EncodeToString(body)}");
}
