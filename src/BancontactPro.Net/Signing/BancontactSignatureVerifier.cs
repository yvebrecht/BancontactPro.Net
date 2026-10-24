using System.Buffers.Text;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace BancontactPro.Signing;

/// <summary>
/// Verifies a detached JWS Bancontact attaches to inbound callbacks, resolving the signing key
/// from a JWKS (<see cref="IJwksClient"/>) rather than a locally-held private key.
/// </summary>
public sealed class BancontactSignatureVerifier
{
    private static readonly HashSet<string> ExpectedCrit =
    [
        "https://payconiq.com/sub",
        "https://payconiq.com/iss",
        "https://payconiq.com/iat",
        "https://payconiq.com/jti",
        "https://payconiq.com/path",
    ];

    private readonly IJwksClient _jwksClient;

    /// <param name="jwksClient">Resolves Bancontact's public keys by <c>kid</c>.</param>
    public BancontactSignatureVerifier(IJwksClient jwksClient)
    {
        _jwksClient = jwksClient;
    }

    /// <summary>
    /// Verifies <paramref name="signatureHeader"/> (the raw <c>Signature</c> header value) against
    /// <paramref name="body"/> and <paramref name="path"/> (the path the endpoint actually
    /// received the callback on). Returns the parsed claims on success, or <c>null</c> if the
    /// value is malformed, the signature doesn't validate, the signing key can't be resolved, an
    /// unrecognized critical extension is present, or the signed <c>path</c> claim doesn't match
    /// <paramref name="path"/>.
    /// </summary>
    public async Task<JoseHeader?> VerifyAsync(string signatureHeader, ReadOnlyMemory<byte> body, string path, CancellationToken cancellationToken = default)
    {
        if (!DetachedJwsSigner.TrySplit(signatureHeader, out var encodedHeader, out var encodedSignature))
        {
            return null;
        }

        JoseHeaderJson headerJson;
        try
        {
            var headerBytes = Base64Url.DecodeFromChars(encodedHeader);
            headerJson = JsonSerializer.Deserialize<JoseHeaderJson>(headerBytes)
                ?? throw new JsonException("JOSE header deserialized to null.");
        }
        catch (Exception ex) when (ex is JsonException or FormatException)
        {
            return null;
        }

        if (headerJson.Crit.Length != ExpectedCrit.Count || !headerJson.Crit.All(ExpectedCrit.Contains))
        {
            return null;
        }

        if (!SignedPathMatches(headerJson.Path, path))
        {
            return null;
        }

        byte[] signature;
        try
        {
            signature = Base64Url.DecodeFromChars(encodedSignature);
        }
        catch (FormatException)
        {
            return null;
        }

        var publicKey = await _jwksClient.GetKeyAsync(headerJson.Kid, cancellationToken).ConfigureAwait(false);
        if (publicKey is null)
        {
            return null;
        }

        var signingInput = DetachedJwsSigner.ComputeSigningInput(encodedHeader, body.Span);
        if (!publicKey.VerifyData(signingInput, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
        {
            return null;
        }

        if (!DateTimeOffset.TryParseExact(headerJson.Iat, "yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var issuedAt))
        {
            return null;
        }

        return new JoseHeader(
            Kid: headerJson.Kid,
            MerchantProfileId: headerJson.Sub,
            Issuer: headerJson.Iss,
            IssuedAt: issuedAt,
            RequestId: headerJson.Jti,
            Path: headerJson.Path);
    }

    /// <summary>
    /// Whether the signed <c>path</c> claim names the endpoint that received the callback. The docs call the claim a
    /// path, but Bancontact signs the callback URL the merchant registered (observed on a real preprod callback:
    /// <c>https://host/bancontact/callback</c>), so a claim that is an absolute http(s) URL matches when its path
    /// equals the received path. A plain path is compared as it is. The host is not compared: the application behind a
    /// proxy cannot rely on the host it sees, and the path is what stops a callback for one endpoint being replayed
    /// to another.
    /// </summary>
    private static bool SignedPathMatches(string claim, string path) =>
        claim == path
        || (Uri.TryCreate(claim, UriKind.Absolute, out var uri)
            && (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp)
            && uri.AbsolutePath == path);
}
