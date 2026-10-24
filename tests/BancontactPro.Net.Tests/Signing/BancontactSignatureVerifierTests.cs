using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using BancontactPro.Signing;

namespace BancontactPro.Net.Tests.Signing;

public class BancontactSignatureVerifierTests
{
    private sealed class FakeJwksClient : IJwksClient
    {
        private readonly Dictionary<string, ECDsa> _keys = new();

        public void Add(string kid, ECDsa key) => _keys[kid] = key;

        public Task<ECDsa?> GetKeyAsync(string kid, CancellationToken cancellationToken = default) =>
            Task.FromResult(_keys.TryGetValue(kid, out var key) ? key : null);
    }

    private static JoseHeader SampleHeader(string path = "/callback") => new(
        Kid: "bancontact-kid",
        MerchantProfileId: "merchant-123",
        Issuer: "Payconiq",
        IssuedAt: new DateTimeOffset(2026, 1, 2, 3, 4, 5, 678, TimeSpan.Zero),
        RequestId: "jti-abc",
        Path: path);

    private static string BuildRawSignature(string headerJson, ReadOnlySpan<byte> body, ECDsa key)
    {
        var encodedHeader = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(headerJson));
        var signingInput = Encoding.ASCII.GetBytes($"{encodedHeader}.{Base64Url.EncodeToString(body)}");
        var signature = key.SignData(signingInput, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return $"{encodedHeader}.{Base64Url.EncodeToString(signature)}";
    }

    [Fact]
    public async Task VerifyAsync_ValidCallback_ReturnsClaims()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jwks = new FakeJwksClient();
        jwks.Add("bancontact-kid", key);
        var verifier = new BancontactSignatureVerifier(jwks);
        var body = """{"paymentId":"p1"}"""u8.ToArray();

        var signature = DetachedJwsSigner.Sign(SampleHeader(), body, key);
        var claims = await verifier.VerifyAsync(signature, body, "/callback");

        Assert.NotNull(claims);
        Assert.Equal("merchant-123", claims!.MerchantProfileId);
        Assert.Equal("Payconiq", claims.Issuer);
        Assert.Equal("jti-abc", claims.RequestId);
        Assert.Equal("/callback", claims.Path);
    }

    [Fact]
    public async Task VerifyAsync_TamperedBody_ReturnsNull()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jwks = new FakeJwksClient();
        jwks.Add("bancontact-kid", key);
        var verifier = new BancontactSignatureVerifier(jwks);

        var signature = DetachedJwsSigner.Sign(SampleHeader(), """{"amount":100}"""u8, key);
        var claims = await verifier.VerifyAsync(signature, """{"amount":999}"""u8.ToArray(), "/callback");

        Assert.Null(claims);
    }

    [Fact]
    public async Task VerifyAsync_UnknownKid_ReturnsNull()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jwks = new FakeJwksClient(); // no keys registered
        var verifier = new BancontactSignatureVerifier(jwks);

        var signature = DetachedJwsSigner.Sign(SampleHeader(), "{}"u8, key);
        var claims = await verifier.VerifyAsync(signature, "{}"u8.ToArray(), "/callback");

        Assert.Null(claims);
    }

    [Fact]
    public async Task VerifyAsync_PathMismatch_ReturnsNull()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jwks = new FakeJwksClient();
        jwks.Add("bancontact-kid", key);
        var verifier = new BancontactSignatureVerifier(jwks);

        var signature = DetachedJwsSigner.Sign(SampleHeader(path: "/callback"), "{}"u8, key);
        var claims = await verifier.VerifyAsync(signature, "{}"u8.ToArray(), "/some/other/path");

        Assert.Null(claims);
    }

    [Fact]
    public async Task VerifyAsync_UnrecognizedCritEntry_IsRejected()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jwks = new FakeJwksClient();
        jwks.Add("bancontact-kid", key);
        var verifier = new BancontactSignatureVerifier(jwks);
        var body = "{}"u8.ToArray();

        const string headerJson = """
        {
          "typ": "jose+json",
          "kid": "bancontact-kid",
          "alg": "ES256",
          "https://payconiq.com/sub": "merchant-123",
          "https://payconiq.com/iss": "Payconiq",
          "https://payconiq.com/iat": "2026-01-02T03:04:05.678Z",
          "https://payconiq.com/jti": "jti-abc",
          "https://payconiq.com/path": "/callback",
          "https://payconiq.com/evil": "injected",
          "crit": ["https://payconiq.com/sub", "https://payconiq.com/iss", "https://payconiq.com/iat", "https://payconiq.com/jti", "https://payconiq.com/path", "https://payconiq.com/evil"]
        }
        """;

        var signature = BuildRawSignature(headerJson, body, key);
        var claims = await verifier.VerifyAsync(signature, body, "/callback");

        Assert.Null(claims);
    }

    [Fact]
    public async Task VerifyAsync_MissingRequiredClaim_ReturnsNullWithoutThrowing()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jwks = new FakeJwksClient();
        jwks.Add("bancontact-kid", key);
        var verifier = new BancontactSignatureVerifier(jwks);
        var body = "{}"u8.ToArray();

        const string headerJson = """
        {
          "typ": "jose+json",
          "kid": "bancontact-kid",
          "alg": "ES256",
          "https://payconiq.com/iss": "Payconiq",
          "https://payconiq.com/iat": "2026-01-02T03:04:05.678Z",
          "https://payconiq.com/jti": "jti-abc",
          "https://payconiq.com/path": "/callback",
          "crit": ["https://payconiq.com/sub", "https://payconiq.com/iss", "https://payconiq.com/iat", "https://payconiq.com/jti", "https://payconiq.com/path"]
        }
        """;

        var signature = BuildRawSignature(headerJson, body, key);
        var claims = await verifier.VerifyAsync(signature, body, "/callback");

        Assert.Null(claims);
    }

    [Fact]
    public async Task VerifyAsync_EmptyPayloadSegment_IsAccepted()
    {
        // Bancontact's callback guide, and its real callbacks, write the detached JWS as header..signature.
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jwks = new FakeJwksClient();
        jwks.Add("bancontact-kid", key);
        var verifier = new BancontactSignatureVerifier(jwks);
        var body = """{"paymentId":"p1"}"""u8.ToArray();

        var singleDot = DetachedJwsSigner.Sign(SampleHeader(), body, key);
        var doubleDot = singleDot.Replace(".", "..");
        var claims = await verifier.VerifyAsync(doubleDot, body, "/callback");

        Assert.NotNull(claims);
        Assert.Equal("jti-abc", claims!.RequestId);
    }

    [Theory]
    [InlineData("header.signature", true, "header", "signature")]
    [InlineData("header..signature", true, "header", "signature")]
    [InlineData("header...signature", false, "", "")]
    [InlineData("header.payload.signature", false, "", "")]
    [InlineData("header", false, "", "")]
    public void TrySplit_AcceptsOneOrTwoDots_AndNothingElse(string value, bool expected, string header, string signature)
    {
        var ok = DetachedJwsSigner.TrySplit(value, out var encodedHeader, out var encodedSignature);

        Assert.Equal(expected, ok);
        Assert.Equal(header, encodedHeader);
        Assert.Equal(signature, encodedSignature);
    }
    [Theory]
    [InlineData("https://shop.example/callback", "/callback", true)]
    [InlineData("http://shop.example/callback", "/callback", true)]
    [InlineData("https://shop.example/other", "/callback", false)]
    [InlineData("ftp://shop.example/callback", "/callback", false)]
    [InlineData("/callback", "/callback", true)]
    public async Task VerifyAsync_PathClaimMayBeTheCallbackUrl(string claim, string receivedPath, bool expected)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jwks = new FakeJwksClient();
        jwks.Add("bancontact-kid", key);
        var verifier = new BancontactSignatureVerifier(jwks);

        var signature = DetachedJwsSigner.Sign(SampleHeader(path: claim), "{}"u8, key);
        var claims = await verifier.VerifyAsync(signature, "{}"u8.ToArray(), receivedPath);

        Assert.Equal(expected, claims is not null);
    }

    [Fact]
    public async Task VerifyAsync_RealPreprodCallback_Verifies()
    {
        // A callback captured from Bancontact's preprod (2026-10-24), verified with the public key from
        // https://jwks.preprod.bancontact.net/ . Header form header..signature, a path claim that is the callback URL,
        // and a signing input of header + "." + base64url(body).
        const string signature =
            "eyJjcml0IjpbImh0dHBzOi8vcGF5Y29uaXEuY29tL2lzcyIsImh0dHBzOi8vcGF5Y29uaXEuY29tL2lhdCIsImh0dHBzOi8vcGF5Y29uaXEuY29tL3N1YiIsImh0dHBzOi8vcGF5Y29uaXEuY29tL3BhdGgiLCJodHRwczovL3BheWNvbmlxLmNvbS9qdGkiXSwiaHR0cHM6Ly9wYXljb25pcS5jb20vaXNzIjoiUGF5Y29uaXEiLCJraWQiOiJjMzBmNDE0ZC04NTVmLTQ3OTEtOTc1ZC1mNmQ5ZjNkMjNlNDIiLCJodHRwczovL3BheWNvbmlxLmNvbS9pYXQiOiIyMDI2LTEwLTI0VDIyOjI1OjIzLjE4NVoiLCJ0eXAiOiJKT1NFK0pTT04iLCJodHRwczovL3BheWNvbmlxLmNvbS9zdWIiOiI3eGt5ZGpiYzluZ2dzeWtjZzVzaDBhYnMiLCJodHRwczovL3BheWNvbmlxLmNvbS9wYXRoIjoiaHR0cHM6Ly9iYW5jb250YWN0LXByZXByb2Qub3MtbGFuLmJlL2JhbmNvbnRhY3QvY2FsbGJhY2siLCJodHRwczovL3BheWNvbmlxLmNvbS9qdGkiOiI4MTM4OWVhNS1lZDRlLTQyZTMtODkwYy0xNjExMjkyZWNiOTYiLCJhbGciOiJFUzI1NiJ9..rqZVQYddn67bBOG7iej3jAYwMpT-6R3mI_Ar7npJwHfYLd8iGmKw62on21guVo9XGveBJBd8ApVGPTcZSr78Hg";
        const string body =
            """{"paymentId":"tx668ldrz9fgg4ararakc62r","currency":"EUR","amount":100,"createdAt":"2026-10-24T22:08:10.040086Z","status":"SUCCEEDED","debtor":{"iban":"************7034","name":"Axel Dewaele"},"description":"sample payment","expireAt":"2026-10-24T22:10:10.040086Z","succeededAt":"2026-10-24T22:08:28.514776Z"}""";

        using var key = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = Base64Url.DecodeFromChars("QXagknFz-0HTQGL-jISbuOdPFP4561SmbmHm2y14HEg"),
                Y = Base64Url.DecodeFromChars("0XJYHdztagEf-qFj1_lnE1HAqp5LkMDskW4hbhnKiII"),
            },
        });
        var jwks = new FakeJwksClient();
        jwks.Add("c30f414d-855f-4791-975d-f6d9f3d23e42", key);
        var verifier = new BancontactSignatureVerifier(jwks);

        var claims = await verifier.VerifyAsync(signature, Encoding.UTF8.GetBytes(body), "/bancontact/callback");

        Assert.NotNull(claims);
        Assert.Equal("Payconiq", claims!.Issuer);
        Assert.Equal("7xkydjbc9nggsykcg5sh0abs", claims.MerchantProfileId);
        Assert.Equal("81389ea5-ed4e-42e3-890c-1611292ecb96", claims.RequestId);
    }
    [Theory]
    [InlineData("not-a-valid-signature-value")]
    [InlineData("one.two.three")]
    public async Task VerifyAsync_MalformedSignatureValue_ReturnsNull(string malformed)
    {
        var jwks = new FakeJwksClient();
        var verifier = new BancontactSignatureVerifier(jwks);

        var claims = await verifier.VerifyAsync(malformed, "{}"u8.ToArray(), "/callback");

        Assert.Null(claims);
    }
}
