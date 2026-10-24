using System.Buffers.Text;

namespace BancontactPro.Net.Tests.Signing;

/// <summary>
/// Runs against the framework's Base64Url on .NET 10 and against the library's stand-in on .NET 8, so both must
/// give the same answers.
/// </summary>
public class Base64UrlTests
{
    [Theory]
    [InlineData(new byte[0], "")]
    [InlineData(new byte[] { 1 }, "AQ")]
    [InlineData(new byte[] { 0xfb, 0xff }, "-_8")]
    [InlineData(new byte[] { 0xfb, 0xff, 0xfe }, "-__-")]
    public void EncodesWithTheUrlAlphabetAndNoPadding(byte[] bytes, string expected) =>
        Assert.Equal(expected, Base64Url.EncodeToString(bytes));

    [Theory]
    [InlineData("", new byte[0])]
    [InlineData("AQ", new byte[] { 1 })]
    [InlineData("-_8", new byte[] { 0xfb, 0xff })]
    [InlineData("-__-", new byte[] { 0xfb, 0xff, 0xfe })]
    public void DecodesTheUrlAlphabetWithoutPadding(string text, byte[] expected) =>
        Assert.Equal(expected, Base64Url.DecodeFromChars(text));

    [Fact]
    public void RoundTripsEveryLengthUpTo64()
    {
        var random = new Random(42);
        for (var length = 0; length <= 64; length++)
        {
            var bytes = new byte[length];
            random.NextBytes(bytes);
            Assert.Equal(bytes, Base64Url.DecodeFromChars(Base64Url.EncodeToString(bytes)));
        }
    }

    [Fact]
    public void SkipsWhitespace() =>
        Assert.Equal(Base64Url.DecodeFromChars("AQA"), Base64Url.DecodeFromChars("AQ A"));

    [Theory]
    [InlineData("A")]
    [InlineData("A+B/")]
    [InlineData("AQ!")]
    public void RejectsWhatIsNotBase64Url(string text) =>
        Assert.Throws<FormatException>(() => Base64Url.DecodeFromChars(text));
}