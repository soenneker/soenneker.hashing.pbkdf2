using AwesomeAssertions;
using Soenneker.Tests.FixturedUnit;
using System;
using Xunit;

namespace Soenneker.Hashing.Pbkdf2.Tests;

[Collection("Collection")]
public sealed class Pbkdf2HashingUtilTests : FixturedUnitTest
{
    public Pbkdf2HashingUtilTests(Fixture fixture, ITestOutputHelper output) : base(fixture, output)
    {
    }

    [Fact]
    public void Default()
    {
    }


    [Theory]
    [InlineData("password")]
    [InlineData("correct horse battery staple")]
    [InlineData("pässwörd")] // UTF-8 non-ASCII
    [InlineData("emoji 🚀🔥")]
    [InlineData("   leading and trailing   ")]
    public void Hash_Then_Verify_Roundtrip_Succeeds(string secret)
    {
        string phc = Pbkdf2HashingUtil.Hash(secret);

        Pbkdf2HashingUtil.Verify(secret, phc).Should().BeTrue("the same secret should verify against its own PHC record");
    }

    [Fact]
    public void Hash_ProducesDifferentSaltEachTime()
    {
        const string secret = "password";

        string phc1 = Pbkdf2HashingUtil.Hash(secret);
        string phc2 = Pbkdf2HashingUtil.Hash(secret);

        phc1.Should().NotBe(phc2, "salts should be random, making records differ");
        Pbkdf2HashingUtil.Verify(secret, phc1).Should().BeTrue();
        Pbkdf2HashingUtil.Verify(secret, phc2).Should().BeTrue();
    }

    [Fact]
    public void Verify_Fails_WithWrongSecret()
    {
        const string secret = "password";
        const string other = "passw0rd";
        string phc = Pbkdf2HashingUtil.Hash(secret);

        Pbkdf2HashingUtil.Verify(other, phc).Should().BeFalse("a different secret must not verify");
    }

    [Fact]
    public void Hash_Respects_CustomParameters_And_FormatsPHC()
    {
        const string secret = "password";
        int iterations = 123_456;
        int saltBytes = 24;
        int hashBytes = 48;

        string phc = Pbkdf2HashingUtil.Hash(secret, iterations, saltBytes, hashBytes);

        string[] parts = phc.Split('$', StringSplitOptions.RemoveEmptyEntries);
        parts.Should().HaveCount(4);
        parts[0].Should().Be("pbkdf2_sha256");
        parts[1].Should().Be(iterations.ToString());

        byte[] salt = Convert.FromBase64String(parts[2]);
        byte[] hash = Convert.FromBase64String(parts[3]);

        salt.Length.Should().Be(saltBytes);
        hash.Length.Should().Be(hashBytes);

        Pbkdf2HashingUtil.Verify(secret, phc).Should().BeTrue();
    }

    [Fact]
    public void Verify_Rejects_WrongPrefix()
    {
        string phc = Pbkdf2HashingUtil.Hash("password");
        string bad = phc.Replace("pbkdf2_sha256$", "pbkdf2_sha1$", StringComparison.Ordinal);

        Pbkdf2HashingUtil.Verify("password", bad).Should().BeFalse("records with the wrong algorithm prefix must be rejected");
    }

    [Theory]
    [InlineData("pbkdf2_sha256$")] // missing pieces
    [InlineData("pbkdf2_sha256$abc$def")] // only 3 parts
    [InlineData("pbkdf2_sha256$-3$AAAA$BBBB")] // negative iterations
    [InlineData("pbkdf2_sha256$NaN$AAAA$BBBB")] // non-numeric iterations
    public void Verify_Rejects_Malformed_Records(string phc)
    {
        Pbkdf2HashingUtil.Verify("password", phc).Should().BeFalse();
    }

    [Fact]
    public void Verify_Rejects_When_SaltBase64_IsInvalid()
    {
        string phc = Pbkdf2HashingUtil.Hash("password");
        string[] parts = phc.Split('$', StringSplitOptions.RemoveEmptyEntries);

        parts[2] = parts[2] + "*"; // corrupt salt b64
        string broken = string.Join('$', parts);

        Pbkdf2HashingUtil.Verify("password", broken).Should().BeFalse();
    }

    [Fact]
    public void Verify_Rejects_When_HashBase64_IsInvalid()
    {
        string phc = Pbkdf2HashingUtil.Hash("password");
        string[] parts = phc.Split('$', StringSplitOptions.RemoveEmptyEntries);

        parts[3] = parts[3] + "*"; // corrupt hash b64
        string broken = string.Join('$', parts);

        Pbkdf2HashingUtil.Verify("password", broken).Should().BeFalse();
    }

    [Fact]
    public void Verify_Rejects_When_Salt_Or_Hash_Truncated()
    {
        string phc = Pbkdf2HashingUtil.Hash("password");
        string[] parts = phc.Split('$', StringSplitOptions.RemoveEmptyEntries);

        // Truncate salt (force invalid base64 / length)
        parts[2] = parts[2].Length > 2 ? parts[2][..^2] : "A";
        string brokenSalt = string.Join('$', parts);

        Pbkdf2HashingUtil.Verify("password", brokenSalt).Should().BeFalse();

        // Rebuild and truncate hash instead
        phc = Pbkdf2HashingUtil.Hash("password");
        parts = phc.Split('$', StringSplitOptions.RemoveEmptyEntries);
        parts[3] = parts[3].Length > 2 ? parts[3][..^2] : "A";
        string brokenHash = string.Join('$', parts);

        Pbkdf2HashingUtil.Verify("password", brokenHash).Should().BeFalse();
    }

    [Fact]
    public void Verify_Handles_Long_Secrets()
    {
        var longSecret = new string('x', 10_000);
        string phc = Pbkdf2HashingUtil.Hash(longSecret);

        Pbkdf2HashingUtil.Verify(longSecret, phc).Should().BeTrue();
        Pbkdf2HashingUtil.Verify(longSecret + "y", phc).Should().BeFalse();
    }

    [Fact]
    public void Hash_Throws_On_NullOrWhitespace()
    {
        Action act1 = () => Pbkdf2HashingUtil.Hash(null!);
        Action act2 = () => Pbkdf2HashingUtil.Hash(string.Empty);
        Action act3 = () => Pbkdf2HashingUtil.Hash("   ");

        act1.Should().Throw<InvalidOperationException>();
        act2.Should().Throw<ArgumentException>();
        act3.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Verify_ReturnsFalse_On_NullOrWhitespace_Inputs()
    {
        string phc = Pbkdf2HashingUtil.Hash("password");

        Pbkdf2HashingUtil.Verify(null!, phc).Should().BeFalse();
        Pbkdf2HashingUtil.Verify(string.Empty, phc).Should().BeFalse();
        Pbkdf2HashingUtil.Verify("   ", phc).Should().BeFalse();

        Pbkdf2HashingUtil.Verify("password", null!).Should().BeFalse();
        Pbkdf2HashingUtil.Verify("password", string.Empty).Should().BeFalse();
        Pbkdf2HashingUtil.Verify("password", "   ").Should().BeFalse();
    }

    [Fact]
    public void DifferentIterationCounts_StillVerify()
    {
        const string secret = "password";

        string low = Pbkdf2HashingUtil.Hash(secret, iterations: 10_000);
        string high = Pbkdf2HashingUtil.Hash(secret, iterations: 600_000);

        Pbkdf2HashingUtil.Verify(secret, low).Should().BeTrue();
        Pbkdf2HashingUtil.Verify(secret, high).Should().BeTrue();
    }

    [Fact]
    public void Record_Is_Parsable_And_Sane()
    {
        string phc = Pbkdf2HashingUtil.Hash("password");
        string[] parts = phc.Split('$', StringSplitOptions.RemoveEmptyEntries);

        parts.Should().HaveCount(4);
        parts[0].Should().Be("pbkdf2_sha256");
        parts[1].Should().MatchRegex(@"^\d+$");

        byte[] salt = Convert.FromBase64String(parts[2]);
        byte[] hash = Convert.FromBase64String(parts[3]);

        salt.Length.Should().BeInRange(8, 1024);
        hash.Length.Should().BeInRange(16, 1024);
    }
}