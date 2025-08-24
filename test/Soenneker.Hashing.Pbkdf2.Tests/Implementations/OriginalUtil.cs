using System;
using System.Security.Cryptography;
using Soenneker.Extensions.Arrays.Bytes;
using Soenneker.Extensions.String;

namespace Soenneker.Hashing.Pbkdf2.Tests.Implementations;

/// <summary>
/// Utility for PBKDF2-SHA256 password hashing and verification.
/// Produces PHC-like records: pbkdf2_sha256$<iterations>$<saltB64>$<hashB64>
/// </summary>
public static class OriginalUtil
{
    /// <summary>Default salt size in bytes.</summary>
    private const int _defaultSaltBytes = 16;

    /// <summary>Default output hash size in bytes.</summary>
    private const int _defaultHashBytes = 32;

    /// <summary>Default iteration count (tuned for ~20–40ms on typical CPUs).</summary>
    private const int _defaultIterations = 300_000;

    /// <summary>
    /// Hashes a password/secret into a PHC-style PBKDF2 record.
    /// </summary>
    /// <param name="secret">Secret to hash (must not be null or whitespace).</param>
    /// <param name="iterations">Iteration count (default: 300k).</param>
    /// <param name="saltBytes">Salt size in bytes (default: 16).</param>
    /// <param name="hashBytes">Hash size in bytes (default: 32).</param>
    /// <returns>A record string like pbkdf2_sha256$300000$saltB64$hashB64.</returns>
    public static string Hash(string secret, int iterations = _defaultIterations, int saltBytes = _defaultSaltBytes, int hashBytes = _defaultHashBytes)
    {
        secret.ThrowIfNullOrWhiteSpace();

        byte[] salt = RandomNumberGenerator.GetBytes(saltBytes);
        byte[] pwdBytes = secret.ToBytes();
        var hash = new byte[hashBytes];

        try
        {
            using var kdf = new Rfc2898DeriveBytes(pwdBytes, salt, iterations, HashAlgorithmName.SHA256);
            byte[] derived = kdf.GetBytes(hashBytes);
            Buffer.BlockCopy(derived, 0, hash, 0, hashBytes);

            string saltB64 = salt.ToBase64String();
            string hashB64 = hash.ToBase64String();

            return $"pbkdf2_sha256${iterations}${saltB64}${hashB64}";
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pwdBytes);
            CryptographicOperations.ZeroMemory(hash);
        }
    }

    /// <summary>
    /// Verifies a secret against a PBKDF2 record string.
    /// </summary>
    /// <param name="secret">Secret to verify.</param>
    /// <param name="phc">Record string from Hash.</param>
    /// <returns>True if secret matches the record; otherwise false.</returns>
    public static bool Verify(string secret, string phc)
    {
        secret.ThrowIfNullOrWhiteSpace();
        phc.ThrowIfNullOrWhiteSpace();

        string[] parts = phc.Split('$', StringSplitOptions.RemoveEmptyEntries);

        if (parts.Length != 4 || !parts[0].Equals("pbkdf2_sha256", StringComparison.Ordinal))
            return false;

        if (!int.TryParse(parts[1], out int iterations) || iterations <= 0)
            return false;

        byte[] salt, expected;
        try
        {
            salt = parts[2].ToBytesFromBase64();
            expected = parts[3].ToBytesFromBase64();
        }
        catch
        {
            return false;
        }

        byte[] pwdBytes = secret.ToBytes();
        var derived = new byte[expected.Length];

        try
        {
            using var kdf = new Rfc2898DeriveBytes(pwdBytes, salt, iterations, HashAlgorithmName.SHA256);
            byte[] check = kdf.GetBytes(expected.Length);
            Buffer.BlockCopy(check, 0, derived, 0, expected.Length);

            return CryptographicOperations.FixedTimeEquals(expected, derived);
        }
        catch
        {
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pwdBytes);
            CryptographicOperations.ZeroMemory(derived);
            CryptographicOperations.ZeroMemory(expected);
        }
    }
}