using Soenneker.Extensions.String;
using System;
using System.Buffers;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace Soenneker.Hashing.Pbkdf2;

public static class Pbkdf2HashingUtil
{
    private const string _prefix = "pbkdf2_sha256$";
    private const int _defaultSaltBytes = 16;
    private const int _defaultHashBytes = 32;
    private const int _defaultIterations = 300_000;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int Base64DecodedMaxLen(int charLen) => charLen / 4 * 3;

    /// <summary>Hashes a password/secret into a PHC-style PBKDF2 record.</summary>
    public static string Hash(string secret, int iterations = _defaultIterations, int saltBytes = _defaultSaltBytes, int hashBytes = _defaultHashBytes)
    {
        secret.ThrowIfNullOrWhiteSpace();

        if (iterations <= 0) 
            throw new ArgumentOutOfRangeException(nameof(iterations));

        if (saltBytes <= 0) 
            throw new ArgumentOutOfRangeException(nameof(saltBytes));

        if (hashBytes <= 0) 
            throw new ArgumentOutOfRangeException(nameof(hashBytes));

        // Salt
        byte[]? saltArr = null;
        Span<byte> salt = saltBytes <= 64 ? stackalloc byte[saltBytes] : (saltArr = ArrayPool<byte>.Shared.Rent(saltBytes)).AsSpan(0, saltBytes);
        RandomNumberGenerator.Fill(salt);

        // Password bytes (pooled)
        int pwdCount = Encoding.UTF8.GetByteCount(secret);
        byte[] pwdArr = ArrayPool<byte>.Shared.Rent(pwdCount);
        Span<byte> pwd = pwdArr.AsSpan(0, pwdCount);
        _ = Encoding.UTF8.GetBytes(secret, pwd);

        // Derived hash
        byte[]? hashArr = null;
        Span<byte> hash = hashBytes <= 64 ? stackalloc byte[hashBytes] : (hashArr = ArrayPool<byte>.Shared.Rent(hashBytes)).AsSpan(0, hashBytes);

        try
        {
            Rfc2898DeriveBytes.Pbkdf2(pwd, salt, hash, iterations, HashAlgorithmName.SHA256);

            string saltB64 = Convert.ToBase64String(salt);
            string hashB64 = Convert.ToBase64String(hash);

            // Single final string allocation
            return string.Concat(_prefix, iterations.ToString(CultureInfo.InvariantCulture), "$", saltB64, "$", hashB64);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pwd);
            ArrayPool<byte>.Shared.Return(pwdArr, clearArray: true);

            CryptographicOperations.ZeroMemory(hash);

            if (hashArr is not null) 
                ArrayPool<byte>.Shared.Return(hashArr, clearArray: true);

            // Salt isn't secret, but clear when returning pooled arrays
            if (saltArr is not null) 
                ArrayPool<byte>.Shared.Return(saltArr, clearArray: true);
        }
    }

    /// <summary>Verifies a secret against a PBKDF2 record string.</summary>
    public static bool Verify(string secret, string phc)
    {
        if (secret.IsNullOrWhiteSpace() || phc.IsNullOrWhiteSpace())
            return false;

        ReadOnlySpan<char> span = phc.AsSpan();

        if (!span.StartsWith(_prefix.AsSpan(), StringComparison.Ordinal))
            return false;

        span = span.Slice(_prefix.Length); // iterations$saltB64$hashB64

        int i1 = span.IndexOf('$');
        if (i1 < 0)
            return false;

        ReadOnlySpan<char> iterSpan = span.Slice(0, i1);
        span = span.Slice(i1 + 1);

        int i2 = span.IndexOf('$');
        if (i2 < 0) return false;
        ReadOnlySpan<char> saltB64 = span.Slice(0, i2);
        ReadOnlySpan<char> hashB64 = span.Slice(i2 + 1);

        if (!int.TryParse(iterSpan, NumberStyles.None, CultureInfo.InvariantCulture, out int iterations) || iterations <= 0)
            return false;

        // Decode Base64 directly to bytes
        int saltMax = Base64DecodedMaxLen(saltB64.Length);
        int hashMax = Base64DecodedMaxLen(hashB64.Length);

        byte[]? saltArr = saltMax <= 64 ? null : ArrayPool<byte>.Shared.Rent(saltMax);
        Span<byte> salt = saltArr is null ? stackalloc byte[saltMax] : saltArr.AsSpan(0, saltMax);

        if (!Convert.TryFromBase64Chars(saltB64, salt, out int saltLen))
        {
            if (saltArr is not null) 
                ArrayPool<byte>.Shared.Return(saltArr, clearArray: true);

            return false;
        }

        salt = salt.Slice(0, saltLen);

        byte[]? expectedArr = hashMax <= 64 ? null : ArrayPool<byte>.Shared.Rent(hashMax);
        Span<byte> expected = expectedArr is null ? stackalloc byte[hashMax] : expectedArr.AsSpan(0, hashMax);

        if (!Convert.TryFromBase64Chars(hashB64, expected, out int expectedLen))
        {
            if (expectedArr is not null) ArrayPool<byte>.Shared.Return(expectedArr, clearArray: true);
            CryptographicOperations.ZeroMemory(salt);
            if (saltArr is not null) ArrayPool<byte>.Shared.Return(saltArr, clearArray: true);
            return false;
        }

        expected = expected.Slice(0, expectedLen);

        // Password bytes (pooled)
        int pwdCount = Encoding.UTF8.GetByteCount(secret);
        byte[] pwdArr = ArrayPool<byte>.Shared.Rent(pwdCount);
        Span<byte> pwd = pwdArr.AsSpan(0, pwdCount);
        _ = Encoding.UTF8.GetBytes(secret, pwd);

        // Derive into a buffer sized to expected hash
        byte[]? derivedArr = expectedLen <= 64 ? null : ArrayPool<byte>.Shared.Rent(expectedLen);
        Span<byte> derived = derivedArr is null ? stackalloc byte[expectedLen] : derivedArr.AsSpan(0, expectedLen);

        try
        {
            Rfc2898DeriveBytes.Pbkdf2(pwd, salt, derived, iterations, HashAlgorithmName.SHA256);

            bool ok = derived.Length == expected.Length && CryptographicOperations.FixedTimeEquals(derived, expected);

            return ok;
        }
        catch
        {
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pwd);
            ArrayPool<byte>.Shared.Return(pwdArr, clearArray: true);

            CryptographicOperations.ZeroMemory(derived);

            if (derivedArr is not null) 
                ArrayPool<byte>.Shared.Return(derivedArr, clearArray: true);

            CryptographicOperations.ZeroMemory(expected);

            if (expectedArr is not null) 
                ArrayPool<byte>.Shared.Return(expectedArr, clearArray: true);

            CryptographicOperations.ZeroMemory(salt);

            if (saltArr is not null) 
                ArrayPool<byte>.Shared.Return(saltArr, clearArray: true);
        }
    }
}