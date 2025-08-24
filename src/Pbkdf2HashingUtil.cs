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
    private static int Base64EncodedMaxLen(int byteLen) => (byteLen + 2) / 3 * 4;

    /// <summary>
    /// Span-first hasher that writes a PHC record into <paramref name="dest"/>.
    /// Returns true on success and sets <paramref name="charsWritten"/>.
    /// </summary>
    public static bool TryHashToSpan(ReadOnlySpan<char> secret, Span<char> dest, out int charsWritten, int iterations = _defaultIterations,
        int saltBytes = _defaultSaltBytes, int hashBytes = _defaultHashBytes)
    {
        charsWritten = 0;
        if (secret.IsEmpty || iterations <= 0 || saltBytes <= 0 || hashBytes <= 0)
            return false;

        // Precompute worst-case output length to ensure dest is big enough
        int saltB64Max = Base64EncodedMaxLen(saltBytes);
        int hashB64Max = Base64EncodedMaxLen(hashBytes);
        // prefix + iterations + '$' + salt + '$' + hash
        // iterations max 9 digits for sanity (e.g., <= 999,999,999)
        int needed = _prefix.Length + 10 + 1 + saltB64Max + 1 + hashB64Max;
        if (dest.Length < needed)
            return false;

        byte[]? saltArr = null;
        byte[]? pwdArr = null;
        byte[]? hashArr = null;

        Span<byte> salt = saltBytes <= 64 ? stackalloc byte[saltBytes] : (saltArr = ArrayPool<byte>.Shared.Rent(saltBytes)).AsSpan(0, saltBytes);
        Span<byte> hash = hashBytes <= 64 ? stackalloc byte[hashBytes] : (hashArr = ArrayPool<byte>.Shared.Rent(hashBytes)).AsSpan(0, hashBytes);

        try
        {
            // Salt
            RandomNumberGenerator.Fill(salt);

            // UTF-8 secret -> pooled bytes
            int pwdCount = Encoding.UTF8.GetByteCount(secret);
            pwdArr = ArrayPool<byte>.Shared.Rent(pwdCount);
            Span<byte> pwd = pwdArr.AsSpan(0, pwdCount);
            _ = Encoding.UTF8.GetBytes(secret, pwd);

            // Derive
            Rfc2898DeriveBytes.Pbkdf2(pwd, salt, hash, iterations, HashAlgorithmName.SHA256);

            // Emit to dest: prefix
            int written = 0;
            _prefix.AsSpan().CopyTo(dest);
            written += _prefix.Length;

            // iterations
            if (!iterations.TryFormat(dest.Slice(written), out int itersChars, provider: CultureInfo.InvariantCulture))
                return false;
            written += itersChars;

            // '$'
            dest[written++] = '$';

            // salt -> Base64 chars directly into dest
            if (!Convert.TryToBase64Chars(salt, dest.Slice(written), out int saltChars))
                return false;
            written += saltChars;

            // '$'
            dest[written++] = '$';

            // hash -> Base64 chars directly into dest
            if (!Convert.TryToBase64Chars(hash, dest.Slice(written), out int hashChars))
                return false;

            written += hashChars;

            charsWritten = written;
            return true;
        }
        finally
        {
            if (pwdArr is not null)
            {
                CryptographicOperations.ZeroMemory(pwdArr);
                ArrayPool<byte>.Shared.Return(pwdArr, clearArray: true);
            }

            CryptographicOperations.ZeroMemory(hash);
            if (hashArr is not null) ArrayPool<byte>.Shared.Return(hashArr, clearArray: true);

            // Salt isn’t secret, but clear if pooled
            if (saltArr is not null)
            {
                CryptographicOperations.ZeroMemory(salt);
                ArrayPool<byte>.Shared.Return(saltArr, clearArray: true);
            }
        }
    }


    /// <summary>
    /// Convenience wrapper that allocates exactly once for the final string.
    /// </summary>
    public static string Hash(ReadOnlySpan<char> secret, int iterations = _defaultIterations, int saltBytes = _defaultSaltBytes,
        int hashBytes = _defaultHashBytes)
    {
        // Compute an upper bound and rent a char buffer
        int saltB64Max = Base64EncodedMaxLen(saltBytes);
        int hashB64Max = Base64EncodedMaxLen(hashBytes);
        int upper = _prefix.Length + 10 + 1 + saltB64Max + 1 + hashB64Max;

        char[] arr = ArrayPool<char>.Shared.Rent(upper);

        try
        {
            if (!TryHashToSpan(secret, arr, out int written, iterations, saltBytes, hashBytes))
                throw new InvalidOperationException("PBKDF2 hash failed.");

            // This string allocation is unavoidable if the API returns string.
            string s = new(arr.AsSpan(0, written));

            // Clear the buffer that held sensitive chars before returning it.
            Array.Clear(arr, 0, written);
            return s;
        }
        finally
        {
            ArrayPool<char>.Shared.Return(arr, clearArray: false); // already cleared the written prefix
        }
    }

    public static string Hash(string secret, int iterations = _defaultIterations, int saltBytes = _defaultSaltBytes, int hashBytes = _defaultHashBytes) =>
        Hash(secret.AsSpan(), iterations, saltBytes, hashBytes);

    /// <summary>
    /// Span-first verifier; avoids allocating intermediate strings and never materializes the secret as a string.
    /// </summary>
    public static bool Verify(ReadOnlySpan<char> secret, ReadOnlySpan<char> phc)
    {
        if (phc.Length < _prefix.Length || !phc.StartsWith(_prefix.AsSpan(), StringComparison.Ordinal))
            return false;

        phc = phc.Slice(_prefix.Length); // iterations$saltB64$hashB64

        int i1 = phc.IndexOf('$');
        if (i1 <= 0) return false;

        ReadOnlySpan<char> iterSpan = phc.Slice(0, i1);
        phc = phc.Slice(i1 + 1);

        int i2 = phc.IndexOf('$');
        if (i2 <= 0) return false;

        ReadOnlySpan<char> saltB64 = phc.Slice(0, i2);
        ReadOnlySpan<char> hashB64 = phc.Slice(i2 + 1);

        if (!int.TryParse(iterSpan, NumberStyles.None, CultureInfo.InvariantCulture, out int iterations) || iterations <= 0)
            return false;

        int saltMax = saltB64.Length / 4 * 3;
        int hashMax = hashB64.Length / 4 * 3;

        byte[]? saltArr = saltMax <= 64 ? null : ArrayPool<byte>.Shared.Rent(saltMax);
        Span<byte> salt = saltArr is null ? stackalloc byte[saltMax] : saltArr.AsSpan(0, saltMax);

        if (!Convert.TryFromBase64Chars(saltB64, salt, out int saltLen))
        {
            if (saltArr is not null) ArrayPool<byte>.Shared.Return(saltArr, clearArray: true);
            return false;
        }

        salt = salt.Slice(0, saltLen);

        byte[]? expectedArr = hashMax <= 64 ? null : ArrayPool<byte>.Shared.Rent(hashMax);
        Span<byte> expected = expectedArr is null ? stackalloc byte[hashMax] : expectedArr.AsSpan(0, hashMax);

        if (!Convert.TryFromBase64Chars(hashB64, expected, out int expectedLen))
        {
            if (expectedArr is not null) ArrayPool<byte>.Shared.Return(expectedArr, clearArray: true);
            if (saltArr is not null) ArrayPool<byte>.Shared.Return(saltArr, clearArray: true);
            return false;
        }

        expected = expected.Slice(0, expectedLen);

        // Secret -> UTF8 bytes (pooled)
        int pwdCount = Encoding.UTF8.GetByteCount(secret);
        byte[] pwdArr = ArrayPool<byte>.Shared.Rent(pwdCount);
        Span<byte> pwd = pwdArr.AsSpan(0, pwdCount);
        _ = Encoding.UTF8.GetBytes(secret, pwd);

        byte[]? derivedArr = expectedLen <= 64 ? null : ArrayPool<byte>.Shared.Rent(expectedLen);
        Span<byte> derived = derivedArr is null ? stackalloc byte[expectedLen] : derivedArr.AsSpan(0, expectedLen);

        try
        {
            Rfc2898DeriveBytes.Pbkdf2(pwd, salt, derived, iterations, HashAlgorithmName.SHA256);
            return derived.Length == expected.Length && CryptographicOperations.FixedTimeEquals(derived, expected);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pwd);
            ArrayPool<byte>.Shared.Return(pwdArr, clearArray: true);

            CryptographicOperations.ZeroMemory(derived);
            if (derivedArr is not null) ArrayPool<byte>.Shared.Return(derivedArr, clearArray: true);

            CryptographicOperations.ZeroMemory(expected);
            if (expectedArr is not null) ArrayPool<byte>.Shared.Return(expectedArr, clearArray: true);

            // salt not strictly secret, but wipe pooled memory anyway
            CryptographicOperations.ZeroMemory(salt);
            if (saltArr is not null) ArrayPool<byte>.Shared.Return(saltArr, clearArray: true);
        }
    }

    public static bool Verify(string secret, string phc) => Verify(secret.AsSpan(), phc.AsSpan());
}