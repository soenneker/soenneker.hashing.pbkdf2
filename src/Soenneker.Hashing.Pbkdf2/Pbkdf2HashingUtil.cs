using System;
using System.Buffers;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Soenneker.Hashing.Phc;

namespace Soenneker.Hashing.Pbkdf2;

/// <summary>
/// A utility library for Pbkdf2 hashing and verification.
/// </summary>
public static class Pbkdf2HashingUtil
{
    private const string _identifier = "pbkdf2-sha256";
    private const string _iterationsParameter = "i";
    private const int _defaultSaltBytes = 16;
    private const int _defaultHashBytes = 32;
    private const int _defaultIterations = 300_000;
    private const int _maxIterations = 2_000_000;
    private const int _minSaltBytes = 8;
    private const int _maxSaltBytes = 64;
    private const int _minHashBytes = 16;
    private const int _maxHashBytes = 128;
    private const int _maxRecordChars = 512;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int Base64EncodedMaxLen(int byteLen) => (byteLen + 2) / 3 * 4;

    /// <summary>
    /// Span-first hasher that writes a PHC record into <paramref name="dest"/>.
    /// Returns true on success and sets <paramref name="charsWritten"/>.
    /// </summary>
    /// <param name="secret">Plain-text secret to verify.</param>
    /// <param name="dest">Dest for the try hash to span operation.</param>
    /// <param name="charsWritten">Chars Written for the try hash to span operation.</param>
    /// <param name="iterations">PBKDF2 iteration count.</param>
    /// <param name="saltBytes">Salt bytes used by the password hash.</param>
    /// <param name="hashBytes">Hash bytes to encode or verify.</param>
    /// <returns>true if span-first hasher that writes a PHC record into . Returns true on success and sets; otherwise, false.</returns>
    public static bool TryHashToSpan(ReadOnlySpan<char> secret, Span<char> dest, out int charsWritten, int iterations = _defaultIterations,
        int saltBytes = _defaultSaltBytes, int hashBytes = _defaultHashBytes)
    {
        charsWritten = 0;
        if (secret.IsEmpty || !ParametersAreSafe(iterations, saltBytes, hashBytes))
            return false;

        // Precompute worst-case output length to ensure dest is big enough.
        int saltB64Max = Base64EncodedMaxLen(saltBytes);
        int hashB64Max = Base64EncodedMaxLen(hashBytes);
        int needed = _identifier.Length + _iterationsParameter.Length + 15 + saltB64Max + hashB64Max;
        if (dest.Length < needed)
            return false;

        byte[]? saltArr = null;
        byte[]? pwdArr = null;
        byte[]? hashArr = null;
        var pwdCount = 0;

        Span<byte> salt = saltBytes <= 64 ? stackalloc byte[saltBytes] : (saltArr = ArrayPool<byte>.Shared.Rent(saltBytes)).AsSpan(0, saltBytes);
        Span<byte> hash = hashBytes <= 64 ? stackalloc byte[hashBytes] : (hashArr = ArrayPool<byte>.Shared.Rent(hashBytes)).AsSpan(0, hashBytes);

        try
        {
            // Salt
            RandomNumberGenerator.Fill(salt);

            // UTF-8 secret -> pooled bytes
            pwdCount = Encoding.UTF8.GetByteCount(secret);
            pwdArr = ArrayPool<byte>.Shared.Rent(pwdCount);
            Span<byte> pwd = pwdArr.AsSpan(0, pwdCount);
            _ = Encoding.UTF8.GetBytes(secret, pwd);

            // Derive
            Rfc2898DeriveBytes.Pbkdf2(pwd, salt, hash, iterations, HashAlgorithmName.SHA256);

            string saltText = Convert.ToBase64String(salt).TrimEnd('=');
            string hashText = Convert.ToBase64String(hash).TrimEnd('=');
            var record = new PhcString(_identifier, parameters: [new PhcParameter(_iterationsParameter, iterations.ToString(CultureInfo.InvariantCulture))],
                salt: saltText, hash: hashText);

            return PhcFormatter.TryFormat(record, dest, out charsWritten);
        }
        finally
        {
            if (pwdArr is not null)
            {
                // Secret material: clear only the bytes we wrote, then return without clearing the whole rented buffer.
                CryptographicOperations.ZeroMemory(pwdArr.AsSpan(0, pwdCount));
                ArrayPool<byte>.Shared.Return(pwdArr, clearArray: false);
            }

            CryptographicOperations.ZeroMemory(hash);
            if (hashArr is not null)
                ArrayPool<byte>.Shared.Return(hashArr, clearArray: false);

            // Salt isn’t secret, but clear if pooled
            if (saltArr is not null)
            {
                CryptographicOperations.ZeroMemory(salt);
                ArrayPool<byte>.Shared.Return(saltArr, clearArray: false);
            }
        }
    }

    /// <summary>
    /// Convenience wrapper that allocates exactly once for the final string.
    /// </summary>
    /// <param name="secret">Plain-text secret to verify.</param>
    /// <param name="iterations">PBKDF2 iteration count.</param>
    /// <param name="saltBytes">Salt bytes used by the password hash.</param>
    /// <param name="hashBytes">Hash bytes to encode or verify.</param>
    /// <returns>The text produced by hash.</returns>
    public static string Hash(ReadOnlySpan<char> secret, int iterations = _defaultIterations, int saltBytes = _defaultSaltBytes,
        int hashBytes = _defaultHashBytes)
    {
        if (secret.IsEmpty || !ParametersAreSafe(iterations, saltBytes, hashBytes))
            throw new InvalidOperationException("PBKDF2 parameters exceed the supported safety limits.");

        // Compute an upper bound and rent a char buffer
        int saltB64Max = Base64EncodedMaxLen(saltBytes);
        int hashB64Max = Base64EncodedMaxLen(hashBytes);
        int upper = _identifier.Length + _iterationsParameter.Length + 15 + saltB64Max + hashB64Max;

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

    /// <summary>
    /// Determines whether the Pbkdf2 Hashing h.
    /// </summary>
    /// <param name="secret">Plain-text secret to verify.</param>
    /// <param name="iterations">PBKDF2 iteration count.</param>
    /// <param name="saltBytes">Salt bytes used by the password hash.</param>
    /// <param name="hashBytes">Hash bytes to encode or verify.</param>
    /// <returns>The text produced by hash.</returns>
    public static string Hash(string secret, int iterations = _defaultIterations, int saltBytes = _defaultSaltBytes, int hashBytes = _defaultHashBytes) =>
        Hash(secret.AsSpan(), iterations, saltBytes, hashBytes);

    /// <summary>
    /// Span-first verifier; avoids allocating intermediate strings and never materializes the secret as a string.
    /// </summary>
    /// <param name="secret">Plain-text secret to verify.</param>
    /// <param name="phc">PBKDF2 hash encoded in PHC string format.</param>
    /// <returns>true if span-first verifier; avoids allocating intermediate strings and never materializes the secret as a string; otherwise, false.</returns>
    public static bool Verify(ReadOnlySpan<char> secret, ReadOnlySpan<char> phc)
    {
        if (secret.IsEmpty || phc.Length > _maxRecordChars || !PhcFormatter.TryParse(phc.ToString(), out PhcString? parsed))
            return false;

        PhcString record = parsed!;

        if (
            !record.Identifier.Equals(_identifier, StringComparison.Ordinal) || record.Version is not null || record.Parameters.Count != 1 ||
            !record.TryGetParameter(_iterationsParameter, out string? iterationsText) || record.Salt is null || record.Hash is null)
            return false;

        ReadOnlySpan<char> saltB64 = record.Salt;
        ReadOnlySpan<char> hashB64 = record.Hash;

        if (!int.TryParse(iterationsText, NumberStyles.None, CultureInfo.InvariantCulture, out int iterations) || iterations is <= 0 or > _maxIterations)
            return false;

        if (saltB64.Length > Base64EncodedMaxLen(_maxSaltBytes) || hashB64.Length > Base64EncodedMaxLen(_maxHashBytes))
            return false;

        int saltMax = (saltB64.Length + 3) / 4 * 3;
        int hashMax = (hashB64.Length + 3) / 4 * 3;

        byte[]? saltArr = saltMax <= 64 ? null : ArrayPool<byte>.Shared.Rent(saltMax);
        Span<byte> salt = saltArr is null ? stackalloc byte[saltMax] : saltArr.AsSpan(0, saltMax);

        if (!TryDecodePhcBase64(saltB64, salt, out int saltLen))
        {
            if (saltArr is not null)
            {
                // salt isn't secret, but don't leak caller input / decoded bytes
                CryptographicOperations.ZeroMemory(saltArr.AsSpan(0, saltMax));
                ArrayPool<byte>.Shared.Return(saltArr, clearArray: false);
            }

            return false;
        }

        salt = salt.Slice(0, saltLen);

        if (saltLen is < _minSaltBytes or > _maxSaltBytes)
        {
            CryptographicOperations.ZeroMemory(salt);
            if (saltArr is not null)
                ArrayPool<byte>.Shared.Return(saltArr, clearArray: false);
            return false;
        }

        byte[]? expectedArr = hashMax <= 64 ? null : ArrayPool<byte>.Shared.Rent(hashMax);
        Span<byte> expected = expectedArr is null ? stackalloc byte[hashMax] : expectedArr.AsSpan(0, hashMax);

        if (!TryDecodePhcBase64(hashB64, expected, out int expectedLen))
        {
            if (expectedArr is not null)
            {
                CryptographicOperations.ZeroMemory(expectedArr.AsSpan(0, hashMax));
                ArrayPool<byte>.Shared.Return(expectedArr, clearArray: false);
            }

            if (saltArr is not null)
            {
                CryptographicOperations.ZeroMemory(saltArr.AsSpan(0, saltMax));
                ArrayPool<byte>.Shared.Return(saltArr, clearArray: false);
            }

            return false;
        }

        expected = expected.Slice(0, expectedLen);

        if (expectedLen is < _minHashBytes or > _maxHashBytes)
        {
            CryptographicOperations.ZeroMemory(expected);
            if (expectedArr is not null)
                ArrayPool<byte>.Shared.Return(expectedArr, clearArray: false);

            CryptographicOperations.ZeroMemory(salt);
            if (saltArr is not null)
                ArrayPool<byte>.Shared.Return(saltArr, clearArray: false);
            return false;
        }

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
            ArrayPool<byte>.Shared.Return(pwdArr, clearArray: false);

            CryptographicOperations.ZeroMemory(derived);
            if (derivedArr is not null)
                ArrayPool<byte>.Shared.Return(derivedArr, clearArray: false);

            CryptographicOperations.ZeroMemory(expected);
            if (expectedArr is not null)
                ArrayPool<byte>.Shared.Return(expectedArr, clearArray: false);

            // salt not strictly secret, but wipe pooled memory anyway
            CryptographicOperations.ZeroMemory(salt);
            if (saltArr is not null)
                ArrayPool<byte>.Shared.Return(saltArr, clearArray: false);
        }
    }

    /// <summary>
    /// Verifies a secret against a PBKDF2 password hash encoded in PHC format.
    /// </summary>
    /// <param name="secret">Plain-text secret to verify.</param>
    /// <param name="phc">PBKDF2 hash encoded in PHC string format.</param>
    /// <returns>true if the secret matches the encoded hash; otherwise, false.</returns>
    public static bool Verify(string secret, string phc) => Verify(secret.AsSpan(), phc.AsSpan());

    private static bool ParametersAreSafe(int iterations, int saltBytes, int hashBytes) =>
        iterations is >= 1 and <= _maxIterations && saltBytes is >= _minSaltBytes and <= _maxSaltBytes &&
        hashBytes is >= _minHashBytes and <= _maxHashBytes;

    private static bool TryDecodePhcBase64(ReadOnlySpan<char> value, Span<byte> destination, out int bytesWritten)
    {
        int padding = (4 - value.Length % 4) % 4;
        Span<char> padded = stackalloc char[value.Length + padding];
        value.CopyTo(padded);
        padded[value.Length..].Fill('=');
        return Convert.TryFromBase64Chars(padded, destination, out bytesWritten);
    }
}
