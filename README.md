[![](https://img.shields.io/nuget/v/soenneker.hashing.pbkdf2.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.hashing.pbkdf2/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.hashing.pbkdf2/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.hashing.pbkdf2/actions/workflows/publish-package.yml)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.hashing.pbkdf2/build-and-test.yml?style=for-the-badge&label=build)](https://github.com/soenneker/soenneker.hashing.pbkdf2/actions/workflows/build-and-test.yml)
[![](https://img.shields.io/nuget/dt/soenneker.hashing.pbkdf2.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.hashing.pbkdf2/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.hashing.pbkdf2/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.hashing.pbkdf2/actions/workflows/codeql.yml)

# Soenneker.Hashing.Pbkdf2

Hashes secrets with PBKDF2-HMAC-SHA256 and encodes the iteration count, random salt, and derived hash in one record. It includes string convenience methods and span-first APIs for callers that want to control the output buffer.

## Installation

```bash
dotnet add package Soenneker.Hashing.Pbkdf2
```

## Hash and verify

```csharp
using Soenneker.Hashing.Pbkdf2;

string storedHash = Pbkdf2HashingUtil.Hash(password);

bool valid = Pbkdf2HashingUtil.Verify(candidatePassword, storedHash);
```

The encoded record has this format:

```text
pbkdf2_sha256$300000$<salt-base64>$<hash-base64>
```

Each hash gets a new cryptographically secure salt. The defaults are 300,000 iterations, a 16-byte salt, and a 32-byte derived hash.

## Write into an existing character buffer

```csharp
Span<char> destination = stackalloc char[128];

if (!Pbkdf2HashingUtil.TryHashToSpan(password, destination, out int written))
    throw new InvalidOperationException("The destination was too small or the parameters were invalid.");

ReadOnlySpan<char> encoded = destination[..written];
```

`TryHashToSpan()` returns `false` and writes zero characters when the secret is empty, parameters are unsupported, or the destination cannot hold the complete record. Use `Hash()` when a final string is needed.

## Work-factor limits

Custom values can be supplied to either hashing overload:

```csharp
string storedHash = Pbkdf2HashingUtil.Hash(
    password,
    iterations: 600_000,
    saltBytes: 24,
    hashBytes: 32);
```

Supported records use 1–2,000,000 iterations, 8–64 salt bytes, and 16–128 derived bytes. These bounds prevent stored or attacker-controlled records from requesting unbounded CPU or buffer allocation. `Hash()` throws `InvalidOperationException` outside the bounds; `TryHashToSpan()` and `Verify()` return `false`.

Verification compares derived bytes in constant time and returns `false` for malformed, oversized, empty, or mismatched records. Sensitive temporary byte buffers are cleared before being returned to their pools. Applications should benchmark their chosen iteration count, rate-limit authentication, and avoid logging secrets or encoded records.
