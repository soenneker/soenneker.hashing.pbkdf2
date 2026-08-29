[![](https://img.shields.io/nuget/v/soenneker.hashing.pbkdf2.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.hashing.pbkdf2/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.hashing.pbkdf2/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.hashing.pbkdf2/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/soenneker.hashing.pbkdf2.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.hashing.pbkdf2/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.hashing.pbkdf2/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.hashing.pbkdf2/actions/workflows/codeql.yml)

# Soenneker.Hashing.Pbkdf2

A utility library for Pbkdf2 hashing and verification.

## Install

```bash
dotnet add package Soenneker.Hashing.Pbkdf2
```

## Quick start

```csharp
using Soenneker.Hashing.Pbkdf2;

var result = Pbkdf2HashingUtil.TryHashToSpan(/* supply secret */ default!, /* supply dest */ default!, 1);
```

Span-first hasher that writes a PHC record into `dest`. Returns true on success and sets `charsWritten`.

## What you get

- `Pbkdf2HashingUtil` — A utility library for Pbkdf2 hashing and verification.

## API at a glance

| API | What it does | Result / important behavior |
| --- | --- | --- |
| `Pbkdf2HashingUtil.TryHashToSpan(secret, dest, charsWritten, iterations, saltBytes, hashBytes)` | Span-first hasher that writes a PHC record into `dest`. Returns true on success and sets `charsWritten`. | true if span-first hasher that writes a PHC record into . Returns true on success and sets; otherwise, false. |
| `Pbkdf2HashingUtil.Verify(secret, phc)` | Span-first verifier; avoids allocating intermediate strings and never materializes the secret as a string. | true if span-first verifier; avoids allocating intermediate strings and never materializes the secret as a string; otherwise, false. |
