using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using BenchmarkDotNet.Jobs;
using Soenneker.Hashing.Pbkdf2.Tests.Implementations;

namespace Soenneker.Hashing.Pbkdf2.Tests.Benchmarks;

[ThreadingDiagnoser]
[MemoryDiagnoser]
[SimpleJob(RunStrategy.Throughput, RuntimeMoniker.Net90, launchCount: 1, warmupCount: 1, iterationCount: 1)]
public class Benchmark
{
    // BenchmarkDotNet will spin up a fresh *instance of this class* per thread,
    // so the fields below are already thread-local; no further protection needed.
    private string _testPassword = null!;
    private string _originalHash = null!;
    private string _newHash = null!;

    [GlobalSetup]
    public void Setup()
    {
        _testPassword = "MySecurePassword123!";
        
        // Pre-generate hashes for verification benchmarks
        _originalHash = OriginalUtil.Hash(_testPassword);
        _newHash = Pbkdf2HashingUtil.Hash(_testPassword);
    }

    [Benchmark]
    public string HashOriginal() => OriginalUtil.Hash(_testPassword);

    [Benchmark]
    public string HashNew() => Pbkdf2HashingUtil.Hash(_testPassword);

    [Benchmark]
    public bool VerifyOriginal() => OriginalUtil.Verify(_testPassword, _originalHash);

    [Benchmark]
    public bool VerifyNew() => Pbkdf2HashingUtil.Verify(_testPassword, _newHash);

    [Benchmark]
    public bool VerifyOriginalWrongPassword() => OriginalUtil.Verify("WrongPassword", _originalHash);

    [Benchmark]
    public bool VerifyNewWrongPassword() => Pbkdf2HashingUtil.Verify("WrongPassword", _newHash);
}