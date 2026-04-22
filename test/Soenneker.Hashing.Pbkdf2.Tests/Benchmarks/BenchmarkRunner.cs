using System.Threading.Tasks;
using BenchmarkDotNet.Reports;
using Soenneker.Benchmarking.Extensions.Summary;
using Soenneker.Tests.Benchmark;

namespace Soenneker.Hashing.Pbkdf2.Tests.Benchmarks;

public sealed class BenchmarkRunner : BenchmarkTest
{
    public BenchmarkRunner() : base()
    {
    }

   // [Test]
    public async ValueTask Benchmark()
    {
        Summary summary = BenchmarkDotNet.Running.BenchmarkRunner.Run<Benchmark>(DefaultConf);

        await summary.OutputSummaryToLog(OutputHelper, CancellationToken);
    }
}