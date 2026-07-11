using System.Text;
using YuukoProtocol;
using YuukoSandbox;

// dotnet run --project YuukoSandbox -- bench   → performance benchmark
if (args.Length > 0 && args[0].Equals("bench", StringComparison.OrdinalIgnoreCase))
{
    await Benchmark.RunAsync();
    return;
}

await MainTest.Main();

