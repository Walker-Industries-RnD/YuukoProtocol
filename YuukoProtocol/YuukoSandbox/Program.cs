using System.Text;
using YuukoProtocol;
using YuukoSandbox;

// dotnet run --project YuukoSandbox -- bench      → performance benchmark
// dotnet run --project YuukoSandbox -- selftest   → checks for the most important parts (no network needed)
if (args.Length > 0 && args[0].Equals("bench", StringComparison.OrdinalIgnoreCase))
{
    await Benchmark.RunAsync();
    return;
}

if (args.Length > 0 && args[0].Equals("selftest", StringComparison.OrdinalIgnoreCase))
{
    Environment.Exit(await SelfTest.RunAsync());
    return;
}

await MainTest.Main();

