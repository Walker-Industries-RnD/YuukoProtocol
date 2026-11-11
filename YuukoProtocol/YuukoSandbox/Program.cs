using System.Text;
using YuukoProtocol;
using YuukoSandbox;

// dotnet run --project YuukoSandbox -- bench                      → performance benchmark
// dotnet run --project YuukoSandbox -- example ot|crdt|audit     → runnable, narrated demos
// dotnet run --project YuukoSandbox -- selftest                   → security + behaviour checks (no network needed)
// dotnet run --project YuukoSandbox -- id|provider|client|offer|join ...   → two-device service template
if (args.Length > 0 && args[0].Equals("bench", StringComparison.OrdinalIgnoreCase))
{
    await Benchmark.RunAsync();
    return;
}

if (args.Length > 0 && args[0].Equals("example", StringComparison.OrdinalIgnoreCase))
{
    Environment.Exit(await Examples.RunAsync(args));
    return;
}

if (args.Length > 0 && args[0].Equals("selftest", StringComparison.OrdinalIgnoreCase))
{
    Environment.Exit(await SelfTest.RunAsync());
    return;
}

if (args.Length > 0 && (args[0].Equals("provider", StringComparison.OrdinalIgnoreCase)
                     || args[0].Equals("client", StringComparison.OrdinalIgnoreCase)
                     || args[0].Equals("offer", StringComparison.OrdinalIgnoreCase)
                     || args[0].Equals("join", StringComparison.OrdinalIgnoreCase)
                     || args[0].Equals("id", StringComparison.OrdinalIgnoreCase)))
{
    await ServiceTemplate.RunAsync(args);
    return;
}

await MainTest.Main();
