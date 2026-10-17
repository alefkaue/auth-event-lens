using AuthEventLens;
using System.Text.Json;

if (args.Length == 1 && args[0] == "--help")
{
    Console.WriteLine("Usage: AuthEventLens INPUT.jsonl [THRESHOLD WINDOW_SECONDS]");
    return 0;
}
if (args.Length is not (1 or 3))
{
    Console.Error.WriteLine("Usage: AuthEventLens INPUT.jsonl [THRESHOLD WINDOW_SECONDS]");
    return 2;
}
try
{
    int threshold = args.Length == 3 ? int.Parse(args[1], System.Globalization.CultureInfo.InvariantCulture) : 3;
    int window = args.Length == 3 ? int.Parse(args[2], System.Globalization.CultureInfo.InvariantCulture) : 300;
    var report = Analyzer.Analyze(File.ReadLines(args[0]), threshold, window);
    Console.WriteLine(JsonSerializer.Serialize(report, new JsonSerializerOptions
    {
        WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    }));
    return report.Findings.Length == 0 ? 0 : 1;
}
catch (Exception error) when (error is IOException or UnauthorizedAccessException or FormatException
    or ArgumentException or JsonException or InvalidOperationException or OverflowException)
{
    Console.Error.WriteLine($"Error: {error.Message}");
    return 2;
}
