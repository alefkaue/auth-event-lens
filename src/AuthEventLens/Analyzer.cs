using System.Globalization;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace AuthEventLens;

public sealed record AuthEvent(DateTimeOffset Timestamp, int EventId, string User, string SourceIp, int LogonType, int Line);
public sealed record Finding(string Rule, string SourceIp, string Timestamp, string[] Users, int[] EvidenceLines);
public sealed record Report(int Events, int IgnoredEvents, Finding[] Findings);

public static class Analyzer
{
    public static AuthEvent Parse(string line, int number)
    {
        if (line.Length > 65536) throw new FormatException($"Line {number} exceeds 64 KiB characters");
        using var document = JsonDocument.Parse(line);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object) throw new FormatException($"Line {number}: object expected");
        string[] names = ["timestamp", "eventId", "user", "sourceIp", "logonType"];
        var fields = root.EnumerateObject().Select(p => p.Name).ToArray();
        if (fields.Length != names.Length || !fields.Order().SequenceEqual(names.Order()))
            throw new FormatException($"Line {number}: exact normalized event schema required");
        var timestamp = root.GetProperty("timestamp").GetString() ?? "";
        if (!Regex.IsMatch(timestamp, @"^\d{4}-\d{2}-\d{2}T.+(?:Z|[+-]\d{2}:\d{2})$") ||
            !DateTimeOffset.TryParse(timestamp, CultureInfo.InvariantCulture, DateTimeStyles.None, out var time))
            throw new FormatException($"Line {number}: ISO timestamp with timezone required");
        var user = root.GetProperty("user").GetString() ?? "";
        var ip = root.GetProperty("sourceIp").GetString() ?? "";
        if (string.IsNullOrWhiteSpace(user) || user.Any(char.IsControl) || user != user.Trim())
            throw new FormatException($"Line {number}: nonempty normalized user required");
        if ((!ip.Contains(':') && !Regex.IsMatch(ip, @"^(?:(?:0|[1-9]\d{0,2})\.){3}(?:0|[1-9]\d{0,2})$")) ||
            !IPAddress.TryParse(ip, out var address) || ip.Contains('%'))
            throw new FormatException($"Line {number}: valid IPv4/IPv6 address required");
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        return new(time, root.GetProperty("eventId").GetInt32(), user, address.ToString(),
                   root.GetProperty("logonType").GetInt32(), number);
    }

    public static Report Analyze(IEnumerable<string> lines, int threshold = 3, int windowSeconds = 300)
    {
        if (threshold < 2 || windowSeconds < 1 || windowSeconds > 86400)
            throw new ArgumentException("Threshold must be >= 2 and window within 1..86400 seconds");
        var events = new List<AuthEvent>();
        int number = 0, ignored = 0;
        foreach (var line in lines)
        {
            number++;
            if (number > 100000) throw new FormatException("Input exceeds 100000 lines");
            if (string.IsNullOrWhiteSpace(line)) continue;
            var item = Parse(line, number);
            if (item.EventId is not (4624 or 4625) || item.LogonType is not (3 or 10)) { ignored++; continue; }
            events.Add(item);
        }
        var windows = new Dictionary<string, List<AuthEvent>>();
        var active = new HashSet<string>();
        var findings = new List<Finding>();
        foreach (var item in events.OrderBy(e => e.Timestamp).ThenBy(e => e.Line))
        {
            if (!windows.TryGetValue(item.SourceIp, out var failures))
                windows[item.SourceIp] = failures = [];
            // Subtraction avoids DateTimeOffset underflow on timestamps near year 1.
            failures.RemoveAll(f => (item.Timestamp - f.Timestamp).TotalSeconds > windowSeconds);
            int distinct() => failures.Select(f => f.User).Distinct(StringComparer.OrdinalIgnoreCase).Count();
            if (distinct() < threshold) active.Remove(item.SourceIp);
            if (item.EventId == 4625)
            {
                failures.Add(item);
                if (distinct() >= threshold && active.Add(item.SourceIp))
                    findings.Add(new("password_spray_pattern", item.SourceIp, item.Timestamp.ToString("O"),
                        failures.Select(f => f.User).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).ToArray(),
                        failures.Select(f => f.Line).ToArray()));
            }
            else
            {
                var related = failures.Where(f => string.Equals(f.User, item.User, StringComparison.OrdinalIgnoreCase)).ToArray();
                if (related.Length != 0)
                {
                    findings.Add(new("success_after_failure", item.SourceIp, item.Timestamp.ToString("O"),
                        [item.User], related.Select(f => f.Line).Append(item.Line).ToArray()));
                    failures.RemoveAll(f => string.Equals(f.User, item.User, StringComparison.OrdinalIgnoreCase));
                }
            }
        }
        return new(events.Count, ignored, findings.ToArray());
    }
}
