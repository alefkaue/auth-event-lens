using AuthEventLens;
using System.Text.Json;

int checks = 0;
void Check(bool value, string label)
{
    checks++;
    if (!value) throw new Exception(label);
}
string Line(int second, string user = "lab\\alice", int id = 4625, string ip = "192.0.2.40", int type = 3) =>
    JsonSerializer.Serialize(new { timestamp = $"2026-01-01T12:00:{second:00}Z", eventId = id, user, sourceIp = ip, logonType = type });

var spray = Analyzer.Analyze([Line(0), Line(1, "lab\\bob"), Line(2, "lab\\carol"), Line(3, id: 4624)]);
Check(spray.Findings.Length == 2, "Spray and related success");
Check(spray.Findings[0].Rule == "password_spray_pattern", "Spray rule");
Check(spray.Findings[0].EvidenceLines.SequenceEqual([1, 2, 3]), "Spray provenance");
Check(spray.Findings[1].EvidenceLines.SequenceEqual([1, 4]), "Success tied to same user");
Check(Analyzer.Analyze([Line(0), Line(1), Line(2)]).Findings.Length == 0, "Distinct users required");
Check(Analyzer.Analyze([Line(0), Line(1, "LAB\\ALICE"), Line(2, "lab\\bob")]).Findings.Length == 0, "Case insensitive users");
Check(Analyzer.Analyze([Line(0), Line(1, "bob", ip: "192.0.2.41"), Line(2, "carol")]).Findings.Length == 0, "Separate IPs");
Check(Analyzer.Analyze([Line(0), Line(20, "bob"), Line(21, "carol")], 3, 10).Findings.Length == 0, "Expired failures");
Check(Analyzer.Analyze([Line(2, "carol"), Line(0), Line(1, "bob")], 3, 2).Findings.Length == 1, "Unsorted inclusive window");
Check(Analyzer.Analyze([Line(0), Line(1, "other", id: 4624)]).Findings.Length == 0, "Unrelated user success");
Check(Analyzer.Analyze([Line(0), Line(1, id: 4624), Line(2, id: 4624)]).Findings.Length == 1, "No repeated success correlation");
var ignored = Analyzer.Analyze([Line(0, type: 2), Line(1, id: 9999)]);
Check(ignored.Events == 0 && ignored.IgnoredEvents == 2, "Ignore non-network and unsupported IDs");
Check(Analyzer.Parse(Line(0, ip: "::ffff:192.0.2.40"), 1).SourceIp == "192.0.2.40", "Normalize mapped IP");
foreach (var value in new[] { "{}", "[]", "garbage", Line(0).Replace("Z\"", "\""), Line(0, ip: "123"), Line(0, ip: "010.0.0.1"), Line(0, user: " ") })
{
    bool rejected = false;
    try { Analyzer.Analyze([value]); }
    catch (Exception e) when (e is FormatException or JsonException or InvalidOperationException) { rejected = true; }
    Check(rejected, "Reject invalid event");
}
bool badOptions = false;
try { Analyzer.Analyze([], 1); } catch (ArgumentException) { badOptions = true; }
Check(badOptions, "Reject invalid options");
Console.WriteLine($"PASS: {checks} assertions");
