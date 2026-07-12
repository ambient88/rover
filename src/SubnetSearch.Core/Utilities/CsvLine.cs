using System.Text;

namespace SubnetSearch.Core.Utilities;

/// <summary>
/// Minimal RFC 4180-style parser for a single CSV record line. Handles quoted fields, commas
/// embedded inside quotes, and escaped quotes (""). A plain String.Split(',') mangles provider
/// names like "ThePlanet.com Internet Services, Inc." — splitting the name and shifting every
/// later column by one (F7). This does not support quoted fields spanning multiple physical lines,
/// which the data sources here never use (files are read line by line).
/// </summary>
public static class CsvLine
{
    public static List<string> Parse(string line)
    {
        var fields = new List<string>();
        var sb = new StringBuilder();
        bool inQuotes = false;

        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (inQuotes)
            {
                if (c == '"')
                {
                    // Doubled quote inside a quoted field is a literal quote.
                    if (i + 1 < line.Length && line[i + 1] == '"') { sb.Append('"'); i++; }
                    else inQuotes = false;
                }
                else sb.Append(c);
            }
            else if (c == '"') inQuotes = true;
            else if (c == ',') { fields.Add(sb.ToString()); sb.Clear(); }
            else sb.Append(c);
        }

        fields.Add(sb.ToString());
        return fields;
    }
}
