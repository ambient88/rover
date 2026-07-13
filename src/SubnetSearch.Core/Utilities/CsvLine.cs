using System.Text;

namespace SubnetSearch.Core.Utilities;

/// <summary>
/// Parses one CSV record with quoted fields and escaped quotes.
/// Multiline fields are not supported because the input sources use one record per line.
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
