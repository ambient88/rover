namespace SubnetSearch.Classification;

// Загружает community-теги ASN с bgp.tools (https://bgp.tools/kb/api).
// Формат файла: "AS44684,Mythic Beasts Ltd" — по строке на ASN.
// Файлы скачиваются DownloadManager'ом как bgptools-{tag}.csv (TTL 7 дней).
public static class BgpToolsTagLoader
{
    // Теги, участвующие в определении типа ASN (см. AsnTypeResolver).
    public static readonly string[] Tags =
    [
        "vpsh",   // VPS hosting (позитивный сигнал)
        "cdn",    // CDN
        "dsl",    // residential ISP
        "mobile", // мобильные операторы
        "satnet", // спутниковые сети
        "gov",    // государственные
        "uni",    // университеты/образование
        "perso",  // персональные ASN
        "corp",   // корпоративные сети
        "biznet", // B2B-сети
        "event",  // временные (конференции)
    ];

    public static string FileName(string tag) => $"bgptools-{tag}.csv";

    // Возвращает tag → множество ASN. Отсутствующий файл → пустое множество
    // (резолвер деградирует до категорий as.json).
    public static async Task<IReadOnlyDictionary<string, HashSet<uint>>> LoadAllAsync(string dataDir)
    {
        var result = new Dictionary<string, HashSet<uint>>();
        foreach (var tag in Tags)
            result[tag] = await LoadTagAsync(Path.Combine(dataDir, FileName(tag)));
        return result;
    }

    public static async Task<HashSet<uint>> LoadTagAsync(string filePath)
    {
        var set = new HashSet<uint>();
        if (!File.Exists(filePath)) return set;
        try
        {
            foreach (var line in await File.ReadAllLinesAsync(filePath))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                var comma = line.IndexOf(',');
                var token = (comma > 0 ? line[..comma] : line).Trim();
                if (token.StartsWith("AS", StringComparison.OrdinalIgnoreCase))
                    token = token[2..];
                if (uint.TryParse(token, out var asn))
                    set.Add(asn);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Повреждённый/недоступный файл → пустое множество, резолвер деградирует мягко.
        }
        return set;
    }

    // Парсит asn → имя из tag-файла (например vpsh.csv), нужен для vpsh-supplement (D-06):
    // кандидаты конструируются напрямую из имени bgp.tools, без похода в PeeringDB по одному ASN.
    // Формат строки: "AS215439,PLAY2GO LTD" — ASN до первой запятой, имя — весь остаток
    // (запятые внутри имени сохраняются, например "AS1,Foo, Inc."). Строки без запятой или
    // с пустым именем пропускаются — supplement-кандидату обязательно нужно имя.
    // Дубликаты ASN: первая запись побеждает (TryAdd).
    public static async Task<IReadOnlyDictionary<uint, string>> LoadTagWithNamesAsync(string filePath)
    {
        var map = new Dictionary<uint, string>();
        if (!File.Exists(filePath)) return map;
        try
        {
            foreach (var line in await File.ReadAllLinesAsync(filePath))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                var comma = line.IndexOf(',');
                if (comma < 0) continue;

                var token = line[..comma].Trim();
                if (token.StartsWith("AS", StringComparison.OrdinalIgnoreCase))
                    token = token[2..];
                if (!uint.TryParse(token, out var asn)) continue;

                var name = line[(comma + 1)..].Trim();
                if (name.Length == 0) continue;

                map.TryAdd(asn, name);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Повреждённый/недоступный файл → пустой словарь, supplement молча пропускается.
        }
        return map;
    }
}
