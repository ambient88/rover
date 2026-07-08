namespace SubnetSearch.Classification;

// Локальная замена ASN-типов ipapi.is: объединяет категории as.json (ipverse, 123k ASN)
// и community-теги bgp.tools в единую карту asn → тип.
// Типы совместимы с фильтрами ProviderFinder:
//   "hosting" — проходит --type server/vps; всё остальное отсеивается.
//
// Приоритет правил (выше = сильнее), выверен на реальных конфликтах данных:
//   1. as.json isp/government_admin/education_research — сильный негатив, бьёт vpsh-тег.
//      (Кейс CG-Net AS16247: устаревший vpsh-тег на B2B-провайдере; as.json говорит isp.)
//   2. bgp.tools dsl/mobile/satnet → isp. Бьёт vpsh: противоречащий тег доступа сильнее
//      устаревшего vpsh-тега. (Кейс Wavenet AS5413: vpsh+dsl+corp+biznet → isp. ~143
//      access-ISP со случайным vpsh-тегом — China Telecom, Cox, Bell, Telia — так корректно
//      уходят из выдачи хостинга.)
//   3. bgp.tools vpsh → hosting. Бьёт cdn-тег: OVH/AWS/Google несут оба тега (cdn∩vpsh=39),
//      и cdn-приоритет выбросил бы крупнейшие облака.
//   4. bgp.tools cdn → cdn. (Кейс Blizzard AS57976: as.json ошибочно даёт hosting,
//      cdn-тег без vpsh корректно выводит его из выдачи хостинга.)
//   5. bgp.tools gov/uni/perso/event → government/education/personal/business.
//   6. bgp.tools corp/biznet → business. Остаётся НИЖЕ vpsh: тег шумный (хостер может
//      обслуживать бизнес), и для реальных кейсов достаточно тега доступа.
//   7. Категория as.json business → business.
//      ВАЖНО: as.json "hosting" НЕ даёт позитивный вердикт — категория слишком щедрая
//      (12k+ ASN, включая F5, Cisco Umbrella, Hurricane Electric, Blizzard). Позитив
//      "hosting" выдаётся только по кураторскому vpsh-тегу; as.json hosting → null
//      (неизвестный), дальше решают консервативные правила фильтра.
//   8. Нет данных → ASN отсутствует в карте (null для потребителя).
public static class AsnTypeResolver
{
    public static IReadOnlyDictionary<uint, string> Build(
        IReadOnlyDictionary<string, HashSet<uint>> bgpToolsTags,
        IReadOnlyDictionary<uint, string> asJsonCategories)
    {
        HashSet<uint> Tag(string name) =>
            bgpToolsTags.TryGetValue(name, out var s) ? s : [];

        var vpsh = Tag("vpsh");   var cdn    = Tag("cdn");
        var dsl  = Tag("dsl");    var mobile = Tag("mobile"); var satnet = Tag("satnet");
        var gov  = Tag("gov");    var uni    = Tag("uni");
        var perso = Tag("perso"); var corp   = Tag("corp");
        var biznet = Tag("biznet"); var evnt = Tag("event");

        var universe = new HashSet<uint>(asJsonCategories.Keys);
        foreach (var set in bgpToolsTags.Values)
            universe.UnionWith(set);

        var result = new Dictionary<uint, string>(universe.Count);
        foreach (var asn in universe)
        {
            asJsonCategories.TryGetValue(asn, out var cat);

            string? type = cat switch
            {
                "isp"                => "isp",
                "government_admin"   => "government",
                "education_research" => "education",
                _ => null,
            };

            type ??= (dsl.Contains(asn) || mobile.Contains(asn) || satnet.Contains(asn)) ? "isp"
                   : vpsh.Contains(asn) ? "hosting"
                   : cdn.Contains(asn) ? "cdn"
                   : gov.Contains(asn) ? "government"
                   : uni.Contains(asn) ? "education"
                   : perso.Contains(asn) ? "personal"
                   : evnt.Contains(asn) ? "business"
                   : (corp.Contains(asn) || biznet.Contains(asn)) ? "business"
                   : cat switch
                   {
                       // as.json "hosting" intentionally maps to null — see rule 7 above.
                       "business" => "business",
                       _ => null,
                   };

            if (type != null)
                result[asn] = type;
        }
        return result;
    }
}
