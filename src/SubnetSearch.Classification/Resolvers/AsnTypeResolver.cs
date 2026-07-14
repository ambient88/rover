namespace SubnetSearch.Classification;

// Builds a local ASN type map from as.json categories and bgp.tools community tags.
// Strong as.json access, government, and education categories override stale hosting tags.
// The bgp.tools dsl, mobile, and satnet tags also identify access networks.
// A vpsh tag identifies hosting and takes priority over CDN and business tags.
// A CDN tag without vpsh identifies a CDN network.
// Government, university, personal, event, corporate, and business tags map to their matching categories.
// The broad as.json hosting category does not produce a positive hosting result on its own.
// ASNs without reliable data remain absent from the map.
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
                       // as.json "hosting" intentionally maps to null. See rule 7 above.
                       "business" => "business",
                       _ => null,
                   };

            if (type != null)
                result[asn] = type;
        }
        return result;
    }
}
