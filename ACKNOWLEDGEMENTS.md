# 🙏 Acknowledgements

`rover` stands on the shoulders of giants. This project wouldn't be possible without the following open-source projects, data sources, communities, and individuals.

## 📜 Attribution (License-Required)

This section lists third-party works used by `rover` whose licenses require attribution.

### AS & Network Metadata

- **ipverse/as-metadata**
  - **Author/Organization:** ipverse
  - **Source:** [https://github.com/ipverse/as-metadata](https://github.com/ipverse/as-metadata)
  - **License:** CC0-1.0 (Public Domain)[reference:0]
  - **Used for:** Autonomous System (AS) metadata — handle, organization name, and country code for all assigned ASNs[reference:1].
  - **File:** `as.json` (downloaded from `https://raw.githubusercontent.com/ipverse/as-metadata/master/as.json`)

### Datacenter & Hosting Provider IP Ranges

- **podlibre/ipcat**
  - **Author/Organization:** podlibre
  - **Source:** [https://github.com/podlibre/ipcat](https://github.com/podlibre/ipcat)
  - **License:** GNU General Public License v3.0[reference:2]
  - **Used for:** Detecting datacenter and hosting provider IPs.
  - **File:** `datacenters.csv` (downloaded from `https://raw.githubusercontent.com/podlibre/ipcat/master/datacenters.csv`)

### Cloud Provider IP Ranges

- **rezmoss/cloud-provider-ip-addresses**
  - **Author/Organization:** rezmoss
  - **Source:** [https://github.com/rezmoss/cloud-provider-ip-addresses](https://github.com/rezmoss/cloud-provider-ip-addresses)
  - **License:** CC0-1.0 (Public Domain)[reference:3]
  - **Used for:** Identifying IP addresses belonging to major cloud providers (AWS, Azure, GCP, Cloudflare, etc.)[reference:4].
  - **File:** `all_providers.json` (downloaded from `https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/all_providers/all_providers.json`)

- **jhassine/server-ip-addresses**
  - **Author/Organization:** jhassine
  - **Source:** [https://github.com/jhassine/server-ip-addresses](https://github.com/jhassine/server-ip-addresses)
  - **License:** Not explicitly specified[reference:5] (use with caution; consider it proprietary or contact the author for clarification)
  - **Used for:** Daily updated list of IP addresses / CIDR blocks used by data centers, cloud service providers, and servers[reference:6].
  - **File:** `datacenters.csv` (downloaded from `https://raw.githubusercontent.com/jhassine/server-ip-addresses/master/data/datacenters.csv`)

### Threat Intelligence & Reputation Data

- **stamparm/ipsum**
  - **Author/Organization:** Miroslav Stampar (stamparm)
  - **Source:** [https://github.com/stamparm/ipsum](https://github.com/stamparm/ipsum)
  - **License:** The Unlicense (Public Domain)[reference:7][reference:8]
  - **Used for:** Threat intelligence and reputation scoring (suspicious and malicious IP addresses)[reference:9].
  - **File:** `ipsum.txt` (downloaded from `https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt`)

---

### Geolocation Data

- **DB-IP**
  - **Author/Organization:** DB-IP
  - **Source:** [https://db-ip.com/](https://db-ip.com/)
  - **License:** CC BY 4.0 ([https://creativecommons.org/licenses/by/4.0/](https://creativecommons.org/licenses/by/4.0/))
  - **Used for:** IP geolocation (country, city, region, coordinates, timezone).
  - **File:** `dbip-city.mmdb.gz` (downloaded on first run).

### ASN & Network Data

- **IPtoASN (ip2asn)**
  - **Author/Organization:** IPtoASN.com
  - **Source:** [https://iptoasn.com/](https://iptoasn.com/)
  - **License:** Apache License 2.0 ([https://www.apache.org/licenses/LICENSE-2.0](https://www.apache.org/licenses/LICENSE-2.0))
  - **Used for:** Mapping IP addresses to Autonomous System Numbers (ASN), organization, and range.
  - **File:** `ip2asn-v4.tsv.gz` (downloaded on first run).

### CLI Framework

- **Spectre.Console**
  - **Author/Organization:** Patrik Svensson
  - **Source:** [https://github.com/spectreconsole/spectre.console](https://github.com/spectreconsole/spectre.console)
  - **License:** MIT License ([https://github.com/spectreconsole/spectre.console/blob/main/LICENSE](https://github.com/spectreconsole/spectre.console/blob/main/LICENSE))
  - **Used for:** Building the CLI interface with rich formatting, progress bars, and tables.

### Runtime & Build Tools

- **.NET 8**
  - **Author/Organization:** Microsoft
  - **Source:** [https://dotnet.microsoft.com/](https://dotnet.microsoft.com/)
  - **License:** MIT License ([https://github.com/dotnet/runtime/blob/main/LICENSE.TXT](https://github.com/dotnet/runtime/blob/main/LICENSE.TXT))
  - **Used for:** Runtime environment and build system.

## 🔌 External Services & APIs

The following online services are queried at runtime (when API keys are provided) to enrich reputation and network data. They are not distributed with `rover` but are used under their respective terms of service.

- **AbuseIPDB** - for IP reputation checks ([https://www.abuseipdb.com/](https://www.abuseipdb.com/))
- **GreyNoise** - for IP intelligence ([https://greynoise.io/](https://greynoise.io/))
- **Spamhaus DROP** - for blacklist feeds ([https://www.spamhaus.org/](https://www.spamhaus.org/))
- **PeeringDB** - for peering and IXP data ([https://www.peeringdb.com/](https://www.peeringdb.com/))
- **RIPE Stat** - for RPKI and routing stats ([https://stat.ripe.net/](https://stat.ripe.net/))
- **BGPView** - for BGP routing information ([https://bgpview.io/](https://bgpview.io/))
- **ipapi.is** - for additional IP metadata ([https://ipapi.is/](https://ipapi.is/))

## 🙏 Thanks

This section acknowledges the broader community and tools that have inspired and supported `rover`.

- **Key Dependencies**: We are grateful to the creators and maintainers of [.NET](https://dotnet.microsoft.com/), [Spectre.Console](https://github.com/spectreconsole/spectre.console), and all the open-source data providers listed above.
- **Inspiration**: This project was inspired by the need for a simple, offline-capable tool to rank hosting providers, drawing from the wealth of public data available.

---

*This document is maintained manually. If you believe any attribution is missing or incorrect, please open an issue or submit a pull request.*