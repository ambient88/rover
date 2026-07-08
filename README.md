# 🛰️ rover

[![Build](https://github.com/ambient88/rover/actions/workflows/release.yml/badge.svg)](https://github.com/ambient88/rover/actions/workflows/release.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.0.1-green.svg)](https://github.com/ambient88/rover/releases)
[![.NET](https://img.shields.io/badge/.NET-8.0-purple.svg)](https://dotnet.microsoft.com/download)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-lightgrey.svg)]()

A CLI tool for classifying IP addresses, domains, and subnets. Identifies hosting providers, geolocation, reputation, network characteristics, and ranks providers worldwide.

![gif](https://raw.githubusercontent.com/ambient88/rover/main/static/images/demo1.gif)
---

## 🚀 Quick Start

### Prerequisites

* Linux, macOS, or Windows
* Administrator rights to install to a system path (optional)

### Installation

**curl (Linux / macOS)**
```bash
curl -fsSL https://raw.githubusercontent.com/ambient88/rover/main/scripts/install.sh | bash
```

**apt (Debian / Ubuntu, amd64)**
```bash
curl -fsSL https://ambient88.github.io/rover/gpg.key \
  | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/rover.gpg

echo "deb [arch=amd64] https://ambient88.github.io/rover/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/rover.list

sudo apt update && sudo apt install rover
```

**Docker**
```bash
docker run --rm \
  -v ~/.local/share/rover/data:/data \
  ghcr.io/ambient88/rover -a 1.2.3.4
```

**Manual binary:** download from the [Releases](https://github.com/ambient88/rover/releases) page, make it executable, and run:
```bash
chmod +x rover-linux-x64
./rover-linux-x64 -a 1.2.3.4
```

### First run

On the first run rover downloads its databases (~500 MB). After that it works offline.

```bash
rover -a 8.8.8.8
rover -d github.com
rover -r --country DE --max-ping 50 --top 10
```

---

## 📖 Documentation

* [Full flag and option reference](#-usage) (below in this file)
* [Build from source](#-build-from-source)
* [API key setup](#-api-keys)

---

## ✨ Features

* 🔍 IP classification: hosting type, ASN, organization, range, RIR
* 🌍 Geolocation: country, city, region, coordinates, timezone (DB-IP)
* 🛡️ Reputation: IPsum, ipapi.is, AbuseIPDB, GreyNoise, Spamhaus DROP
* 📡 Network: ping, traceroute, port scan, HTTP/TLS fingerprint
* 🌐 Domains: registrar, NS, WHOIS, service type (VPN / CDN / hosting)
* 🏢 Providers: scan by ASN or name — prefixes, upstreams, peerings
* 🏆 Recommendations (`-r`): find and rank hosting providers worldwide

---

## 🛠 Tech stack

* **Runtime:** .NET 8, self-contained single-file binary
* **CLI:** Spectre.Console
* **Data sources:** PeeringDB, RIPE Stat, BGPView, ipapi.is, AbuseIPDB, GreyNoise, Spamhaus
* **Databases:** DB-IP (geolocation), ip2asn, IPsum, ipcat
* **Packaging:** Docker (GHCR), Debian .deb, apt repository on GitHub Pages

---

## 🔧 Usage

### Analyze

```
rover -a <ip>         Classify a single IP address
rover -d <domain>     Classify a domain
rover -c <CIDR>       Classify a CIDR range
rover -l <file>       Batch classify from file (IPs and domains mixed)
rover -o <ASN|name>   Scan a provider: prefixes, upstreams, peerings
--whois               Force WHOIS lookups (slower, more detail)
```

### Discover providers

```
rover -r                        Find and rank hosting providers
rover -r <region>               Search by IXP region (e.g. Frankfurt, Amsterdam)
--type <type>                   Filter by provider type
--country <CC>                  Filter by country (ISO 3166-1, comma-separated)
--max-ping <ms>                 Only show providers below this latency
--top <N>                       Number of results (default: 20)
--sort <field>                  Sort order (default: score)
--preset <name>                 Scoring preset (default: balanced)
--from <path|url>               Cross-reference results against a list of IPs
--trace-to <ip>                 Run traceroute and highlight providers in the route
```

#### --type values

| Value | What it returns |
|-------|----------------|
| `server` | VPS, dedicated, cloud: all server rental types (excludes AI/GPU-only providers) |
| `cdn` | CDN and content delivery networks (Cloudflare, Akamai, Fastly, CDN77...) |
| `nsp` | Transit and network service providers |
| `ai` | AI/GPU-only cloud providers (CoreWeave, Lambda Labs, Crusoe, Voltage Park, Gcore...) |

`vps`, `cloud`, `dedicated`, `hosting` are aliases for `server`; `content` is an alias for `cdn`; `isp`, `transit` are aliases for `nsp`.

#### --preset values

| Preset | Best for |
|--------|---------|
| `balanced` (default) | General-purpose ranking |
| `performance` | Low latency and well-peered networks (latency 45%, peering 30%) |
| `security` | Clean reputation and RPKI validity (reputation 45%, RPKI 20%) |

#### Scoring (balanced)

| Factor | Weight | How it's calculated |
|--------|--------|---------------------|
| Latency | 30% | Concave quadratic decay: 0ms→1.00, 100ms→0.75, 200ms→0.00 |
| Peering | 20% | 70% IXP count (PeeringDB) + 30% upstream transit providers |
| Reputation | 25% | IPsum, ipapi.is, AbuseIPDB, GreyNoise, Spamhaus |
| Network size | 15% | Total IPv4 pool (log scale) |
| RPKI | 10% | Share of ROA-valid prefixes (RIPE Stat) |

When data is unavailable (no ping, no RPKI), its weight redistributes across the remaining components. Providers are not penalized for missing data.

### Examples

```bash
# Analyze
rover -a 8.8.8.8
rover -d github.com
rover -c 192.168.1.0/24
rover -o AS13335
rover -o "Hetzner"

# Discover providers
rover -r
rover -r Frankfurt
rover -r --country DE --max-ping 30 --top 10
rover -r --country DE,NL,FI --type server --top 20
rover -r --type cdn --top 10
rover -r --preset performance --max-ping 50
rover -r --preset security --type server

# IP list coverage
rover -r --type server --from targets.txt --sort coverage
rover -r --from https://example.com/iplist.txt --top 30

# Traceroute
rover -r --trace-to 8.8.8.8 --country DE
```

---

## 🔑 API keys

Optional keys extend reputation scoring in `-r` mode:

```
--set-key abuseipdb=KEY      AbuseIPDB (free at abuseipdb.com)
--set-key greynoise=KEY      GreyNoise  (free at greynoise.io)
--set-key peeringdb=KEY      PeeringDB  (free at peeringdb.com — raises rate limits)
--unset-key <service>        Remove a saved key
--list-keys                  Show all configured keys
```

Keys are stored in `%APPDATA%\rover\config.json` (Windows) or `~/.config/rover/config.json` (Linux/macOS).

For a one-off run without saving:
```bash
rover -r --abuseipdb-key YOUR_KEY --max-ping 100
```

---

## 📦 Data files

| File | Source | Size | TTL |
|------|--------|------|-----|
| `ip2asn-v4.tsv.gz` | iptoasn.com | ~10 MB | 7 days |
| `dbip-city.mmdb.gz` | db-ip.com | ~40 MB | 30 days |
| `ipsum.txt` | stamparm/ipsum | ~1 MB | 1 day |
| `ipcat-datacenters.csv` | ipcat | ~1 MB | 7 days |
| `cloud-provider-ip-addresses.json` | Various | ~1 MB | 7 days |
| `server-ip-addresses.csv` | Various | ~1 MB | 7 days |
| `asn-exclusions.json` | GitHub (this repo) | <1 KB | 14 days |

Stored in `~/.local/share/rover/data` (Linux/macOS) or `%APPDATA%\rover\data` (Windows).

**Optional:** Place a CAIDA AS Classification file at `as-classification.txt.gz` in the data directory to improve Enterprise/Transit network filtering in `-r` mode. The file is available after free registration at [data.caida.org](https://data.caida.org/datasets/as-classification/).

To override the path:
```bash
SUBNETSEARCH_DATA_DIR=/custom/path rover -a 1.2.3.4
```

---

## 🔨 Build from source

Requires [.NET 8 SDK](https://dotnet.microsoft.com/download).

```bash
git clone https://github.com/ambient88/rover.git
cd rover
dotnet run --project src/SubnetSearch.Cli -- -a 8.8.8.8
```

Self-contained binary:
```bash
dotnet publish src/SubnetSearch.Cli/SubnetSearch.Cli.csproj \
  -c Release -r linux-x64 --self-contained true \
  -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true \
  -o ./publish
```

Tests:
```bash
dotnet test
```

---

## 🙏 Acknowledgements

`rover` stands on the shoulders of the open-source community.  
We use third-party data for geolocation, ASN mapping, reputation scoring, and cloud provider detection.  
Full credits and license information are available in [ACKNOWLEDGEMENTS.md](ACKNOWLEDGEMENTS.md).

## 🤝 Contributing

Open issues and pull requests. All contributions welcome.

---

## 📜 License

MIT. See [LICENSE](LICENSE) for details.

---

## 📞 Contact

* Repository: [github.com/ambient88/rover](https://github.com/ambient88/rover)
* Email: [thriilerchiller123@gmail.com](mailto:thriilerchiller123@gmail.com)
