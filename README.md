# SubnetSearch

A command-line tool for classifying IP addresses, domains, and CIDR ranges. Identifies hosting providers, geolocation, reputation, network diagnostics, TLS/HTTP fingerprints, and ranks hosting providers worldwide.

## Features

- Hosting provider detection with type classification (VPS, Cloud, CDN, Dedicated, Colocation)
- ASN, organization, IP range, and RIR information
- Geolocation: country, city, region, coordinates, timezone (DB-IP)
- Reputation check against aggregated blocklists (IPsum)
- PTR / reverse DNS lookup
- PeeringDB integration: IXP count and exchange locations
- Ping with latency statistics and packet loss, VPN bypass
- Traceroute with per-hop latency
- Port scan (22, 80, 443, 3306, 8080, 8443)
- HTTP/TLS fingerprinting: CDN/WAF detection, server headers, certificate info
- Cloudflare product detection: WARP vs Tunnel vs Workers/Pages
- Domain classification: registrar, nameservers, WHOIS, hosting provider, service type
- Domain service type detection: proxy, VPN, hosting, CDN, etc.
- CIDR range batch classification
- Bulk processing from file (IPs and domains mixed)
- Provider scan by ASN or name: prefixes, upstreams, peerings
- **Provider recommendation** (`-r`): finds and ranks hosting providers worldwide using latency, RPKI, reputation, and network metrics

## Installation

### curl (Linux and macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/greshnik200ready2die/SubnetSearch/main/scripts/install.sh | bash
```

Installs the binary to `/usr/local/bin/subnetSearch`. Uses `sudo` only if the directory is not writable.

To install to a custom directory:

```bash
INSTALL_DIR=~/.local/bin curl -fsSL https://raw.githubusercontent.com/greshnik200ready2die/SubnetSearch/main/scripts/install.sh | bash
```

### apt (Debian / Ubuntu, amd64)

```bash
curl -fsSL https://greshnik200ready2die.github.io/SubnetSearch/gpg.key \
  | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/subnetSearch.gpg

echo "deb [arch=amd64] https://greshnik200ready2die.github.io/SubnetSearch/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/subnetSearch.list

sudo apt update && sudo apt install subnetSearch
```

### Docker

```bash
docker run --rm \
  -v ~/.local/share/SubnetSearch/data:/data \
  ghcr.io/greshnik200ready2die/subnetSearch -a 1.2.3.4
```

The `/data` volume persists downloaded data files (~500 MB) between runs.

### Manual download

Pre-built binaries for all platforms are available on the [Releases](https://github.com/greshnik200ready2die/SubnetSearch/releases) page.

| Platform | File |
|---|---|
| Linux x64 | `subnetSearch-linux-x64` |
| Linux ARM64 | `subnetSearch-linux-arm64` |
| Windows x64 | `subnetSearch-win-x64.exe` |
| macOS x64 | `subnetSearch-osx-x64` |
| macOS ARM64 (Apple Silicon) | `subnetSearch-osx-arm64` |

Make the binary executable on Linux and macOS:

```bash
chmod +x subnetSearch-linux-x64
./subnetSearch-linux-x64 -a 1.2.3.4
```

## Usage

### Analyze

```
subnetSearch -a <ip>         Classify a single IP address
subnetSearch -d <domain>     Classify a domain
subnetSearch -c <CIDR>       Classify a CIDR range
subnetSearch -l <file>       Batch classify from file (IPs or domains, one per line)
subnetSearch -o <ASN|name>   Scan a provider: prefixes, upstreams, peerings
--whois                      Force WHOIS lookups for each IP (slower, more detail)
```

### Discover providers

```
subnetSearch -r                        Find and rank hosting providers worldwide
subnetSearch -r <region>               Search by IXP region (e.g. Frankfurt, Amsterdam)
--type <type>                          Filter by provider type (see below)
--country <CC>                         Filter by country — comma-separated for multiple
--max-ping <ms>                        Only show providers below this latency
--top <N>                              Number of results (default: 20)
--sort <field>                         Sort order (default: score)
--preset <name>                        Scoring preset (default: balanced)
--from <path|url>                      Cross-reference results against a list of IPs
--trace-to <ip>                        Run traceroute and highlight providers in the route
```

#### --type values

| Value | What it returns |
|-------|----------------|
| `server` | VPS, dedicated, cloud — all server rental types |
| `vps` | Same as `server` |
| `cloud` | Same as `server` |
| `dedicated` | Same as `server` |
| `hosting` | Same as `server` |
| `cdn` | CDN and content delivery networks (Cloudflare, Akamai, Fastly, CDN77, …) |
| `content` | Same as `cdn` |
| `nsp` | Transit and network service providers |
| `isp` | Same as `nsp` |
| `transit` | Same as `nsp` |

#### --sort values

`score` (default), `coverage`, `latency`, `rpki`, `size`, `peering`, `upstream`

`coverage` requires `--from` — sorts by how many IPs from your list fall in each provider's range. Without `--from`, falls back to `score` with a warning. When `--from` is active, providers with high coverage are **pinned** into the result set even if their peering score is low — they will appear regardless of the scoring cutoff.

`latency` falls back to `score` when ICMP is blocked and no latency was measured.

#### --preset values

| Preset | Best for |
|--------|---------|
| `balanced` (default) | General-purpose ranking |
| `performance` | Prioritizes low latency and well-peered networks (latency 45%, peering 30%) |
| `security` | Prioritizes clean reputation and RPKI validity (reputation 45%, RPKI 20%) |

#### --country values

ISO 3166-1 alpha-2 codes (2 letters). Comma-separated for multiple countries.

```bash
subnetSearch -r --country DE
subnetSearch -r --country DE,NL,FI --type server
```

Country data is resolved from ip2asn — all providers found by PeeringDB are enriched before filtering.

### Scoring

Provider scoring uses a weighted formula. Weights depend on the active preset and adjust automatically when data is unavailable — a provider without a ping result is not penalized; its latency weight redistributes to other components.

**Default weights (balanced):**

| Factor | Weight | Notes |
|--------|--------|-------|
| Latency | 30% | Average ping; penalized by packet loss |
| Peering | 20% | Number of IXP connections (PeeringDB) |
| Reputation | 25% | IPsum, ipapi.is, AbuseIPDB, GreyNoise, Spamhaus DROP |
| Network size | 15% | Total IPv4 address pool (log scale) |
| RPKI | 10% | Ratio of ROA-valid prefixes (RIPE Stat) |

### --from: coverage analysis

Pass a file or URL containing IP addresses to see which providers cover those IPs:

```bash
# From a local file
subnetSearch -r --type server --from targets.txt

# From a URL (GitHub raw, plain text)
subnetSearch -r --type server --from https://example.com/iplist.txt --sort coverage

# GitHub blob URLs are automatically converted to raw
subnetSearch -r --from https://github.com/user/repo/blob/main/ips.txt
```

Each provider in the results shows a **Coverage** line with the count and percentage of IPs from your list that fall within its address space, plus a density figure (hits per million IPs). ASNs found in your list but not yet in the main results are automatically supplemented.

When `--sort coverage` is used with `--from`, the top providers by coverage count are **pinned** into the result set: they appear even if their peering score would normally exclude them from the top-N. This ensures that cloud providers with few IXP peerings but significant coverage of your IP list are always visible.

### Configure API keys

Optional API keys unlock deeper reputation scoring for `-r`:

```
--set-key abuseipdb=KEY      Save AbuseIPDB API key (free at abuseipdb.com)
--set-key greynoise=KEY      Save GreyNoise API key (free at greynoise.io)
--set-key peeringdb=KEY      Save PeeringDB API key (free at peeringdb.com — raises rate limits)
--unset-key <service>        Remove a saved key
--list-keys                  Show all configured keys
```

Keys are stored in `%APPDATA%\subnetSearch\config.json` (Windows) or `~/.config/subnetSearch/config.json` (Linux/macOS).

Use inline keys for a single run without saving:

```
--abuseipdb-key <key>        Use AbuseIPDB key for this run only
--greynoise-key <key>        Use GreyNoise key for this run only
--peeringdb-key <key>        Use PeeringDB key for this run only
```

### Examples

```bash
# Analyze
subnetSearch -a 8.8.8.8
subnetSearch -d github.com
subnetSearch -c 192.168.1.0/24
subnetSearch -l targets.txt
subnetSearch -o AS13335
subnetSearch -o "Hetzner"
subnetSearch -a 1.2.3.4 --whois

# Recommend providers — basic
subnetSearch -r
subnetSearch -r Frankfurt
subnetSearch -r --country DE --max-ping 30 --top 10
subnetSearch -r --country DE,NL,FI --type server --top 20

# Recommend by type
subnetSearch -r --type cdn --top 10
subnetSearch -r --type nsp --country US

# Recommend providers — with IP list
subnetSearch -r --type server --from targets.txt --sort coverage
subnetSearch -r --from https://example.com/whitelist.txt --top 30

# Scoring presets
subnetSearch -r --preset performance --max-ping 50
subnetSearch -r --preset security --type server

# Traceroute integration
subnetSearch -r --trace-to 8.8.8.8 --country DE

# API keys
subnetSearch --set-key abuseipdb=YOUR_KEY
subnetSearch --set-key peeringdb=YOUR_KEY
subnetSearch --list-keys
subnetSearch -r --abuseipdb-key YOUR_KEY --max-ping 100
```

## Data files

On first run, SubnetSearch downloads the following files automatically:

| File | Source | Size | TTL |
|---|---|---|---|
| ip2asn-v4.tsv.gz | iptoasn.com | ~10 MB | 7 days |
| dbip-city.mmdb.gz | db-ip.com | ~40 MB | 30 days |
| ipsum.txt | stamparm/ipsum | ~1 MB | 1 day |
| ipcat-datacenters.csv | ipcat | ~1 MB | 7 days |
| cloud-provider-ip-addresses.json | Various | ~1 MB | 7 days |
| server-ip-addresses.csv | Various | ~1 MB | 7 days |
| asn-exclusions.json | GitHub (this repo) | <1 KB | 14 days |

A `ripe_cache.json` file is written to the same directory after the first `-r` run. It caches RIPE Stat prefix and neighbour data for 24 hours, making subsequent runs significantly faster.

Files are stored in `~/.local/share/SubnetSearch/data` on Linux and macOS, and `%APPDATA%\SubnetSearch\data` on Windows. To override:

```bash
SUBNETSEARCH_DATA_DIR=/custom/path subnetSearch -a 1.2.3.4
```

## Build from source

Requires [.NET 8 SDK](https://dotnet.microsoft.com/download).

```bash
git clone https://github.com/greshnik200ready2die/SubnetSearch.git
cd SubnetSearch
dotnet run --project src/SubnetSearch.Cli -- -a 8.8.8.8
```

Self-contained binary:

```bash
dotnet publish src/SubnetSearch.Cli/SubnetSearch.Cli.csproj \
  -c Release -r linux-x64 --self-contained true \
  -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true \
  -o ./publish
```

Run tests:

```bash
dotnet test
```

## License

MIT
