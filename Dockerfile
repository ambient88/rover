# ── Stage 1: build self-contained binary ─────────────────────────────────────
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

COPY . .
RUN dotnet publish src/SubnetSearch.Cli/SubnetSearch.Cli.csproj \
        -c Release \
        -r linux-x64 \
        --self-contained true \
        -p:PublishSingleFile=true \
        -p:EnableCompressionInSingleFile=true \
        -o /app/publish

# ── Stage 2: minimal runtime image ───────────────────────────────────────────
# runtime-deps contains only the native libs needed for self-contained .NET apps.
FROM mcr.microsoft.com/dotnet/runtime-deps:8.0

# traceroute and iputils-ping are used by the traceroute / ping features.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        traceroute \
        iputils-ping \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /app/publish/rover ./rover
RUN chmod +x ./rover

# Data files are persisted in a volume so they survive container restarts.
# Mount a host directory: docker run -v ~/.local/share/rover/data:/data ...
ENV SUBNETSEARCH_DATA_DIR=/data
VOLUME ["/data"]

ENTRYPOINT ["./rover"]
