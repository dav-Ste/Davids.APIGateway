# Build from workspace parent directory so sibling ../Davids.Shared is in build context:
#   docker build -f Davids.APIGateway/Dockerfile -t ghcr.io/davids/davids-api-gateway:1.0.0 .
FROM mcr.microsoft.com/dotnet/sdk:10.0-noble AS build
WORKDIR /workspace

COPY Davids.Shared/Directory.Build.props Davids.Shared/Directory.Packages.props Davids.Shared/global.json ./Davids.Shared/
COPY Davids.Shared/eng/ ./Davids.Shared/eng/
COPY Davids.Shared/src/Davids.ServiceDefaults/Davids.ServiceDefaults.csproj Davids.Shared/src/Davids.ServiceDefaults/packages.lock.json ./Davids.Shared/src/Davids.ServiceDefaults/
COPY Davids.APIGateway/Directory.Build.props Davids.APIGateway/Directory.Packages.props Davids.APIGateway/global.json ./Davids.APIGateway/
COPY Davids.APIGateway/src/Davids.APIGateway.Infrastructure/Davids.APIGateway.Infrastructure.csproj Davids.APIGateway/src/Davids.APIGateway.Infrastructure/packages.lock.json ./Davids.APIGateway/src/Davids.APIGateway.Infrastructure/
COPY Davids.APIGateway/src/Davids.APIGateway.Api/Davids.APIGateway.Api.csproj Davids.APIGateway/src/Davids.APIGateway.Api/packages.lock.json ./Davids.APIGateway/src/Davids.APIGateway.Api/

RUN dotnet restore ./Davids.APIGateway/src/Davids.APIGateway.Api/Davids.APIGateway.Api.csproj --locked-mode

COPY Davids.Shared/src/Davids.ServiceDefaults/ ./Davids.Shared/src/Davids.ServiceDefaults/
COPY Davids.APIGateway/src/ ./Davids.APIGateway/src/

RUN dotnet publish ./Davids.APIGateway/src/Davids.APIGateway.Api/Davids.APIGateway.Api.csproj \
      --no-restore -c Release /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble AS runtime
WORKDIR /app
ENV ASPNETCORE_HTTP_PORTS=8080 \
    DOTNET_EnableDiagnostics=0

COPY --from=build --chown=10001:10001 /workspace/Davids.APIGateway/artifacts/publish/Davids.APIGateway.Api/release .
USER 10001:10001
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["dotnet", "--info"]

ENTRYPOINT ["dotnet", "Davids.APIGateway.Api.dll"]
