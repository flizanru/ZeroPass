$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    $env:CGO_ENABLED = '0'
    go test ./...
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
    go vet ./...
    if ($LASTEXITCODE -ne 0) { throw 'Vet failed' }
    go build -trimpath '-ldflags=-H=windowsgui' -o ZeroPass.exe .
    if ($LASTEXITCODE -ne 0) { throw 'Build failed; close the running ZeroPass first' }
    Copy-Item -LiteralPath third_party\libsodium\libsodium.dll -Destination libsodium.dll -Force
} finally {
    Pop-Location
}
