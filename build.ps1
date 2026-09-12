$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    $env:CGO_ENABLED = '0'
    # The Go race detector requires CGO on windows/amd64, while ZeroPass is a
    # strict CGO_ENABLED=0 build. Run race tests only in a separate toolchain job.
    go test ./... -count=1
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
    go vet ./...
    if ($LASTEXITCODE -ne 0) { throw 'Vet failed' }
    go build -trimpath '-ldflags=-H=windowsgui' -o ZeroPass.exe .
    if ($LASTEXITCODE -ne 0) { throw 'Build failed; close the running ZeroPass first' }
} finally {
    Pop-Location
}
