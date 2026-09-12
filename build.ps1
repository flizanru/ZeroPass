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
    if ($env:ZEROPASS_SIGN_THUMBPRINT) {
        & signtool sign /sha1 $env:ZEROPASS_SIGN_THUMBPRINT /fd sha256 /tr http://timestamp.digicert.com /td sha256 ZeroPass.exe
        if ($LASTEXITCODE -ne 0) { throw 'Authenticode signing failed' }
    } else {
        Write-Warning 'ZEROPASS_SIGN_THUMBPRINT is not set; ZeroPass.exe is unsigned'
    }
} finally {
    Pop-Location
}
