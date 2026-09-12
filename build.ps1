param(
    [switch]$Installer
)

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
        $signTool = (Get-Command signtool.exe -ErrorAction SilentlyContinue).Source
        if (-not $signTool) {
            $kitsRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
            $signTool = Get-ChildItem -Path $kitsRoot -Filter signtool.exe -File -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
                Sort-Object FullName -Descending |
                Select-Object -First 1 -ExpandProperty FullName
        }
        if (-not $signTool) { throw 'signtool.exe was not found' }
        & $signTool sign /sha1 $env:ZEROPASS_SIGN_THUMBPRINT /fd sha256 /tr http://timestamp.digicert.com /td sha256 ZeroPass.exe
        if ($LASTEXITCODE -ne 0) { throw 'Authenticode signing failed' }
    } else {
        Write-Warning 'ZEROPASS_SIGN_THUMBPRINT is not set; ZeroPass.exe is unsigned'
    }
    if ($Installer) {
        $iscc = (Get-Command ISCC.exe -ErrorAction SilentlyContinue).Source
        if (-not $iscc) {
            $iscc = Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'
        }
        if (-not (Test-Path -LiteralPath $iscc)) { throw 'Inno Setup 6 (ISCC.exe) was not found' }
        & $iscc .\installer.iss
        if ($LASTEXITCODE -ne 0) { throw 'Installer build failed' }

        if ($env:ZEROPASS_SIGN_THUMBPRINT) {
            $installerVersion = [regex]::Match((Get-Content -Raw .\installer.iss), '#define MyAppVersion "([^"]+)"').Groups[1].Value
            $installerPath = ".\dist\ZeroPassSetup-$installerVersion.exe"
            if (-not (Test-Path -LiteralPath $installerPath)) { throw 'Installer output was not found' }
            & $signTool sign /sha1 $env:ZEROPASS_SIGN_THUMBPRINT /fd sha256 /tr http://timestamp.digicert.com /td sha256 $installerPath
            if ($LASTEXITCODE -ne 0) { throw 'Installer Authenticode signing failed' }
        }
    }
} finally {
    Pop-Location
}
