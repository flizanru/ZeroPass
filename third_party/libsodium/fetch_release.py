"""Fetch the pinned official release in bounded HTTP ranges; verify with minisign before use."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import subprocess
import zipfile

BASE = "https://download.libsodium.org/libsodium/releases/"
NAME = "libsodium-1.0.22-msvc.zip"
SIZE = 17690194
CHUNK = 12000
ROOT = Path(__file__).resolve().parent

def fetch(start):
    end = min(start + CHUNK, SIZE) - 1
    for attempt in range(3):
        try:
            data = subprocess.check_output([
                "curl.exe", "-sSfL", "--max-time", "15", "--range", f"{start}-{end}", BASE + NAME
            ])
            if len(data) != end - start + 1:
                raise RuntimeError("Truncated release download or unsupported range")
            return data
        except Exception:
            if attempt == 2:
                raise

if __name__ == "__main__":
    with ThreadPoolExecutor(max_workers=16) as pool:
        parts = list(pool.map(fetch, range(0, SIZE, CHUNK)))
    archive = ROOT / NAME
    archive.write_bytes(b"".join(parts))
    signature = subprocess.check_output(["curl.exe", "-sSfL", "--max-time", "15", BASE + NAME + ".minisig"])
    Path(str(archive) + ".minisig").write_bytes(signature)
    subprocess.run([
        "go", "run", "aead.dev/minisign/cmd/minisign@v0.3.0", "-Vm", str(archive),
        "-P", "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3",
    ], check=True)
    with zipfile.ZipFile(archive) as package:
        (ROOT / "upstream-static.lib").write_bytes(package.read("libsodium/x64/Release/v143/static/libsodium.lib"))
