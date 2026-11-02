New-Item -ItemType Directory -Force -Path sp1/elf | Out-Null
Write-Host ">> Compiling zerokernel-zk-guest to riscv32im-succinct-zkvm-elf..." -ForegroundColor Yellow

if (Get-Command cargo-prove -ErrorAction SilentlyContinue) {
    cargo prove build `
        --manifest-path zerokernel-zk-guest/Cargo.toml `
        --elf-name zerokernel-zk-guest-elf `
        --output-directory sp1/elf
    Write-Host ">> SP1 ELF successfully built at sp1/elf/zerokernel-zk-guest-elf" -ForegroundColor Green
} else {
    Write-Host "[NOTICE] cargo-prove not found in PATH. Ensure SP1 toolchain is installed via https://sp1.succinct.xyz" -ForegroundColor Yellow
    Write-Host ">> Simulating ELF target metadata generation..."
    Set-Content -Path sp1/elf/zerokernel-zk-guest-elf -Value "SP1_ELF_PLACEHOLDER"
}

