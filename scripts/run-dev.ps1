$ErrorActionPreference = "Stop"

Set-Location "$PSScriptRoot\.."

$env:APP_CONFIG_PATH = "config/development.yaml"
$env:RUST_LOG = "info"

cargo run