$exe    = (Resolve-Path ".\target\i686-pc-windows-msvc\release\probe-mcp.exe").Path
$target = (Resolve-Path ".\crackme\crackme.dll").Path

function Run($name, [string[]]$reqs) {
  Write-Host ""
  Write-Host "=== $name ===" -ForegroundColor Cyan
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $exe; $psi.Arguments = "`"$target`""
  $psi.RedirectStandardInput  = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
  $p = [System.Diagnostics.Process]::Start($psi)
  $p.StandardInput.Write(($reqs -join "`r`n") + "`r`n")
  $p.StandardInput.Close()
  $out = $p.StandardOutput.ReadToEnd()
  $err = $p.StandardError.ReadToEnd()
  $p.WaitForExit(5000) | Out-Null
  Write-Host "--- STDOUT (raw) ---"
  $out -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { Write-Host $_ }
  Write-Host "--- STDERR ---" -ForegroundColor Yellow
  $err -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { Write-Host $_ }
}

$init  = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"diag","version":"0.1"}}}'
$notif = '{"jsonrpc":"2.0","method":"notifications/initialized"}'

# 1. какие функции вообще видны серверу?
Run "list-functions (search crash/verify/decrypt)" @(
  $init, $notif
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"probe_list_functions","arguments":{"name_contains":"crash"}}}'
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"probe_list_functions","arguments":{"name_contains":"verify"}}}'
  '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"probe_list_functions","arguments":{"name_contains":"decrypt"}}}'
)

# 2. одиночный crash_null_deref — какая ошибка?
Run "crash_null_deref alone" @(
  $init, $notif
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"probe_invoke","arguments":{"target":"crash_null_deref"}}}'
)

# 3. одиночный verify_serial_timing — какая ошибка?
Run "verify_serial_timing alone" @(
  $init, $notif
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"probe_invoke","arguments":{"target":"verify_serial_timing","args":[{"type":"string","value":"AAAAAAA"}]}}}'
)

# 4. decrypt_inplace без watch_diff — какая ошибка?
Run "decrypt_inplace no-diff" @(
  $init, $notif
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"probe_alloc","arguments":{"size":16}}}'
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"probe_poke","arguments":{"address":"0xPLACEHOLDER","hex":"595B464B4C1D1B29"}}}'
)