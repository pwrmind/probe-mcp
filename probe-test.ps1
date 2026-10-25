# Force UTF-8 for the console so "→" and Cyrillic render correctly
# (probe writes UTF-8 to stdout; Windows console defaults to CP866/CP1251,
#  which turns "→" into "тЖТ").
chcp 65001 | Out-Null
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$exe    = (Resolve-Path ".\target\i686-pc-windows-msvc\release\probe-mcp.exe").Path
$target = (Resolve-Path ".\crackme\crackme.dll").Path

$init  = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"diag","version":"0.1"}}}'
$notif = '{"jsonrpc":"2.0","method":"notifications/initialized"}'

# probe_open request. Built with ConvertTo-Json so Windows backslashes in
# $target are escaped correctly regardless of the path.
$open = @{
    jsonrpc = "2.0"
    id      = 0
    method  = "tools/call"
    params  = @{
        name      = "probe_open"
        arguments = @{ path = $target }
    }
} | ConvertTo-Json -Compress -Depth 10

# =========================================================================
# Batch runner: все запросы известны заранее.
#
# probe_open вставляется автоматически сразу после $notif — сам агент
# его не передаёт (это соответствует реальному поведению: агент вызывает
# probe_open первым, а тест просто инкапсулирует этот шаг).
# =========================================================================
function Run([string]$name, [string[]]$reqs) {
  Write-Host ""
  Write-Host "=== $name ===" -ForegroundColor Cyan
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $exe; $psi.Arguments = ""
  $psi.RedirectStandardInput  = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
  $p = [System.Diagnostics.Process]::Start($psi)

  # $reqs[0] = init, $reqs[1] = notif. Insert $open at index 2.
  $final = @()
  $final += $reqs[0]
  if ($reqs.Count -gt 1) { $final += $reqs[1] }
  $final += $open
  if ($reqs.Count -gt 2) { $final += $reqs[2..($reqs.Count - 1)] }

  $p.StandardInput.Write(($final -join "`r`n") + "`r`n")
  $p.StandardInput.Close()
  $out = $p.StandardOutput.ReadToEnd()
  $err = $p.StandardError.ReadToEnd()
  $p.WaitForExit(5000) | Out-Null
  Write-Host "--- STDOUT (raw) ---"
  $out -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { Write-Host $_ }
  Write-Host "--- STDERR ---" -ForegroundColor Yellow
  $err -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { Write-Host $_ }
}

# =========================================================================
# Sequential runner: каждый следующий запрос может зависеть от предыдущих
# ответов (например, probe_poke по адресу из probe_alloc).
#
# $NextRequest получает массив уже полученных ответов (строки) и
# возвращает следующий JSON-запрос — или $null, чтобы закончить.
#
# $responses[0] = initialize. probe_open выполняется до цикла и в массив
# НЕ попадает, чтобы callbacks оставались простыми.
# =========================================================================
function Run-Seq {
  param(
    [string]$Name,
    [scriptblock]$NextRequest
  )
  Write-Host ""
  Write-Host "=== $Name ===" -ForegroundColor Cyan
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $exe; $psi.Arguments = ""
  $psi.RedirectStandardInput  = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
  $p = [System.Diagnostics.Process]::Start($psi)

  $responses = New-Object System.Collections.ArrayList

  # initialize (ждём ответ)
  $p.StandardInput.Write($init + "`r`n"); $p.StandardInput.Flush()
  $r = $p.StandardOutput.ReadLine()
  [void]$responses.Add($r)
  Write-Host "--- RESP init ---"; Write-Host $r

  # notifications/initialized (НЕ ждём ответа — сервер на нотификации
  # не отвечает, иначе ReadLine() завис бы)
  $p.StandardInput.Write($notif + "`r`n"); $p.StandardInput.Flush()

  # probe_open (ждём ответ, в $responses НЕ кладём — это служебный шаг)
  Write-Host "--- REQ open ---"; Write-Host $open
  $p.StandardInput.Write($open + "`r`n"); $p.StandardInput.Flush()
  $open_resp = $p.StandardOutput.ReadLine()
  if ($null -eq $open_resp) { Write-Host "(no response to probe_open — server closed?)"; return }
  Write-Host "--- RESP open ---"; Write-Host $open_resp

  $idx = 2
  while ($true) {
    $next = & $NextRequest $responses
    if ([string]::IsNullOrEmpty($next)) { break }

    Write-Host "--- REQ $idx ---"; Write-Host $next
    $p.StandardInput.Write($next + "`r`n"); $p.StandardInput.Flush()

    $resp = $p.StandardOutput.ReadLine()
    if ($null -eq $resp) { Write-Host "(no response — server closed?)"; break }
    [void]$responses.Add($resp)
    Write-Host "--- RESP $idx ---"; Write-Host $resp
    $idx++
    if ($idx -gt 30) { Write-Host "(safety stop after 30 requests)"; break }
  }

  $p.StandardInput.Close()
  $err = $p.StandardError.ReadToEnd()
  $p.WaitForExit(5000) | Out-Null
  if ($err.Trim()) {
    Write-Host "--- STDERR ---" -ForegroundColor Yellow
    $err -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { Write-Host $_ }
  }
}

# =========================================================================
# 1. Какие функции вообще видны серверу?
# =========================================================================
Run "list-functions (search crash/verify/decrypt)" @(
  $init, $notif
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"probe_list_functions","arguments":{"name_contains":"crash"}}}'
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"probe_list_functions","arguments":{"name_contains":"verify"}}}'
  '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"probe_list_functions","arguments":{"name_contains":"decrypt"}}}'
)

# =========================================================================
# 2. Одиночный crash_null_deref — какая ошибка?
# =========================================================================
Run "crash_null_deref alone" @(
  $init, $notif
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"probe_invoke","arguments":{"target":"crash_null_deref"}}}'
)

# =========================================================================
# 3. Одиночный verify_serial_timing — какая ошибка?
# =========================================================================
Run "verify_serial_timing alone" @(
  $init, $notif
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"probe_invoke","arguments":{"target":"verify_serial_timing","args":[{"type":"string","value":"AAAAAAA"}]}}}'
)

# =========================================================================
# 4. decrypt_inplace БЕЗ watch_diff: alloc → poke → invoke(len=8) → peek
# =========================================================================
Run-Seq "decrypt_inplace without watch_diff (chained)" {
  param($responses)

  # responses[0] = initialize
  # responses[1] = probe_alloc
  # responses[2] = probe_poke
  # responses[3] = probe_invoke
  # responses[4] = probe_peek

  if ($responses.Count -eq 1) {
    return '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"probe_alloc","arguments":{"size":16}}}'
  }

  if ($responses.Count -eq 2) {
    try {
      $addr = ($responses[1] | ConvertFrom-Json).result.structuredContent.address
    } catch {
      Write-Host "(alloc failed, cannot continue)" -ForegroundColor Red
      return $null
    }
    Write-Host "(allocated at $addr)"
    return '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"probe_poke","arguments":{"address":"' + $addr + '","hex":"595B464B4C1D1B29"}}}'
  }

  if ($responses.Count -eq 3) {
    $addr = ($responses[1] | ConvertFrom-Json).result.structuredContent.address
    return '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"probe_invoke","arguments":{"target":"decrypt_inplace","args":[{"type":"pointer","value":"' + $addr + '"},{"type":"int","value":"8"}]}}}'
  }

  if ($responses.Count -eq 4) {
    $addr = ($responses[1] | ConvertFrom-Json).result.structuredContent.address
    return '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"probe_peek","arguments":{"address":"' + $addr + '","size":16}}}'
  }

  return $null
}