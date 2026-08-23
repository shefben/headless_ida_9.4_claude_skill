$ErrorActionPreference = "Stop"

$skillsDir = Join-Path $HOME ".claude\skills"
$targetDir = Join-Path $skillsDir "ida-headless-analysis"

if (-not (Test-Path $skillsDir)) {
    New-Item -ItemType Directory -Force -Path $skillsDir | Out-Null
}

Write-Host "Installing skill folder to $targetDir..."
Copy-Item -Path "ida-headless-analysis" -Destination $targetDir -Recurse -Force

Write-Host "Searching for IDA 9.2, 9.3, or 9.4 in environment variables..."
$idaPaths = @()
foreach ($envVar in (Get-ChildItem Env:)) {
    $paths = $envVar.Value -split ";"
    foreach ($p in $paths) {
        if ($p -match "ida" -and $p -match "9\.[234]") {
            if (Test-Path $p) {
                $dir = if ((Get-Item $p) -is [System.IO.FileInfo]) { Split-Path $p } else { $p }
                if ((Test-Path (Join-Path $dir "ida.exe")) -or (Test-Path (Join-Path $dir "ida64.exe")) -or (Test-Path (Join-Path $dir "idat.exe")) -or (Test-Path (Join-Path $dir "idat64.exe"))) {
                    if ($idaPaths -notcontains $dir) {
                        $idaPaths += $dir
                    }
                }
            }
        }
    }
}

$selectedIda = $null
if ($idaPaths.Count -eq 0) {
    $selectedIda = Read-Host "No IDA 9.2, 9.3, or 9.4 found in environment variables. Please enter the path to the IDA folder manually"
} elseif ($idaPaths.Count -eq 1) {
    Write-Host "Found IDA at: $($idaPaths[0])"
    $selectedIda = $idaPaths[0]
} else {
    Write-Host "Multiple IDA installations found:"
    for ($i = 0; $i -lt $idaPaths.Count; $i++) {
        Write-Host "[$($i + 1)] $($idaPaths[$i])"
    }
    $selection = 0
    while ($selection -lt 1 -or $selection -gt $idaPaths.Count) {
        $input = Read-Host "Select the correct one by typing the corresponding number"
        if ([int]::TryParse($input, [ref]$selection)) {
            if ($selection -lt 1 -or $selection -gt $idaPaths.Count) {
                Write-Host "Invalid selection. Please try again."
            }
        }
    }
    $selectedIda = $idaPaths[$selection - 1]
}

Write-Host "Searching for Python 3.13.* in environment variables..."
$pythonPaths = @()
foreach ($envVar in (Get-ChildItem Env:)) {
    $paths = $envVar.Value -split ";"
    foreach ($p in $paths) {
        if (Test-Path $p) {
            $pyExe = if ((Get-Item $p) -is [System.IO.FileInfo]) { $p } else { Join-Path $p "python.exe" }
            if (Test-Path $pyExe) {
                try {
                    $ver = & $pyExe -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
                    if ($ver -eq "3.13") {
                        if ($pythonPaths -notcontains $pyExe) {
                            $pythonPaths += $pyExe
                        }
                    }
                } catch {}
            }
        }
    }
}

$selectedPython = $null
if ($pythonPaths.Count -eq 0) {
    $selectedPython = Read-Host "No Python 3.13.* found. Please enter the path to the python.exe binary manually"
} elseif ($pythonPaths.Count -eq 1) {
    Write-Host "Found Python at: $($pythonPaths[0])"
    $selectedPython = $pythonPaths[0]
} else {
    Write-Host "Multiple Python 3.13.* installations found:"
    for ($i = 0; $i -lt $pythonPaths.Count; $i++) {
        Write-Host "[$($i + 1)] $($pythonPaths[$i])"
    }
    $selection = 0
    while ($selection -lt 1 -or $selection -gt $pythonPaths.Count) {
        $input = Read-Host "Select the correct one by typing the corresponding number"
        if ([int]::TryParse($input, [ref]$selection)) {
            if ($selection -lt 1 -or $selection -gt $pythonPaths.Count) {
                Write-Host "Invalid selection. Please try again."
            }
        }
    }
    $selectedPython = $pythonPaths[$selection - 1]
}

Write-Host "Replacing variables in $targetDir..."
$files = Get-ChildItem -Path $targetDir -File -Recurse
foreach ($file in $files) {
    $content = Get-Content $file.FullName -Raw
    if ($content -match "%PYTHON_BIN_PATH%" -or $content -match "%IDA_PATH%") {
        $content = $content.Replace("%PYTHON_BIN_PATH%", $selectedPython)
        $content = $content.Replace("%IDA_PATH%", $selectedIda)
        Set-Content -Path $file.FullName -Value $content -NoNewline
    }
}

$env:IDADIR = $selectedIda

Write-Host "Installing/Upgrading ida-domain module..."
& $selectedPython -m pip install --upgrade "ida-domain>=0.5.0,<0.6.0"
if ($LASTEXITCODE -ne 0) { throw "ida-domain upgrade failed" }

Write-Host "Installing requirements from requirements.txt..."
if (Test-Path "requirements.txt") {
    & $selectedPython -m pip install -r "requirements.txt"
    if ($LASTEXITCODE -ne 0) { throw "requirements.txt installation failed" }
}

& $selectedPython -c "import ida_domain, idapro; print('ida-domain/idapro import OK')"
if ($LASTEXITCODE -ne 0) { throw "IDA Python verification failed" }

Write-Host "Setup complete. IDADIR=$env:IDADIR"
Write-Host "Skill installed to $targetDir"
