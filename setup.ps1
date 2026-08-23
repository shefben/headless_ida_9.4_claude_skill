$ErrorActionPreference = "Stop"

$skillsDir = Join-Path $HOME ".claude\skills"
$targetDir = Join-Path $skillsDir "ida-headless-analysis"
$sourceSkillDir = Join-Path $PSScriptRoot "ida-headless-analysis"
$requirementsFile = Join-Path $PSScriptRoot "requirements.txt"

function Normalize-CandidatePath {
    param([AllowNull()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }

    $candidate = [Environment]::ExpandEnvironmentVariables($Path.Trim())
    $candidate = $candidate.Trim('"').Trim()
    if ([string]::IsNullOrWhiteSpace($candidate)) { return $null }

    return $candidate
}

function Normalize-DirectoryPath {
    param([AllowNull()][string]$Path)

    $candidate = Normalize-CandidatePath $Path
    if ([string]::IsNullOrWhiteSpace($candidate)) { return $null }

    try {
        $full = [System.IO.Path]::GetFullPath($candidate)
    } catch {
        $full = $candidate
    }

    # idapro generates Python code containing IDAPYTHON_DYNLOAD_BASE as a raw string.
    # A Windows directory ending in a single backslash (r"F:\\IDA\\") is invalid Python
    # because the final backslash escapes the quote. Keep filesystem roots intact, but strip
    # trailing separators from ordinary directories before exporting IDADIR or replacing tokens.
    try {
        $root = [System.IO.Path]::GetPathRoot($full)
        if (-not [string]::IsNullOrWhiteSpace($root) -and
            [string]::Equals($full, $root, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $full
        }
    } catch { }

    return $full.TrimEnd([char[]]'\/')
}

function Add-UniquePath {
    param(
        [System.Collections.Generic.List[string]]$List,
        [string]$Path
    )
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    foreach ($existing in $List) {
        if ([string]::Equals($existing, $Path, [System.StringComparison]::OrdinalIgnoreCase)) {
            return
        }
    }
    $List.Add($Path)
}

function Get-EnvironmentPathCandidates {
    foreach ($envVar in (Get-ChildItem Env:)) {
        foreach ($raw in ($envVar.Value -split ";")) {
            $candidate = Normalize-CandidatePath $raw
            if ($candidate) { $candidate }
        }
    }
}

if (-not (Test-Path -LiteralPath $skillsDir -PathType Container)) {
    New-Item -ItemType Directory -Force -Path $skillsDir | Out-Null
}
if (-not (Test-Path -LiteralPath $sourceSkillDir -PathType Container)) {
    throw "Skill source folder was not found: $sourceSkillDir"
}

Write-Host "Installing skill folder to $targetDir..."
if (Test-Path -LiteralPath $targetDir) {
    Remove-Item -LiteralPath $targetDir -Recurse -Force
}
Copy-Item -LiteralPath $sourceSkillDir -Destination $targetDir -Recurse -Force

Write-Host "Searching for IDA 9.4 (with 9.2/9.3 compatibility fallback) in environment variables..."
$idaPaths = [System.Collections.Generic.List[string]]::new()
foreach ($candidate in (Get-EnvironmentPathCandidates)) {
    if ($candidate -notmatch "(?i)ida") { continue }
    if ($candidate -notmatch "9\.[234]") { continue }

    try {
        $dir = $null
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            $dir = Split-Path -Parent $candidate
        } elseif (Test-Path -LiteralPath $candidate -PathType Container) {
            $dir = $candidate
        } else {
            continue
        }

        $hasIda = $false
        foreach ($exe in @("ida.exe", "ida64.exe", "idat.exe", "idat64.exe")) {
            if (Test-Path -LiteralPath (Join-Path $dir $exe) -PathType Leaf) {
                $hasIda = $true
                break
            }
        }
        if ($hasIda) {
            $resolved = Normalize-DirectoryPath ((Resolve-Path -LiteralPath $dir -ErrorAction Stop).Path)
            Add-UniquePath -List $idaPaths -Path $resolved
        }
    } catch {
        continue
    }
}

$idaPaths = @($idaPaths | Sort-Object @{Expression={ if ($_ -match "9\.4") { 0 } elseif ($_ -match "9\.3") { 1 } else { 2 } }}, @{Expression={$_}})

$selectedIda = $null
if ($idaPaths.Count -eq 0) {
    $selectedIda = Normalize-DirectoryPath (Read-Host "No IDA 9.2, 9.3, or 9.4 found in environment variables. Please enter the path to the IDA folder manually")
} elseif ($idaPaths.Count -eq 1) {
    Write-Host "Found IDA at: $($idaPaths[0])"
    $selectedIda = $idaPaths[0]
} else {
    Write-Host "Multiple IDA installations found (9.4 preferred):"
    for ($i = 0; $i -lt $idaPaths.Count; $i++) {
        Write-Host "[$($i + 1)] $($idaPaths[$i])"
    }
    $selection = 0
    while ($selection -lt 1 -or $selection -gt $idaPaths.Count) {
        $inputValue = Read-Host "Select the correct one by typing the corresponding number"
        if ([int]::TryParse($inputValue, [ref]$selection)) {
            if ($selection -lt 1 -or $selection -gt $idaPaths.Count) {
                Write-Host "Invalid selection. Please try again."
            }
        }
    }
    $selectedIda = $idaPaths[$selection - 1]
}

# Canonicalize once more after selection so manual input and discovered paths obey the same rule.
$selectedIda = Normalize-DirectoryPath $selectedIda
if ([string]::IsNullOrWhiteSpace($selectedIda) -or -not (Test-Path -LiteralPath $selectedIda -PathType Container)) {
    throw "Selected IDA directory does not exist: $selectedIda"
}
Write-Host "Using canonical IDA path: $selectedIda"
if ($selectedIda -notmatch "9\.4") {
    Write-Warning "Selected IDA path does not appear to be IDA 9.4: $selectedIda. The skill targets IDA 9.4; 9.2/9.3 are compatibility fallbacks only."
}

Write-Host "Searching for Python 3.13.*..."
$pythonPaths = [System.Collections.Generic.List[string]]::new()

foreach ($commandName in @("python3.13.exe", "python.exe", "python3.exe")) {
    try {
        $commands = @(Get-Command $commandName -CommandType Application -All -ErrorAction SilentlyContinue)
        foreach ($cmd in $commands) {
            if ($null -eq $cmd -or [string]::IsNullOrWhiteSpace($cmd.Source)) { continue }
            $pyExe = $cmd.Source
            try {
                $ver = (& $pyExe -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null).Trim()
                if ($LASTEXITCODE -eq 0 -and $ver -eq "3.13") {
                    Add-UniquePath -List $pythonPaths -Path ((Resolve-Path -LiteralPath $pyExe -ErrorAction Stop).Path)
                }
            } catch { continue }
        }
    } catch { }
}

foreach ($candidate in (Get-EnvironmentPathCandidates)) {
    try {
        $pyExe = $null
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            if ([System.IO.Path]::GetFileName($candidate) -match "(?i)^python(?:3(?:\.13)?)?\.exe$") {
                $pyExe = $candidate
            }
        } elseif (Test-Path -LiteralPath $candidate -PathType Container) {
            $maybe = Join-Path $candidate "python.exe"
            if (Test-Path -LiteralPath $maybe -PathType Leaf) {
                $pyExe = $maybe
            }
        } else {
            continue
        }

        if ($pyExe) {
            $ver = (& $pyExe -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null).Trim()
            if ($LASTEXITCODE -eq 0 -and $ver -eq "3.13") {
                Add-UniquePath -List $pythonPaths -Path ((Resolve-Path -LiteralPath $pyExe -ErrorAction Stop).Path)
            }
        }
    } catch {
        continue
    }
}

$selectedPython = $null
if ($pythonPaths.Count -eq 0) {
    $selectedPython = Normalize-CandidatePath (Read-Host "No Python 3.13.* found. Please enter the path to python.exe manually")
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
        $inputValue = Read-Host "Select the correct one by typing the corresponding number"
        if ([int]::TryParse($inputValue, [ref]$selection)) {
            if ($selection -lt 1 -or $selection -gt $pythonPaths.Count) {
                Write-Host "Invalid selection. Please try again."
            }
        }
    }
    $selectedPython = $pythonPaths[$selection - 1]
}

if ([string]::IsNullOrWhiteSpace($selectedPython) -or -not (Test-Path -LiteralPath $selectedPython -PathType Leaf)) {
    throw "Selected Python executable does not exist: $selectedPython"
}
$selectedPythonVersion = (& $selectedPython -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null).Trim()
if ($LASTEXITCODE -ne 0 -or $selectedPythonVersion -ne "3.13") {
    throw "Selected Python must be Python 3.13.x; got '$selectedPythonVersion' from $selectedPython"
}

Write-Host "Replacing variables in $targetDir..."
$textExtensions = @(".md", ".py", ".json", ".txt", ".toml", ".yaml", ".yml", ".ini", ".cfg", ".ps1", ".sh")
$files = Get-ChildItem -LiteralPath $targetDir -File -Recurse | Where-Object {
    $textExtensions -contains $_.Extension.ToLowerInvariant()
}
foreach ($file in $files) {
    $content = Get-Content -LiteralPath $file.FullName -Raw
    if ($content -match "%PYTHON_BIN_PATH%" -or $content -match "%IDA_PATH%") {
        $content = $content.Replace("%PYTHON_BIN_PATH%", $selectedPython)
        $content = $content.Replace("%IDA_PATH%", $selectedIda)
        Set-Content -LiteralPath $file.FullName -Value $content -NoNewline -Encoding utf8NoBOM
    }
}

$env:IDADIR = $selectedIda
# idapro/IDAPython may also consult this location while constructing its dynamic loader.
# Keep it canonical for the same trailing-backslash reason as IDADIR.
$env:IDAPYTHON_DYNLOAD_BASE = $selectedIda

Write-Host "Installing/Upgrading ida-domain module..."
& $selectedPython -m pip install --upgrade "ida-domain>=0.5.0,<0.6.0"
if ($LASTEXITCODE -ne 0) { throw "ida-domain upgrade failed" }

Write-Host "Installing requirements from requirements.txt..."
if (Test-Path -LiteralPath $requirementsFile -PathType Leaf) {
    & $selectedPython -m pip install -r $requirementsFile
    if ($LASTEXITCODE -ne 0) { throw "requirements.txt installation failed" }
}

Write-Host "Verifying ida-domain/idapro imports with IDADIR=$env:IDADIR..."
& $selectedPython -c "import ida_domain, idapro; print('ida-domain/idapro import OK')"
if ($LASTEXITCODE -ne 0) { throw "IDA Python verification failed" }

Write-Host "Setup complete. IDADIR=$env:IDADIR"
Write-Host "Skill installed to $targetDir"
