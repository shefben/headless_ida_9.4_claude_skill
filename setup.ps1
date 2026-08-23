param(
    [string]$IdaPath,
    [string]$PythonPath
)

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

function Get-IdaVersion {
    param([string]$Directory)

    foreach ($exeName in @("ida.exe", "ida64.exe", "idat.exe", "idat64.exe")) {
        $exePath = Join-Path $Directory $exeName
        if (-not (Test-Path -LiteralPath $exePath -PathType Leaf)) { continue }

        try {
            $info = (Get-Item -LiteralPath $exePath -ErrorAction Stop).VersionInfo
            foreach ($versionText in @($info.ProductVersion, $info.FileVersion)) {
                if ($versionText -and $versionText -match '(?<!\d)(9\.[1-4])(?:\.\d+)?') {
                    return $Matches[1]
                }
            }
        } catch { }
    }

    if ($Directory -match '(?<!\d)(9\.[1-4])(?:[^\d]|$)') {
        return $Matches[1]
    }
    if ($Directory -match '(?i)(?:ida|idapro)[^0-9]*9[_-]?([1-4])(?:[^0-9]|$)') {
        return "9.$($Matches[1])"
    }

    return "unknown"
}

function Add-IdaInstallation {
    param(
        [System.Collections.Generic.List[object]]$List,
        [AllowNull()][string]$Path,
        [string]$Source = "unknown"
    )

    $candidate = Normalize-CandidatePath $Path
    if ([string]::IsNullOrWhiteSpace($candidate)) { return }

    try {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            $candidate = Split-Path -Parent $candidate
        }
        if (-not (Test-Path -LiteralPath $candidate -PathType Container)) { return }

        $candidate = Normalize-DirectoryPath ((Resolve-Path -LiteralPath $candidate -ErrorAction Stop).Path)
        $hasIda = $false
        foreach ($exeName in @("ida.exe", "ida64.exe", "idat.exe", "idat64.exe")) {
            if (Test-Path -LiteralPath (Join-Path $candidate $exeName) -PathType Leaf) {
                $hasIda = $true
                break
            }
        }
        if (-not $hasIda) { return }

        foreach ($existing in $List) {
            if ([string]::Equals($existing.Path, $candidate, [System.StringComparison]::OrdinalIgnoreCase)) {
                if ($existing.Source -notlike "*$Source*") {
                    $existing.Source = "$($existing.Source),$Source"
                }
                return
            }
        }

        $List.Add([pscustomobject]@{
            Path = $candidate
            Version = Get-IdaVersion $candidate
            Source = $Source
        })
    } catch {
        return
    }
}

function Search-IdaChildren {
    param(
        [System.Collections.Generic.List[object]]$List,
        [AllowNull()][string]$BasePath,
        [int]$Depth = 1,
        [string]$Source = "filesystem"
    )

    $base = Normalize-CandidatePath $BasePath
    if ([string]::IsNullOrWhiteSpace($base)) { return }
    if (-not (Test-Path -LiteralPath $base -PathType Container)) { return }

    try {
        $children = @(Get-ChildItem -LiteralPath $base -Directory -Force -ErrorAction SilentlyContinue)
    } catch {
        return
    }

    foreach ($child in $children) {
        if ($child.Name -match '(?i)(ida|hex.?rays)') {
            Add-IdaInstallation -List $List -Path $child.FullName -Source $Source

            if ($Depth -gt 1) {
                try {
                    foreach ($grandchild in @(Get-ChildItem -LiteralPath $child.FullName -Directory -Force -ErrorAction SilentlyContinue)) {
                        Add-IdaInstallation -List $List -Path $grandchild.FullName -Source $Source
                    }
                } catch { }
            }
        }
    }
}

function Search-IdaRegistry {
    param([System.Collections.Generic.List[object]]$List)

    $roots = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($root in $roots) {
        try {
            foreach ($entry in @(Get-ItemProperty -Path $root -ErrorAction SilentlyContinue)) {
                $displayName = [string]$entry.DisplayName
                $installLocation = [string]$entry.InstallLocation
                $displayIcon = [string]$entry.DisplayIcon

                if ($displayName -notmatch '(?i)(IDA|Hex.?Rays)' -and
                    $installLocation -notmatch '(?i)(IDA|Hex.?Rays)' -and
                    $displayIcon -notmatch '(?i)(IDA|Hex.?Rays)') {
                    continue
                }

                if (-not [string]::IsNullOrWhiteSpace($installLocation)) {
                    Add-IdaInstallation -List $List -Path $installLocation -Source "registry"
                }

                if (-not [string]::IsNullOrWhiteSpace($displayIcon)) {
                    $iconPath = ($displayIcon -replace ',\s*\d+\s*$', '').Trim().Trim('"')
                    Add-IdaInstallation -List $List -Path $iconPath -Source "registry"
                }
            }
        } catch { }
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

Write-Host "Searching for IDA 9.1 through 9.4 installations..."
$idaInstalls = [System.Collections.Generic.List[object]]::new()

if (-not [string]::IsNullOrWhiteSpace($IdaPath)) {
    Add-IdaInstallation -List $idaInstalls -Path $IdaPath -Source "argument"
    if ($idaInstalls.Count -eq 0) {
        throw "-IdaPath does not point to a valid IDA installation: $IdaPath"
    }
}

if ($idaInstalls.Count -eq 0) {
    foreach ($candidate in (Get-EnvironmentPathCandidates)) {
        Add-IdaInstallation -List $idaInstalls -Path $candidate -Source "environment"
    }

    $knownParents = [System.Collections.Generic.List[string]]::new()
    foreach ($install in @($idaInstalls)) {
        try {
            $parent = Split-Path -Parent $install.Path
            Add-UniquePath -List $knownParents -Path $parent
        } catch { }
    }
    foreach ($parent in $knownParents) {
        Search-IdaChildren -List $idaInstalls -BasePath $parent -Depth 1 -Source "sibling-scan"
    }

    Search-IdaRegistry -List $idaInstalls

    foreach ($base in @(
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:LOCALAPPDATA,
        $env:ProgramData
    )) {
        Search-IdaChildren -List $idaInstalls -BasePath $base -Depth 2 -Source "common-location"
    }

    try {
        foreach ($drive in @(Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue)) {
            if ([string]::IsNullOrWhiteSpace($drive.Root)) { continue }
            Search-IdaChildren -List $idaInstalls -BasePath $drive.Root -Depth 1 -Source "drive-root"

            foreach ($commonSubdir in @("Tools", "Apps", "Programs", "Software")) {
                $candidateBase = Join-Path $drive.Root $commonSubdir
                Search-IdaChildren -List $idaInstalls -BasePath $candidateBase -Depth 2 -Source "drive-common"
            }
        }
    } catch { }
}

$idaInstalls = @($idaInstalls | Sort-Object `
    @{Expression={
        switch ($_.Version) {
            "9.4" { 0 }
            "9.3" { 1 }
            "9.2" { 2 }
            "9.1" { 3 }
            default { 4 }
        }
    }}, `
    @{Expression={$_.Path}}
)

$selectedIda = $null
$selectedIdaVersion = "unknown"

if ($idaInstalls.Count -eq 0) {
    $manual = Normalize-DirectoryPath (Read-Host "No IDA installation was found automatically. Enter the IDA 9.4 folder")
    $manualList = [System.Collections.Generic.List[object]]::new()
    Add-IdaInstallation -List $manualList -Path $manual -Source "manual"
    if ($manualList.Count -eq 0) {
        throw "The manually entered path is not a valid IDA installation: $manual"
    }
    $selectedIda = $manualList[0].Path
    $selectedIdaVersion = $manualList[0].Version
} else {
    Write-Host "Discovered IDA installations:"
    for ($i = 0; $i -lt $idaInstalls.Count; $i++) {
        Write-Host ("[{0}] IDA {1,-7} {2}  ({3})" -f ($i + 1), $idaInstalls[$i].Version, $idaInstalls[$i].Path, $idaInstalls[$i].Source)
    }

    $ida94 = @($idaInstalls | Where-Object { $_.Version -eq "9.4" })
    if ($ida94.Count -eq 1) {
        $selectedIda = $ida94[0].Path
        $selectedIdaVersion = $ida94[0].Version
        Write-Host "Automatically selected the discovered IDA 9.4 installation: $selectedIda"
    } elseif ($idaInstalls.Count -eq 1) {
        $selectedIda = $idaInstalls[0].Path
        $selectedIdaVersion = $idaInstalls[0].Version
        Write-Host "Found IDA at: $selectedIda"
    } else {
        $selection = 0
        while ($selection -lt 1 -or $selection -gt $idaInstalls.Count) {
            $inputValue = Read-Host "Select the IDA installation by typing its number (IDA 9.4 is recommended)"
            if ([int]::TryParse($inputValue, [ref]$selection)) {
                if ($selection -lt 1 -or $selection -gt $idaInstalls.Count) {
                    Write-Host "Invalid selection. Please try again."
                }
            }
        }
        $selectedIda = $idaInstalls[$selection - 1].Path
        $selectedIdaVersion = $idaInstalls[$selection - 1].Version
    }
}

$selectedIda = Normalize-DirectoryPath $selectedIda
if ([string]::IsNullOrWhiteSpace($selectedIda) -or -not (Test-Path -LiteralPath $selectedIda -PathType Container)) {
    throw "Selected IDA directory does not exist: $selectedIda"
}

Write-Host "Using canonical IDA path: $selectedIda"
Write-Host "Detected IDA version: $selectedIdaVersion"
if ($selectedIdaVersion -ne "9.4") {
    Write-Warning "Selected IDA is '$selectedIdaVersion' at $selectedIda. The skill targets IDA 9.4; older versions are fallback/testing configurations."
}

Write-Host "Searching for Python 3.13.*..."
$pythonPaths = [System.Collections.Generic.List[string]]::new()

if (-not [string]::IsNullOrWhiteSpace($PythonPath)) {
    $candidatePython = Normalize-CandidatePath $PythonPath
    if (-not (Test-Path -LiteralPath $candidatePython -PathType Leaf)) {
        throw "-PythonPath does not point to a file: $candidatePython"
    }
    Add-UniquePath -List $pythonPaths -Path ((Resolve-Path -LiteralPath $candidatePython -ErrorAction Stop).Path)
} else {
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
