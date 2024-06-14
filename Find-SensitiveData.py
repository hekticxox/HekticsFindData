# Define regex patterns for sensitive data
$RegexPatterns = @{
    SSN            = '\b\d{3}-\d{2}-\d{4}\b'
    Password       = '(?i)\bpassword\b( |)=( |)'
    DomainPrefix   = "$env:USERDOMAIN\\"
    AWSAccessKey   = '\bAKIA[A-Z0-9]{16}\b'
    AWSSecretKey   = '\b(?:[A-Za-z0-9+/]{40})\b'
    MachineKey     = '\bmachinekey\b'
    CreditCard     = '\b(?:\d[ -]*?){13,16}\b'
}

function Get-FilePaths {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [String]$SharePath,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]$BaseDirectory = $env:USERPROFILE,

        [Parameter(Mandatory = $false)]
        [Switch]$Force
    )

    $script:ShareRootDirectory = "LocalDrive-$(($SharePath -split ':')[0])"

    try {
        $ErrorActionPreference = "Stop"

        $CurrentUser = $env:USERNAME

        if (-not (Test-Path -Path $BaseDirectory)) {
            New-Item -Path $BaseDirectory -ItemType Directory | Out-Null
        }

        $script:ShareRootDirectory = "Drive-$($SharePath.Split(':')[0])"
        $BaseOutputFile = Join-Path -Path $BaseDirectory -ChildPath ("FilePaths-ALL-$script:ShareRootDirectory-$CurrentUser.csv")
        $script:DefaultOutputFile = Join-Path -Path $BaseDirectory -ChildPath ("FilePaths-$script:ShareRootDirectory-$CurrentUser.csv")

        if ($Force) {
            Remove-Item $BaseOutputFile, $DefaultOutputFile -ErrorAction SilentlyContinue
        }

        $BaseFileExist = Test-Path -Path $BaseOutputFile
        $DefaultFileExist = Test-Path -Path $DefaultOutputFile

        if (-not $DefaultFileExist) {
            Write-Output "[*] $(Get-Date) : Recursively searching files in $SharePath and adding to $BaseOutputFile"

            Get-ChildItem -Path $SharePath -File -Recurse -ErrorAction SilentlyContinue | 
                Select-Object FullName, Extension, Length | 
                Export-Csv -Path $BaseOutputFile -Delimiter ',' -Encoding UTF8 -NoTypeInformation
        }
        else {
            Write-Output "[-] $(Get-Date) : File containing file paths exists at $DefaultOutputFile. Using that file."
        }
    }
    catch {
        Write-Error "An error occurred while getting file paths: $_"
    }
}

function Find-SensitiveData {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [String]$SharePath,

        [Parameter(Mandatory = $false)]
        [String]$BaseDirectory = $env:USERPROFILE,

        [Parameter(Mandatory = $false)]
        [Switch]$Force
    )

    $Matches = @()
    $Summary = @{}

    try {
        $ErrorActionPreference = "Stop"

        if ($Force) {
            Write-Output "[!] $(Get-Date) : '-Force' was used. Now removing previous data files"
            Get-FilePaths -SharePath $SharePath -BaseDirectory $BaseDirectory -Force
        }
        else {
            Get-FilePaths -SharePath $SharePath -BaseDirectory $BaseDirectory
        }

        if (Test-Path $script:DefaultOutputFile) {
            $FilePaths = Import-Csv -Path $script:DefaultOutputFile -Delimiter ','

            foreach ($File in $FilePaths) {
                $Content = Get-Content -Path $File.FullName -ErrorAction SilentlyContinue

                $LineNumber = 0
                foreach ($Line in $Content) {
                    $LineNumber++
                    foreach ($RegexPattern in $RegexPatterns.GetEnumerator()) {
                        if ($Line -match $RegexPattern.Value) {
                            $Match = [PSCustomObject]@{
                                FileName    = $File.FullName
                                Pattern     = $RegexPattern.Key
                                MatchedText = $matches[0]
                                LineNumber  = $LineNumber
                            }
                            $Matches += $Match
                            
                            if ($Summary.ContainsKey($RegexPattern.Key)) {
                                $Summary[$RegexPattern.Key] += 1
                            } else {
                                $Summary[$RegexPattern.Key] = 1
                            }
                        }
                    }
                }
            }

            $OutputFile = Join-Path -Path $BaseDirectory -ChildPath "PotentialData-$(Get-Date -Format 'yyyyMMddHHmmss').csv"
            $Matches | Export-Csv -Path $OutputFile -NoTypeInformation

            Write-Output "[*] $(Get-Date) : Summary of sensitive data found:"
            foreach ($Key in $Summary.Keys) {
                Write-Output "$($Key): $($Summary[$Key])"
            }

            Write-Output "[*] $(Get-Date) : Detailed matches saved to $OutputFile"
        }
        else {
            Write-Warning "[!] $(Get-Date) : No matching data found in $SharePath. Exiting..."
        }
    }
    catch {
        Write-Error "An error occurred while finding sensitive data: $_"
    }
}

function Remove-SensitiveData {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)]
        [String[]]$DataFiles = @("PotentialData-*.csv", "FilePaths-*.csv"),

        [Parameter(Mandatory = $false)]
        [String]$BaseDirectory = $env:USERPROFILE
    )

    try {
        $ErrorActionPreference = "Stop"

        foreach ($DataFile in $DataFiles) {
            $FullPath = Join-Path -Path $BaseDirectory -ChildPath $DataFile
            if (Test-Path $FullPath) {
                Write-Output "[!] $(Get-Date) : Removing $FullPath"
                Remove-Item $FullPath -ErrorAction SilentlyContinue
            }
        }
    }
    catch {
        Write-Error "An error occurred while removing sensitive data: $_"
    }
}

# List available drives and prompt user to select one
$drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -gt 0 }
$driveList = $drives | ForEach-Object { "$($_.Name) - $($_.DisplayRoot)" }

Write-Host "Available drives:" -ForegroundColor Cyan
for ($i = 0; $i -lt $driveList.Count; $i++) {
    Write-Host "[$i] $($driveList[$i])"
}

$selectedDriveIndex = Read-Host "Enter the number of the drive you want to scan"
if ($selectedDriveIndex -match '^\d+$' -and $selectedDriveIndex -lt $driveList.Count) {
    $selectedDrive = $drives[$selectedDriveIndex].Root
    Write-Host "Scanning drive $selectedDrive ..." -ForegroundColor Green

    # Execute the script with selected drive
    Find-SensitiveData -SharePath $selectedDrive -BaseDirectory "C:\users\hekti\Desktop"
} else {
    Write-Host "Invalid selection. Exiting..." -ForegroundColor Red
}

# Optionally, remove sensitive data files
# Remove-SensitiveData -BaseDirectory "C:\users\hekti\Desktop"
