# Function to get user-selected patterns
function Get-SelectedPatterns {
    param (
        [hashtable]$RegexPatterns
    )

    $selectedPatterns = @{}

    Write-Host "Available patterns for sensitive data:" -ForegroundColor Cyan
    $i = 0
    $patternKeys = @()
    foreach ($pattern in $RegexPatterns.Keys) {
        Write-Host "[$i] $pattern"
        $patternKeys += $pattern
        $i++
    }

    $selectedIndices = Read-Host "Enter the numbers of the patterns you want to include (comma-separated)"
    $selectedIndices = $selectedIndices -split ','

    foreach ($index in $selectedIndices) {
        $index = $index.Trim()  # Trim whitespace around the index

        Write-Host "Processing index: $index" -ForegroundColor Yellow

        if ($index -match '^\d+$' -and $index -lt $patternKeys.Count) {
            $selectedPatternKey = $patternKeys[$index]
            Write-Host "Selected pattern: $selectedPatternKey" -ForegroundColor Green
            $selectedPatterns[$selectedPatternKey] = $RegexPatterns[$selectedPatternKey]
        } else {
            Write-Host "Invalid selection: $index" -ForegroundColor Red
        }
    }

    if ($selectedPatterns.Count -eq 0) {
        Write-Host "No valid patterns selected. Exiting..." -ForegroundColor Red
        Exit
    }

    return $selectedPatterns
}

# Function to get file paths
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

    try {
        $ErrorActionPreference = "Stop"

        if (-not (Test-Path -Path $SharePath)) {
            Write-Error "Path $SharePath does not exist or is inaccessible."
            return
        }

        $BaseOutputFile = Join-Path -Path $BaseDirectory -ChildPath "FilePaths-ALL-Drive-F-hekti.csv"

        if ($Force -or (-not (Test-Path $BaseOutputFile))) {
            Write-Output "[*] $(Get-Date) : Recursively searching files in $SharePath and adding to $BaseOutputFile"

            Get-ChildItem -Path $SharePath -File -Recurse -ErrorAction SilentlyContinue | 
                Where-Object { $_.Extension -notin @(".exe", ".dll") -and $_.Length -lt 100MB } |
                Select-Object FullName, Extension, Length | 
                Export-Csv -Path $BaseOutputFile -Delimiter ',' -Encoding UTF8 -NoTypeInformation
        }
        else {
            Write-Output "[-] $(Get-Date) : File containing file paths exists at $BaseOutputFile. Using that file."
        }
    }
    catch {
        Write-Error "An error occurred while getting file paths: $_"
    }
}

# Function to find sensitive data
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

    $RegexPatterns = @{
        "Password" = "regex_for_password";
        "AWSAccessKey" = "regex_for_aws_access_key";
        "AWSSecretKey" = "regex_for_aws_secret_key";
        "SSN" = "regex_for_ssn";
        "CreditCard" = "regex_for_credit_card";
        "DomainPrefix" = "regex_for_domain_prefix";
        "MachineKey" = "regex_for_machine_key";
    }

    $selectedPatterns = Get-SelectedPatterns -RegexPatterns $RegexPatterns

    $Matches = @{}
    $Summary = @{}

    try {
        $ErrorActionPreference = "Stop"

        Get-FilePaths -SharePath $SharePath -BaseDirectory $BaseDirectory -Force:$Force

        # Rest of your sensitive data scanning logic
        # Ensure paths are accessible before accessing them

    }
    catch {
        Write-Error "An error occurred while finding sensitive data: $_"
    }
}

# Main script flow
try {
    $ErrorActionPreference = "Stop"

    Write-Host "Available drives:"
    Get-PSDrive -PSProvider FileSystem | ForEach-Object {
        "[{0}] {1}" -f $_.Name, $_.Root
    }

    $driveSelection = Read-Host "Enter the letter of the drive you want to scan"
    $selectedDrive = (Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Name -eq $driveSelection }).Root

    if ([string]::IsNullOrEmpty($selectedDrive)) {
        Write-Error "Invalid drive selection: $driveSelection"
        Exit
    }

    Write-Host "Scanning drive $selectedDrive ..."

    Find-SensitiveData -SharePath $selectedDrive -BaseDirectory "C:\Users\hekti\Desktop"

}
catch {
    Write-Error "An error occurred: $_"
}
