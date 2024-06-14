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

function Analyze-SensitiveData {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [String]$FilePath,

        [Parameter(Mandatory = $true)]
        [String]$OutputDirectory,

        [Parameter(Mandatory = $false)]
        [Switch]$EnableDebug
    )

    $Matches = @()
    $Summary = @{}

    try {
        $ErrorActionPreference = "Stop"

        $FilePaths = Import-Csv -Path $FilePath -Delimiter ','

        $TotalFiles = $FilePaths.Count
        $CurrentFile = 0

        foreach ($File in $FilePaths) {
            $CurrentFile++
            $ProgressPercentage = [math]::Round(($CurrentFile / $TotalFiles) * 100, 2)
            Write-Progress -Activity "Analyzing files" -Status "$ProgressPercentage% Complete" -PercentComplete $ProgressPercentage

            if ($EnableDebug) {
                Write-Output "[DEBUG] Analyzing file $($File.FullName)"
            }

            try {
                $Content = Get-Content -Path $File.FullName -ErrorAction SilentlyContinue -Raw
                if (-not $Content) {
                    if ($EnableDebug) {
                        Write-Output "[DEBUG] Skipping file $($File.FullName) due to null content"
                    }
                    continue
                }

                foreach ($RegexPattern in $RegexPatterns.GetEnumerator()) {
                    $MatchesInContent = [regex]::Matches($Content, $RegexPattern.Value)
                    foreach ($Match in $MatchesInContent) {
                        $Match = [PSCustomObject]@{
                            FileName    = $File.FullName
                            Pattern     = $RegexPattern.Key
                            MatchedText = $Match.Value
                        }
                        $Matches += $Match

                        if ($Summary.ContainsKey($RegexPattern.Key)) {
                            $Summary[$RegexPattern.Key] += 1
                        } else {
                            $Summary[$RegexPattern.Key] = 1
                        }

                        if ($EnableDebug) {
                            Write-Output "[DEBUG] Found match for pattern '$($RegexPattern.Key)' in file '$($File.FullName)'"
                        }
                    }
                }
            } catch {
                Write-Error "Error processing file $($File.FullName): $_"
            }
        }

        $OutputFile = Join-Path -Path $OutputDirectory -ChildPath ("PotentialData-" + (Get-Date -Format 'yyyyMMddHHmmss') + ".csv")
        $Matches | Export-Csv -Path $OutputFile -NoTypeInformation

        Write-Output "[*] $(Get-Date) : Analysis complete. Results saved to $OutputFile"
        Write-Output "[*] Summary of sensitive data found:"
        foreach ($Key in $Summary.Keys) {
            Write-Output "$($Key): $($Summary[$Key])"
        }

    } catch {
        Write-Error "An error occurred while analyzing sensitive data: $_"
    } finally {
        Write-Progress -Activity "Analyzing files" -Completed
    }
}

# Main script execution
Clear-Host
$FilePath = Read-Host "Please enter the file path to analyze"
$OutputDirectory = Read-Host "Please enter the output directory"
$EnableDebug = Read-Host "Enable debug output? (yes/no)"

if ($EnableDebug -eq "yes") {
    Analyze-SensitiveData -FilePath $FilePath -OutputDirectory $OutputDirectory -EnableDebug
} else {
    Analyze-SensitiveData -FilePath $FilePath -OutputDirectory $OutputDirectory
}
