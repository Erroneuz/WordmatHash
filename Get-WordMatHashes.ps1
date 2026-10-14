<#
.SYNOPSIS
    Collects SHA256 hashes for WordMat from three sources:
      1) Seven fixed downloads from wordmat.dk (hash is calculated locally)
         - Note: requires partner access based on your WAN IP.
      2) WordMat.dotm / WordMatP.dotm / WordMatP2.dotm read from the adm page
      3) The files in the latest GitHub release (Eduap-com/WordMat)
    The result is saved as a CSV in Microsoft Defender indicator format (FileSha256 / Allowed)
    and as a TXT file (hash values only, one per line).

.EXAMPLE
    .\Get-WordMatHashes.ps1
    .\Get-WordMatHashes.ps1 -OutputFolder C:\Temp\wm -CsvPath C:\Temp\hashes.csv -TxtPath C:\Temp\hashes.txt
#>

param(
    [string]$OutputFolder = ".\downloads",
    [string]$CsvPath      = ".\wordmat-hashes.csv",
    [string]$TxtPath      = ".\wordmat-hashes.txt",

    # Page containing the hash values for the dotm files
    [string]$HashPageUrl  = "https://www.wordmat.dk/adm",

    [string]$GitHubRepo   = "Eduap-com/WordMat",

    # Optional: GitHub token if you hit the API rate limit (60 requests/hour without a token)
    [string]$GitHubToken  = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

$downloadUrls = @(
    "https://www.wordmat.dk/download.php?file=WordMatP.exe&lang=da"
    "https://www.wordmat.dk/download.php?file=WordMatNA.exe&lang=da"
    "https://www.wordmat.dk/download.php?file=WordMatMacApple.pkg&lang=da"
    "https://www.wordmat.dk/download.php?file=WordMatMacIntel.pkg&lang=da"
    "https://www.wordmat.dk/download.php?file=WordMatALL.msi&lang=da"
    "https://www.wordmat.dk/download.php?file=WordMatALL32bit.msi&lang=da"
    "https://www.wordmat.dk/download.php?file=WordMatUSER.msi&lang=da"
)
$pageFiles = @("WordMat.dotm", "WordMatP.dotm", "WordMatP2.dotm")

if (-not (Test-Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder | Out-Null
}

$results = [System.Collections.Generic.List[object]]::new()

function Add-Result($Source, $FileName, $Hash, $Url) {
    $results.Add([PSCustomObject]@{
        Source   = $Source
        FileName = $FileName
        SHA256  = $Hash
        Url     = $Url
    })
}

# ---------------------------------------------------------------------------
# 1. Fixed downloads from wordmat.dk
# ---------------------------------------------------------------------------
foreach ($url in $downloadUrls) {
    $fileName = [regex]::Match($url, 'file=([^&]+)').Groups[1].Value
    $target   = Join-Path $OutputFolder $fileName
    try {
        Write-Host "Downloading $fileName ..."
        Invoke-WebRequest -Uri $url -OutFile $target -UseBasicParsing
        $hash = (Get-FileHash -Path $target -Algorithm SHA256).Hash
        Add-Result "Calculated from download (wordmat.dk)" $fileName $hash $url
    }
    catch {
        Write-Warning "Error for ${fileName}: $($_.Exception.Message)"
        Add-Result "Calculated from download (wordmat.dk)" $fileName "ERROR" $url
    }
}

# ---------------------------------------------------------------------------
# 2. SHA256 for the dotm files from the adm page
# ---------------------------------------------------------------------------
try {
    Write-Host "Fetching hash values from $HashPageUrl ..."
    $page = Invoke-WebRequest -Uri $HashPageUrl -UseBasicParsing

    $text = $page.Content -replace '(?s)<script.*?</script>', ' ' `
                          -replace '(?s)<style.*?</style>',   ' ' `
                          -replace '<[^>]+>',                  ' '
    $text = [System.Net.WebUtility]::HtmlDecode($text) -replace '\s+', ' '

    foreach ($name in $pageFiles) {
        $pattern = '(?<![A-Za-z0-9])' + [regex]::Escape($name) + '\s+([A-Fa-f0-9]{64})(?![A-Fa-f0-9])'
        $m = [regex]::Match($text, $pattern)
        if ($m.Success) {
            Add-Result "Read from website (adm)" $name $m.Groups[1].Value.ToUpper() $HashPageUrl
        }
        else {
            Write-Warning "Could not find SHA256 for $name on the adm page."
            Add-Result "Read from website (adm)" $name "NOT FOUND" $HashPageUrl
        }
    }
}
catch {
    Write-Warning "Could not fetch the adm page: $($_.Exception.Message)"
    foreach ($name in $pageFiles) { Add-Result "Read from website (adm)" $name "ERROR" $HashPageUrl }
}

# ---------------------------------------------------------------------------
# 3. Latest GitHub release
#    Primarily via the API (field "digest" = "sha256:<hash>"),
#    otherwise by reading the release page as HTML.
# ---------------------------------------------------------------------------
$ghAssets = [System.Collections.Generic.List[object]]::new()   # Name, Url, Digest
$ghTag    = ""

try {
    Write-Host "Fetching latest release from GitHub API ($GitHubRepo) ..."
    $headers = @{ "User-Agent" = "WordMatHashScript"; "Accept" = "application/vnd.github+json" }
    if ($GitHubToken) { $headers["Authorization"] = "Bearer $GitHubToken" }

    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$GitHubRepo/releases/latest" -Headers $headers
    $ghTag   = $release.tag_name
    foreach ($a in $release.assets) {
        $ghAssets.Add([PSCustomObject]@{ Name = $a.name; Url = $a.browser_download_url; Digest = [string]$a.digest })
    }
}
catch {
    Write-Warning "GitHub API failed ($($_.Exception.Message)). Trying to read the release page instead ..."
    try {
        $latest = Invoke-WebRequest -Uri "https://github.com/$GitHubRepo/releases/latest" -UseBasicParsing

        # Find the tag name: first in the final URL after the redirect, otherwise in the page links
        $finalUrl = ""
        if ($latest.BaseResponse.ResponseUri)                 { $finalUrl = $latest.BaseResponse.ResponseUri.AbsoluteUri }
        elseif ($latest.BaseResponse.RequestMessage.RequestUri) { $finalUrl = $latest.BaseResponse.RequestMessage.RequestUri.AbsoluteUri }
        $tm = [regex]::Match($finalUrl, '/releases/tag/([^/?#]+)')
        if (-not $tm.Success) { $tm = [regex]::Match($latest.Content, '/releases/tag/([^"''/?#<>]+)') }
        if (-not $tm.Success) { throw "Could not find the release tag." }
        $ghTag = [Uri]::UnescapeDataString($tm.Groups[1].Value)

        $assetsHtml = (Invoke-WebRequest -Uri "https://github.com/$GitHubRepo/releases/expanded_assets/$ghTag" -UseBasicParsing).Content

        # Each asset is in its own <li>
        foreach ($li in ($assetsHtml -split '(?i)<li\b')) {
            $href = [regex]::Match($li, 'href="(/[^"]+/releases/download/[^"]+)"')
            if (-not $href.Success) { continue }
            $dg   = [regex]::Match($li, 'sha256:([A-Fa-f0-9]{64})')
            $url  = "https://github.com" + [System.Net.WebUtility]::HtmlDecode($href.Groups[1].Value)
            $ghAssets.Add([PSCustomObject]@{
                Name   = [Uri]::UnescapeDataString([IO.Path]::GetFileName($url))
                Url    = $url
                Digest = $(if ($dg.Success) { "sha256:" + $dg.Groups[1].Value } else { "" })
            })
        }
    }
    catch {
        Write-Warning "Could not fetch GitHub release: $($_.Exception.Message)"
        Add-Result "GitHub release" "(release)" "ERROR" "https://github.com/$GitHubRepo/releases/latest"
    }
}

if ($ghAssets.Count -gt 0) {
    Write-Host "GitHub release ${ghTag}: $($ghAssets.Count) file(s)."
    foreach ($asset in $ghAssets) {
        $dm = [regex]::Match($asset.Digest, '^sha256:([A-Fa-f0-9]{64})$')
        if ($dm.Success) {
            Add-Result "Read from GitHub release $ghTag" $asset.Name $dm.Groups[1].Value.ToUpper() $asset.Url
        }
        else {
            # No digest on GitHub (older releases) -> download and calculate it ourselves
            try {
                Write-Host "No digest for $($asset.Name) - downloading and calculating ..."
                $target = Join-Path $OutputFolder ("github_" + $asset.Name)
                Invoke-WebRequest -Uri $asset.Url -OutFile $target -UseBasicParsing
                $hash = (Get-FileHash -Path $target -Algorithm SHA256).Hash
                Add-Result "Calculated from GitHub download $ghTag" $asset.Name $hash $asset.Url
            }
            catch {
                Write-Warning "Error for $($asset.Name): $($_.Exception.Message)"
                Add-Result "GitHub release $ghTag" $asset.Name "ERROR" $asset.Url
            }
        }
    }
}
elseif ($ghTag) {
    Write-Warning "Release $ghTag has no files."
}

# ---------------------------------------------------------------------------
# 4. Display and save
# ---------------------------------------------------------------------------
$results | Format-Table Source, FileName, SHA256 -AutoSize
# CSV in Microsoft Defender format (Indicators -> File hashes -> Import).
# Only rows with a valid SHA256 are included (ERROR / NOT FOUND are skipped).
$indicators = $results | Where-Object { $_.SHA256 -match '^[A-Fa-f0-9]{64}$' } | ForEach-Object {
    [PSCustomObject][ordered]@{
        IndicatorType      = "FileSha256"
        IndicatorValue     = $_.SHA256
        ExpirationTime     = ""
        Action             = "Allowed"
        Severity           = "Informational"
        Title              = $_.FileName
        Description        = $_.Source
        RecommendedActions = ""
        RbacGroups         = ""
        Category           = "SuspiciousActivity"
        MitreTechniques    = ""
        GenerateAlert      = "FALSE"
    }
}
$indicators | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

# TXT: valid hash values only (64 hex characters), one per line, nothing else
$hashesOnly = $results.SHA256 | Where-Object { $_ -match '^[A-Fa-f0-9]{64}$' }
Set-Content -Path $TxtPath -Value $hashesOnly -Encoding ASCII

Write-Host "CSV saved to: $CsvPath"
Write-Host "TXT saved to: $TxtPath ($(@($hashesOnly).Count) hash values)"

$results

# v14102026 - Hoder Jensen - Fælles Digital - https://faellesdigital.dk - https://github.com/Erroneuz/WordmatHash/
