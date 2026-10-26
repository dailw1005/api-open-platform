[CmdletBinding()]
param(
    [ValidateSet("Valid", "Replay", "TokenBucket", "DayQuota", "MonthQuota")]
    [string]$Scenario = "Valid",
    [string]$BaseUrl = $env:STAGING_BASE_URL,
    [string]$AppKey = $env:STAGING_APP_KEY,
    [string]$Secret = $env:STAGING_APP_SECRET,
    [string]$Path = $env:STAGING_PATH,
    [string]$Method = "GET",
    [string]$Body = "",
    [int]$ExpectedAllowed = 0,
    [int]$MaxRequests = 20,
    [switch]$AllowInsecure
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Fail([string]$Message) {
    throw "Staging validation failed: $Message"
}

function Get-Hex([byte[]]$Bytes) {
    $builder = [System.Text.StringBuilder]::new($Bytes.Length * 2)
    foreach ($value in $Bytes) {
        [void]$builder.Append($value.ToString("x2"))
    }
    return $builder.ToString()
}

function Get-Sha256Hex([byte[]]$Bytes) {
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return Get-Hex $sha256.ComputeHash($Bytes)
    } finally {
        $sha256.Dispose()
    }
}

function Get-HmacSha256Hex([string]$Value, [byte[]]$Key) {
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($Key)
    try {
        return Get-Hex $hmac.ComputeHash(
            [System.Text.Encoding]::UTF8.GetBytes($Value)
        )
    } finally {
        $hmac.Dispose()
    }
}

function New-SignedRequest {
    $nonce = [Guid]::NewGuid().ToString("N")
    $timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
    $contentType = if ($bodyBytes.Length -gt 0) {
        "application/json"
    } else {
        ""
    }
    $canonical = @(
        "AK-HMAC-V1"
        $AppKey
        $canonicalHost
        $normalizedMethod
        $Path
        ""
        $contentType
        [string]$timestamp
        $nonce
        (Get-Sha256Hex $bodyBytes)
    ) -join "`n"
    $secretBytes = [System.Text.Encoding]::UTF8.GetBytes($Secret)
    try {
        $signature = Get-HmacSha256Hex $canonical $secretBytes
    } finally {
        [Array]::Clear($secretBytes, 0, $secretBytes.Length)
    }

    return [pscustomobject]@{
        Nonce = $nonce
        Timestamp = $timestamp
        Signature = $signature
        BodyBytes = $bodyBytes
        ContentType = $contentType
    }
}

function Send-SignedRequest([object]$SignedRequest) {
    $request = [System.Net.Http.HttpRequestMessage]::new(
        [System.Net.Http.HttpMethod]::new($normalizedMethod),
        $endpoint
    )
    try {
        $request.Headers.TryAddWithoutValidation(
            "X-Signature-Version",
            "v1"
        ) | Out-Null
        $request.Headers.TryAddWithoutValidation(
            "X-App-Key",
            $AppKey
        ) | Out-Null
        $request.Headers.TryAddWithoutValidation(
            "X-Timestamp",
            [string]$SignedRequest.Timestamp
        ) | Out-Null
        $request.Headers.TryAddWithoutValidation(
            "X-Nonce",
            $SignedRequest.Nonce
        ) | Out-Null
        $request.Headers.TryAddWithoutValidation(
            "X-Signature",
            $SignedRequest.Signature
        ) | Out-Null

        if ($SignedRequest.BodyBytes.Length -gt 0) {
            $content = [System.Net.Http.ByteArrayContent]::new(
                $SignedRequest.BodyBytes
            )
            $content.Headers.ContentType =
                [System.Net.Http.Headers.MediaTypeHeaderValue]::new($SignedRequest.ContentType)
            $request.Content = $content
        }

        $response = $client.SendAsync($request).GetAwaiter().GetResult()
        try {
            $responseBody = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            $code = $null
            if (-not [string]::IsNullOrWhiteSpace($responseBody)) {
                try {
                    $code = ($responseBody | ConvertFrom-Json).code
                } catch {
                    $code = $null
                }
            }
            return [pscustomobject]@{
                Status = [int]$response.StatusCode
                Code = $code
                Body = $responseBody
                RetryAfter = $response.Headers.RetryAfter
            }
        } finally {
            $response.Dispose()
        }
    } finally {
        $request.Dispose()
    }
}

foreach ($required in @(
    @{ Name = "BaseUrl"; Value = $BaseUrl },
    @{ Name = "AppKey"; Value = $AppKey },
    @{ Name = "Secret"; Value = $Secret },
    @{ Name = "Path"; Value = $Path }
)) {
    if ([string]::IsNullOrWhiteSpace($required.Value)) {
        Fail "$($required.Name) is required"
    }
}
if ($AppKey -notmatch "^[A-Za-z0-9_-]{16,128}$") {
    Fail "AppKey format is invalid"
}
if ([System.Text.Encoding]::UTF8.GetByteCount($Secret) -lt 32) {
    Fail "Secret must contain at least 32 UTF-8 bytes"
}
if ($Path -notmatch '^/[A-Za-z0-9._~!$&''()*+,;=:@/-]*$' -or $Path.Contains("//") -or $Path -match "(^|/)\.\.?($|/)") {
    Fail "Path must be a simple absolute path without query or dot segments"
}
if ($MaxRequests -lt 1 -or $MaxRequests -gt 200) {
    Fail "MaxRequests must be between 1 and 200"
}

$baseUri = [Uri]::new($BaseUrl)
if ($baseUri.Scheme -ne "https" -and -not $AllowInsecure) {
    Fail "HTTPS is required unless AllowInsecure is explicitly set"
}
$endpoint = [Uri]::new($BaseUrl.TrimEnd("/") + $Path)
if (-not [string]::IsNullOrEmpty($endpoint.Query)) {
    Fail "BaseUrl and Path must not include a query string"
}
$normalizedMethod = $Method.Trim().ToUpperInvariant()
if ($normalizedMethod -notin @("GET", "POST", "PUT", "PATCH", "DELETE")) {
    Fail "Unsupported HTTP method"
}
$hostValue = $endpoint.Host.ToLowerInvariant()
if ($endpoint.HostNameType -eq [UriHostNameType]::IPv6) {
    $hostValue = "[$hostValue]"
}
$canonicalHost = if ($endpoint.IsDefaultPort) {
    $hostValue
} else {
    "$hostValue`:$($endpoint.Port)"
}

$client = [System.Net.Http.HttpClient]::new()
$client.Timeout = [TimeSpan]::FromSeconds(15)
try {
    switch ($Scenario) {
        "Valid" {
            $response = Send-SignedRequest (New-SignedRequest)
            if ($response.Status -ne 200) {
                Fail "Valid scenario returned $($response.Status) $($response.Code)"
            }
        }
        "Replay" {
            $signed = New-SignedRequest
            $first = Send-SignedRequest $signed
            $second = Send-SignedRequest $signed
            if ($first.Status -ne 200) {
                Fail "Replay first request returned $($first.Status) $($first.Code)"
            }
            if ($second.Status -ne 401 -or $second.Code -ne "NONCE_REPLAYED") {
                Fail "Replay was not rejected with NONCE_REPLAYED"
            }
        }
        "TokenBucket" {
            if ($ExpectedAllowed -lt 1) {
                Fail "ExpectedAllowed is required for TokenBucket"
            }
            $allowed = 0
            $denied = $null
            for ($index = 0; $index -lt $MaxRequests; $index++) {
                $response = Send-SignedRequest (New-SignedRequest)
                if ($response.Status -eq 200) {
                    $allowed++
                    continue
                }
                $denied = $response
                break
            }
            if ($null -eq $denied -or $denied.Status -ne 429 -or $denied.Code -ne "RATE_LIMITED") {
                Fail "Token bucket did not return RATE_LIMITED"
            }
            if ($allowed -lt $ExpectedAllowed -or $allowed -gt ($ExpectedAllowed + 1)) {
                Fail "Observed $allowed allowed requests, expected $ExpectedAllowed with at most one refill"
            }
        }
        "DayQuota" {
            $quotaCode = "QUOTA_EXCEEDED"
            $sawAllowed = $false
            $denied = $null
            for ($index = 0; $index -lt $MaxRequests; $index++) {
                $response = Send-SignedRequest (New-SignedRequest)
                if ($response.Status -eq 200) {
                    $sawAllowed = $true
                    continue
                }
                $denied = $response
                break
            }
            if (-not $sawAllowed -or $null -eq $denied -or $denied.Status -ne 429 -or $denied.Code -ne $quotaCode) {
                Fail "Daily quota did not return QUOTA_EXCEEDED"
            }
        }
        "MonthQuota" {
            $quotaCode = "QUOTA_EXCEEDED"
            $sawAllowed = $false
            $denied = $null
            for ($index = 0; $index -lt $MaxRequests; $index++) {
                $response = Send-SignedRequest (New-SignedRequest)
                if ($response.Status -eq 200) {
                    $sawAllowed = $true
                    continue
                }
                $denied = $response
                break
            }
            if (-not $sawAllowed -or $null -eq $denied -or $denied.Status -ne 429 -or $denied.Code -ne $quotaCode) {
                Fail "Monthly quota did not return QUOTA_EXCEEDED"
            }
        }
    }

    Write-Output (
        "PASS scenario={0} path={1} host={2}" -f
        $Scenario,
        $Path,
        $canonicalHost
    )
} finally {
    $client.Dispose()
}
