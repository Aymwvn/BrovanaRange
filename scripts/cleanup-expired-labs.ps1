param(
  [string]$ApiBase = "http://localhost:8000",
  [string]$AccessToken = $env:REDRANGE_ADMIN_ACCESS_TOKEN
)

if (-not $AccessToken) {
  Write-Error "Set REDRANGE_ADMIN_ACCESS_TOKEN or pass -AccessToken."
  exit 1
}

$headers = @{ Authorization = "Bearer $AccessToken" }
Invoke-RestMethod -Method Post -Uri "$ApiBase/admin/cleanup-expired" -Headers $headers
