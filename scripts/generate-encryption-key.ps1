$bytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
$key = [Convert]::ToBase64String($bytes)
Write-Host "Add this to your local .env file as VAULTCARE_ENCRYPTION_KEY=$key"
Write-Host "Keep this key private. If lost, encrypted secrets cannot be recovered. Do not commit .env."
