# API Testing Examples for Authentication Microservice

# Set your API key and base URL
$API_KEY = "1Pass2rule.th3m4ll"
$BASE_URL = "http://192.168.132.17:8062"

# Health Check
Write-Host "Testing Health Check..." -ForegroundColor Green
Invoke-RestMethod -Uri "$BASE_URL/health" -Method GET

# Sign Up
Write-Host "`nTesting Sign Up..." -ForegroundColor Green
$signupBody = @{
    email = "test@example.com"
    password = "securePassword123!"
    role = "USER"
}

$signupHeaders = @{
    "Content-Type" = "application/json"
    "X-API-Key" = $API_KEY
}

Invoke-RestMethod -Uri "$BASE_URL/signup" -Method POST -Body ($signupBody | ConvertTo-Json) -Headers $signupHeaders

# Login
Write-Host "`nTesting Login..." -ForegroundColor Green
$loginBody = @{
    email = "test@example.com"
    password = "securePassword123!"
}

$loginHeaders = @{
    "Content-Type" = "application/json"
    "X-API-Key" = $API_KEY
}

$loginResponse = Invoke-RestMethod -Uri "$BASE_URL/login" -Method POST -Body ($loginBody | ConvertTo-Json) -Headers $loginHeaders

# Extract JWT token
Write-Host "`nLogin Response:" -ForegroundColor Yellow
Write-Host ($loginResponse | ConvertTo-Json)

# Example of using JWT token for authenticated requests
$JWT_TOKEN = $loginResponse.token  # Use actual token from response

if ($JWT_TOKEN) {
    # Get Profile
    Write-Host "`nTesting Get Profile..." -ForegroundColor Green
    $authHeaders = @{
        "X-API-Key" = $API_KEY
        "Authorization" = "Bearer $JWT_TOKEN"
    }
    
    Invoke-RestMethod -Uri "$BASE_URL/profile" -Method GET -Headers $authHeaders

    # Enable 2FA
    Write-Host "`nTesting Enable 2FA..." -ForegroundColor Green
    Invoke-RestMethod -Uri "$BASE_URL/2fa/enable" -Method POST -Headers $authHeaders
}

Write-Host "`nAPI testing completed!" -ForegroundColor Green
Write-Host "Remember to:" -ForegroundColor Yellow
Write-Host "1. Replace 'your-api-key-here' with your actual API key" -ForegroundColor Yellow
Write-Host "2. Ensure the service is running on http://localhost:8080" -ForegroundColor Yellow
