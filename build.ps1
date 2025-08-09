# Build script for Authentication Microservice (PowerShell)

Write-Host "Building Authentication Microservice..." -ForegroundColor Green

# Clean and build the project
Write-Host "Cleaning and building Maven project..." -ForegroundColor Yellow
mvn clean package -DskipTests

if ($LASTEXITCODE -eq 0) {
    Write-Host "Maven build successful!" -ForegroundColor Green
    
    # Build Docker image
    Write-Host "Building Docker image..." -ForegroundColor Yellow
    docker build -t auth-api:latest .
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Docker image built successfully!" -ForegroundColor Green
        Write-Host "You can now run: docker-compose up" -ForegroundColor Cyan
    } else {
        Write-Host "Docker build failed!" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "Maven build failed!" -ForegroundColor Red
    exit 1
}

Write-Host "Build completed successfully!" -ForegroundColor Green
