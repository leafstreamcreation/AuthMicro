# Deployment Guide

## Prerequisites

Before running this Authentication Microservice, ensure you have the following installed:

### Required Software
1. **Java 11 or higher**
   - Download from: https://adoptopenjdk.net/
   - Verify: `java -version`

2. **Maven 3.6 or higher**
   - Download from: https://maven.apache.org/download.cgi
   - Verify: `mvn -version`

3. **Docker and Docker Compose**
   - Download from: https://www.docker.com/products/docker-desktop
   - Verify: `docker --version` and `docker-compose --version`

## Quick Start with Docker (Recommended)

1. **Clone and navigate to project directory**
   ```powershell
   cd "c:\Users\Cosmi\Desktop\Projects\AuthMicro"
   ```

2. **Create environment file**
   ```powershell
   Copy-Item .env.template .env
   ```

3. **Edit .env file** with your secrets:
   ```
   API_KEY_SECRET=your-super-secret-api-key-here-change-this
   JWT_SECRET=your-super-secret-jwt-signing-key-here-change-this
   ```

4. **Build and run with Docker Compose**
   ```powershell
   docker-compose up --build
   ```

5. **Test the service**
   - Health check: http://localhost:8080/health
   - Use the test script: `.\test-api.ps1`

## Manual Installation (If Docker is not available)

1. **Install and setup Oracle 19c database**
   - Create database user: `admin`
   - Create database: `XEPDB1`
   - Grant necessary permissions

2. **Update application.properties**
   ```properties
   spring.datasource.url=jdbc:oracle:thin:@localhost:1521/XEPDB1
   spring.datasource.username=admin
   spring.datasource.password=your-db-password
   ```

3. **Build the application**
   ```powershell
   mvn clean package
   ```

4. **Run the application**
   ```powershell
   java -jar target/auth-micro-0.0.1-SNAPSHOT.jar
   ```

## Configuration

### Environment Variables
Set these environment variables in your `.env` file or system:
- `API_KEY_SECRET`: Secret key for API authentication
- `JWT_SECRET`: Secret key for JWT token signing
- `DB_URL`: Database connection URL
- `DB_USERNAME`: Database username
- `DB_PASSWORD`: Database password

### Security Notes
1. **Always change default secrets** in production
2. **Use HTTPS** in production environments
3. **Secure your database** with proper network configuration
4. **Regular security updates** for dependencies

## Testing

### Automated Testing
```powershell
mvn test
```

### Manual API Testing
Use the provided PowerShell script:
```powershell
.\test-api.ps1
```

Or test individual endpoints with tools like Postman or curl.

### Sample API Calls

**Health Check:**
```
GET http://localhost:8080/health
```

**Sign Up:**
```
POST http://localhost:8080/signup
Headers: X-API-Key: your-api-key
Body: {
  "email": "user@example.com",
  "password": "securePassword123!",
  "role": "USER"
}
```

**Login:**
```
POST http://localhost:8080/login
Headers: X-API-Key: your-api-key
Body: {
  "email": "user@example.com",
  "password": "securePassword123!"
}
```

## Troubleshooting

### Common Issues

1. **Port 8080 already in use**
   - Stop other services on port 8080
   - Or change port in `application.properties`: `server.port=8081`

2. **Database connection issues**
   - Verify Oracle database is running
   - Check connection string and credentials
   - Ensure database user has proper permissions

3. **Docker build fails**
   - Ensure Docker Desktop is running
   - Check available disk space
   - Try: `docker system prune` to clean up

4. **Maven build fails**
   - Verify Java 11+ is installed
   - Check internet connection for dependency downloads
   - Clear Maven cache: `mvn clean`

### Logs and Monitoring
- Application logs: Check console output or logs directory
- Database logs: Check Oracle logs for connection issues
- Docker logs: `docker-compose logs auth-service`

## Production Deployment

For production deployment:
1. Use environment-specific configuration files
2. Set up proper SSL/TLS certificates
3. Configure firewall rules
4. Set up monitoring and logging
5. Configure backup strategies for the database
6. Use secrets management (Kubernetes secrets, HashiCorp Vault, etc.)

## Support

For issues and questions:
1. Check the troubleshooting section above
2. Review application logs
3. Consult the README.md for detailed API documentation
