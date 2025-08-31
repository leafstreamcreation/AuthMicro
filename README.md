# AuthMicro - Enterprise Authentication Microservice

![Java](https://img.shields.io/badge/java-21-orange.svg)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.5.4-brightgreen.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Coverage](https://img.shields.io/badge/coverage-85%25-green.svg)

A secure, production-ready authentication microservice built with Spring Boot 3.5.4 and Java 21, featuring JWT authentication, TOTP 2FA, API key security, and comprehensive testing infrastructure.

## 🚀 Features

### Core Authentication
- **JWT Token Authentication** - Secure token-based authentication with configurable expiration
- **Two-Factor Authentication (2FA)** - TOTP implementation with QR code generation  
- **API Key Security** - Service-to-service authentication with API keys
- **Role-Based Access Control** - Granular permission management (USER, ADMIN, SERVICE)
- **Password Security** - BCrypt hashing with strength validation
- **Account Security** - Account lockout, password reset, recovery tokens

### Security Features
- **CORS Configuration** - Configurable cross-origin resource sharing
- **SQL Injection Prevention** - JPA query parameterization
- **Input Validation** - Comprehensive request validation with Jakarta Validation
- **Rate Limiting Ready** - Infrastructure for request throttling
- **Security Headers** - HTTP security headers implementation
- **Audit Logging** - Authentication event tracking

### Enterprise Features
- **Multi-Database Support** - Oracle 19c, PostgreSQL, H2 compatibility
- **Docker Support** - Complete containerization with Docker Compose
- **Monitoring Ready** - Actuator endpoints for health checks
- **Configuration Management** - Externalized configuration with profiles
- **Error Handling** - Comprehensive exception handling and logging
- **Service Credentials** - Multi-service authentication support

## 🧪 Testing Infrastructure

The project includes comprehensive testing with the latest libraries:

- **Unit Tests**: JUnit 5, Mockito 5.12.0, AssertJ
- **Integration Tests**: TestContainers with PostgreSQL
- **Security Tests**: Authentication, authorization, injection prevention
- **Performance Tests**: Load testing, memory monitoring  
- **Coverage**: JaCoCo with 85%+ requirement

### Running Tests

```bash
# Unit tests only
mvn clean test

# All tests including integration
mvn clean verify

# Security tests
mvn test -Dtest=SecurityTest

# Performance tests  
mvn test -Dtest=PerformanceTest

# Generate coverage report
mvn clean verify jacoco:report
```

## 📚 API Documentation

### Authentication Endpoints

#### User Registration
```http
POST /signup
Content-Type: application/json
X-API-Key: your-api-key

{
  "email": "user@example.com",
  "password": "securePassword123",
  "role": "USER"
}
```

#### User Login
```http
POST /login
Content-Type: application/json
X-API-Key: your-api-key

{
  "email": "user@example.com", 
  "password": "securePassword123"
}

Response:
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiresIn": 3600,
  "requiresTwoFactor": false
}
```

#### Service Login (Multi-Service Support)
```http
POST /service-login
Content-Type: application/json
X-API-Key: your-api-key

{
  "email": "user@example.com",
  "password": "securePassword123", 
  "serviceName": "payment-service"
}
```

### Two-Factor Authentication

#### Enable 2FA
```http
POST /2fa/enable
Authorization: Bearer {jwt-token}
X-API-Key: your-api-key

Response:
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qrCode": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgA...",
  "backupCodes": ["123456", "789012", ...]
}
```

#### Verify 2FA
```http
POST /2fa/verify
Authorization: Bearer {jwt-token}
X-API-Key: your-api-key

{
  "totpCode": "123456"
}
```

## 🛠️ Quick Start

### Prerequisites
- Java 21+
- Maven 3.9+
- Docker & Docker Compose
- Oracle 19c or PostgreSQL (for production)

### Local Development Setup

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/auth-micro.git
cd auth-micro
```

2. **Start dependencies with Docker Compose**
```bash
docker-compose up -d postgres
```

3. **Run the application**
```bash
mvn spring-boot:run -Dspring.profiles.active=dev
```

4. **Access the application**
- API Base URL: `http://localhost:8080`
- Health Check: `http://localhost:8080/actuator/health`

### Docker Deployment

```bash
# Build the application
mvn clean package

# Run with Docker Compose
docker-compose up --build
```

## 🔧 Technology Stack

- **Runtime**: Java 21 with Jakarta EE
- **Framework**: Spring Boot 3.5.4, Spring Security 6.x
- **Database**: JPA 3.x with Oracle 19c (production), PostgreSQL (testing)
- **Security**: JJWT 0.11.5, j256 Two-Factor Auth, BCrypt
- **Testing**: JUnit 5, Mockito 5.12.0, TestContainers 1.19.8
- **Build**: Maven 3.9+, Docker, CI/CD with GitHub Actions

## 🛡️ Security Features

### Security Headers
- **CSRF Protection** - Enabled for state-changing operations
- **CORS Configuration** - Restrictive cross-origin policies
- **Content Security Policy** - XSS prevention
- **X-Frame-Options** - Clickjacking prevention

### Authentication Security
- **Password Strength** - Configurable complexity requirements
- **Account Lockout** - Brute force protection
- **Token Expiration** - Configurable JWT lifetimes
- **Rate Limiting** - API request throttling (infrastructure ready)

### Data Protection
- **Encryption at Rest** - Database encryption
- **Encryption in Transit** - HTTPS/TLS
- **Secrets Management** - External secret stores integration ready

## 📋 Project Status

### ✅ Completed Features
- JWT Authentication with configurable expiration
- TOTP 2FA with QR code generation
- API Key security for service authentication
- Role-based access control (USER, ADMIN, SERVICE)
- Spring Boot 3.5.4 and Java 21 compatibility
- Comprehensive testing infrastructure with latest libraries
- Docker containerization with Oracle/PostgreSQL support
- CI/CD pipeline configuration with GitHub Actions
- Security testing (SQL injection prevention, JWT validation)
- Performance testing with load and memory monitoring
- Integration testing with TestContainers

### 🔄 Test Implementation Status
- **Unit Tests**: Framework setup complete, endpoint testing implemented
- **Integration Tests**: TestContainer configuration with PostgreSQL
- **Security Tests**: Comprehensive security validation suite
- **Performance Tests**: Concurrent load testing and memory monitoring
- **CI/CD Ready**: Maven plugins configured for pipeline execution

## 🤝 Contributing

1. **Fork the repository**
2. **Create feature branch**: `git checkout -b feature/amazing-feature`
3. **Write tests** for new functionality
4. **Ensure all tests pass**: `mvn clean verify`
5. **Commit changes**: `git commit -m 'Add amazing feature'`
6. **Push to branch**: `git push origin feature/amazing-feature`
7. **Open Pull Request**

## 📄 License

This project is licensed under the MIT License.

---

**AuthMicro** - *Secure, Scalable, Enterprise-Ready Authentication with Comprehensive Testing*
