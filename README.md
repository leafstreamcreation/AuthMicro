# Authentication Microservice

A secure, CORS-enabled, Dockerized authentication API built with Java 11, Maven, Spring Boot 2.7+, and Oracle 19c.

## Features

- **API Key Authentication**: Secure all endpoints with X-API-Key header validation
- **JWT Authentication**: Login endpoint with JWT token generation
- **2FA Support**: TOTP-based two-factor authentication
- **Role-based Authorization**: USER and ADMIN roles with proper access control
- **Password Security**: BCrypt hashing with strength 12
- **CORS Configuration**: Configured for trusted domains
- **Docker Support**: Complete containerization with Oracle database

## Technologies

- Java 11
- Spring Boot 2.7+
- Spring Security
- Spring Data JPA
- Oracle 19c
- JWT (JJWT)
- TOTP (Two-Factor Auth library)
- Maven
- Docker & Docker Compose

## Quick Start

### Using Docker Compose

1. Clone the repository
2. Create environment file from template:
   ```powershell
   Copy-Item .env.template .env
   ```
3. Edit `.env` file with your secrets
4. Build and run:
   ```powershell
   docker-compose up --build
   ```

## API Endpoints

### Public Endpoints

#### Health Check
```
GET /health
```

#### Login
```
POST /login
Content-Type: application/json
X-API-Key: your-api-key

{
  "email": "user@example.com",
  "password": "securePassword123!"
}
```

**Response (No 2FA):**
```json
{
  "token": "jwt.token.here",
  "expiresIn": 3600,
  "requires2FA": false
}
```

**Response (2FA Required):**
```json
{
  "requires2FA": true,
  "message": "TOTP verification required"
}
```

#### Sign Up
```
POST /signup
Content-Type: application/json
X-API-Key: your-api-key

{
  "email": "newuser@example.com",
  "password": "securePassword123!",
  "role": "USER"
}
```

### 2FA Endpoints

#### Verify TOTP Code
```
POST /2fa/verify?email=user@example.com
Content-Type: application/json
X-API-Key: your-api-key

{
  "code": 123456
}
```

#### Enable 2FA
```
POST /2fa/enable
Content-Type: application/json
X-API-Key: your-api-key
Authorization: Bearer jwt-token-here
```

### User Management (Authenticated)

#### Get Profile
```
GET /profile
X-API-Key: your-api-key
Authorization: Bearer jwt-token-here
```

#### Update User Credentials
```
POST /users/{id}/credentials
Content-Type: application/json
X-API-Key: your-api-key
Authorization: Bearer jwt-token-here

{
  "serviceCredentials": [
    {
      "serviceName": "example-service",
      "password": "servicePassword123!"
    }
  ]
}
```

### Admin-Only Endpoints

#### Create User
```
POST /users
Content-Type: application/json
X-API-Key: your-api-key
Authorization: Bearer admin-jwt-token

{
  "email": "admin@example.com",
  "password": "adminPassword123!",
  "role": "ADMIN"
}
```

#### List All Users
```
GET /users
X-API-Key: your-api-key
Authorization: Bearer admin-jwt-token
```

#### Update User Role
```
POST /users/{id}/role
Content-Type: application/json
X-API-Key: your-api-key
Authorization: Bearer admin-jwt-token

{
  "role": "ADMIN"
}
```

## Security Configuration

### API Key Authentication
All endpoints require a valid `X-API-Key` header:
```
X-API-Key: your-secret-api-key
```

### JWT Authentication
Protected endpoints require a valid JWT token:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### CORS Configuration
- Allowed origins: `*`
- Allowed methods: `GET`, `POST`
- Allowed headers: `X-API-Key`, `Content-Type`, `Authorization`
- Max age: 1800 seconds

## Database Schema

### AUTH_USERS Table
- `id`: Primary key (auto-generated)
- `email`: Unique user email
- `password_hash`: BCrypt hashed password
- `totp_secret`: TOTP secret for 2FA (nullable)
- `role`: USER or ADMIN
- `enabled`: Account status
- `created_at`: Account creation timestamp
- `updated_at`: Last update timestamp

### USER_SERVICE_CREDENTIALS Table
- `user_id`: Foreign key to AUTH_USERS
- `service_name`: Name of the service
- `password_hash`: BCrypt hashed service password

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `API_KEY_SECRET` | Secret for API key validation | (required) |
| `JWT_SECRET` | Secret for JWT signing | (required) |
| `DB_URL` | Oracle database URL | `jdbc:oracle:thin:@localhost:1521/XEPDB1` |
| `DB_USERNAME` | Database username | `admin` |
| `DB_PASSWORD` | Database password | `secureDbPass` |
| `AUTH_SERVICE_PORT` | host port | `secureDbPass` |

## Health Monitoring

The application includes health check endpoints:
- `/health` - Basic health status
- `/actuator/health` - Detailed health information

## Security Best Practices

1. **Change Default Secrets**: Always update `API_KEY_SECRET` and `JWT_SECRET` in production
2. **Use HTTPS**: Deploy behind HTTPS proxy in production
3. **Database Security**: Use strong database passwords and network isolation
4. **JWT Expiration**: Tokens expire in 1 hour by default
5. **Password Hashing**: BCrypt with strength 12 for all passwords
6. **2FA**: Enable TOTP-based two-factor authentication for enhanced security
