# Zero-Trust Access Gateway - Startup Guide

## Prerequisites
- Node.js (v16 or higher)
- npm or yarn

## Installation

1. Install dependencies:
   ```bash
   npm install
   ```

2. The project includes self-signed certificates for development in the `certs/` directory (already generated)

## Running the Application

### 1. Build the application:
```bash
npm run build
```

### 2. Run the services separately:

**Terminal 1 - Start the Gateway:**
```bash
npm run start:dev
```
The gateway will start on port 3000.

**Terminal 2 - Start the Users Service:**
```bash
npx ts-node microservices/users-service/main.ts
```
The users service will start on port 3001.

**Terminal 3 - Start the Orders Service:**
```bash
npx ts-node microservices/orders-service/main.ts
```
The orders service will start on port 3002.

**Terminal 4 - Start the Permissions Service:**
```bash
npx ts-node microservices/permissions-service/main.ts
```
The permissions service will start on port 3003.

## Testing the Gateway

### 1. Generate a JWT token
You can use online JWT tools with the secret `your-super-secret-jwt-key-here` (defined in `.env`) and payload like:
```json
{
  "userId": "test-user",
  "roles": ["user"],
  "sessionId": "session123"
}
```

### 2. Make requests through the gateway:
```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" http://localhost:3000/users
```

## Configuration

The main configuration is in the `.env` file:
- `JWT_SECRET`: Secret for JWT token validation
- `FORCE_MTLS`: Whether to require mTLS (set to `true` for development)
- Port configurations and other settings

## Docker Support

The project includes a `docker-compose.yml` file that can run all services:
```bash
docker-compose up
```

## Architecture Overview

The gateway implements a complete zero-trust architecture:
1. **Authentication**: Validates JWT tokens
2. **Trust Scoring**: Calculates risk based on various factors
3. **Policy Evaluation**: Determines allow/deny/challenge decisions
4. **mTLS Proxy**: Forwards requests securely to microservices
5. **Audit Logging**: Records all access decisions
6. **Metrics**: Collects performance and security metrics

## Development

- Source code is in the `src/` directory
- Tests are in `__tests__/` directories next to their source files
- Microservices are in the `microservices/` directory
- Certificates are in the `certs/` directory

## Testing

Run all tests:
```bash
npm test
```

Run tests with coverage:
```bash
npm run test:cov
```