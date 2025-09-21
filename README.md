### Local Development
Start the server locally:
```bash
npm run start
```
The service will run on `http://localhost:3000` (or your configured port).


# Auth Service

This is a Node.js Express-based authentication microservice for Single Sign-On (SSO) in the ONLINE_BAZAR platform. It supports JWT authentication, password hashing, and is designed to run on AWS Lambda using serverless-express.

## Features
- User authentication (login, register)
- JWT token generation and verification
- Password hashing with bcryptjs
- AWS Lambda compatibility
- Environment variable support via dotenv

## Project Structure

```
src/
  server.js           # Express app entry point
  auth/
    auth.controller.js    # Auth logic (login, register)
    auth.middleware.js    # Middleware for auth checks
  utils/
    authUtils.js          # Helper functions for auth
    jwt.js                # JWT utilities
    util.js               # General utilities
lambda.js                 # AWS Lambda handler
```

## Setup

1. **Clone the repository:**
   ```bash
   git clone <repo-url>
   cd auth-service
   ```
2. **Install dependencies:**
   ```bash
   npm install
   ```
3. **Configure environment variables:**
   Create a `.env` file in the root directory:
   ```env
   PORT=3000
   JWT_SECRET=your_jwt_secret
   AWS_REGION=your_aws_region
   # Add other variables as needed
   ```

### AWS Lambda Deployment
The service is compatible with AWS Lambda using `@vendia/serverless-express`. Deploy `lambda.js` as your Lambda handler.

## API Endpoints

### POST /auth/register
Register a new user.
**Body:** `{ "username": "string", "password": "string" }`

### POST /auth/login
Authenticate user and receive JWT.
**Body:** `{ "username": "string", "password": "string" }`

### GET /auth/profile
Get user profile (requires JWT in Authorization header).

## Environment Variables
- `PORT`: Server port (default: 3000)
- `JWT_SECRET`: Secret key for JWT signing
- `AWS_REGION`: AWS region for SDK

## Dependencies
- express
- jsonwebtoken
- bcryptjs
- dotenv
- aws-sdk
- @vendia/serverless-express

## License
MIT
