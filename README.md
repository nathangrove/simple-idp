# Simple Identity Provider

A lightweight OpenID Connect (OIDC) Identity Provider implementation built with Express.js and TypeScript.

## Features

- 🔐 OpenID Connect Authentication
- 🔑 JWT-based Authorization
- 👤 User Management
- 🔄 OAuth 2.0 Authorization Flow
- 📱 Responsive Material Design UI
- 🗄️ SQLite Database Storage

## Getting Started

### Prerequisites

- Node.js (v16 or higher)
- npm or yarn

### Installation

```sh
# Clone the repository
git clone <repository-url>

# Install dependencies
npm install
```

### Configuration

Create a `.env` file in the root directory with the following variables:

```sh
NODE_ENV=development
JWT_PUBLIC_KEY=your_public_key
JWT_PRIVATE_KEY=your_private_key
```

### Development

Run the development server with hot reload:

```sh
npm run dev
```

### Production

This server is not intended or hardened for production use.

## API Endpoints

### OIDC Endpoints

- `GET /.well-known/openid-configuration` - OIDC Configuration
- `GET /.well-known/jwks.json` - JSON Web Key Set
- `GET /authorize` - Authorization Endpoint
- `POST /token` - Token Endpoint
- `GET /userinfo` - UserInfo Endpoint

### Authentication Endpoints

- `POST /login` - User Login
- `POST /register` - User Registration
- `GET /logout` - User Logout

## Database Schema

The application uses SQLite with the following models:

- User
- ServiceProvider
- Authorization
- Authentication

## Development Tools

- TypeScript
- Express.js
- Sequelize ORM
- EJS Templates
- Material Design (Materialize CSS)

## Security

- JWT-based Authentication
- Password Hashing with bcrypt
- Session Management
- CORS Protection

## License

MIT License

Copyright (c) 2024 [Your Name]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.