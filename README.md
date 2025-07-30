# MaAuth

A simple, powerful JWT-based authentication middleware for Express.js with built-in user management and database integration.

## Features

- 🔐 **JWT Authentication** - Secure token-based authentication
- 👤 **User Management** - Built-in user creation, deletion, and password management
- 🛡️ **Role-Based Access** - Admin and user roles with proper permissions
- 💾 **Database Integration** - Uses `easy-database` for seamless data storage
- 🚀 **Zero Configuration** - Works out of the box with sensible defaults
- 🔧 **Highly Configurable** - Customize everything to fit your needs

## Installation

```bash
npm install @maplex-studio/maauth
```

## Quick Start

```javascript
const express = require('express');
const createAuth = require('@maplex-studio/maauth');

const app = express();

// Add authentication middleware
app.use(createAuth());

// Your other routes
app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
  console.log('Login at: http://localhost:3000/api/v1/auth/login');
  console.log('Default credentials: root / changeme');
});
```

That's it! Your app now has full authentication with these routes:

- `POST /api/v1/auth/login` - User login
- `POST /api/v1/auth/password-change` - Change password
- `POST /api/v1/auth/create-user` - Create new user (admin only)
- `DELETE /api/v1/auth/delete-user/:username` - Delete user (admin only)
- `GET /api/v1/auth/users` - List all users (admin only)
- `GET /api/v1/auth/me` - Get current user info
- `POST /api/v1/auth/logout` - Logout

## Configuration

```javascript
const createAuth = require('@maplex-studio/maauth');

app.use(createAuth({
  jwtSecret: 'your-super-secret-key',    // JWT signing secret
  jwtExpiry: '24h',                       // Token expiry time
  apiPrefix: '/api/v1/auth',              // API route prefix
  saltRounds: 10,                         // bcrypt salt rounds
  database: {                             // Database options
    storage: './myauth.sqlite',
    logging: false
  }
}));
```

## API Reference

### Authentication Routes

#### `POST /api/v1/auth/login`
Login with username and password.

**Request:**
```json
{
  "username": "root",
  "password": "changeme"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Login successful",
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": 1,
    "username": "root",
    "role": "admin",
    "lastLogin": "2024-01-15T10:30:00.000Z"
  }
}
```

#### `POST /api/v1/auth/password-change`
Change password (requires authentication).

**Headers:**
```
Authorization: Bearer your-jwt-token
```

**Request (change own password):**
```json
{
  "currentPassword": "oldpassword",
  "newPassword": "newpassword"
}
```

**Request (admin changing another user's password):**
```json
{
  "targetUsername": "someuser",
  "newPassword": "newpassword"
}
```

#### `POST /api/v1/auth/create-user`
Create a new user (admin only).

**Headers:**
```
Authorization: Bearer admin-jwt-token
```

**Request:**
```json
{
  "username": "newuser",
  "password": "userpassword",
  "role": "user"
}
```

#### `DELETE /api/v1/auth/delete-user/:username`
Delete a user (admin only).

**Headers:**
```
Authorization: Bearer admin-jwt-token
```

#### `GET /api/v1/auth/users`
Get all users (admin only).

**Headers:**
```
Authorization: Bearer admin-jwt-token
```

**Response:**
```json
{
  "success": true,
  "users": [
    {
      "id": 1,
      "username": "root",
      "role": "admin",
      "createdAt": "2024-01-15T10:00:00.000Z",
      "lastLogin": "2024-01-15T10:30:00.000Z"
    }
  ]
}
```

#### `GET /api/v1/auth/me`
Get current user information.

**Headers:**
```
Authorization: Bearer your-jwt-token
```

## Protecting Routes

### Protect Individual Routes

```javascript
const express = require('express');
const createAuth = require('@maplex-studio/maauth');

const app = express();

// Add auth middleware
app.use(createAuth());

// Protected route - requires valid JWT
app.get('/protected', createAuth.protect(), (req, res) => {
  res.json({ 
    message: 'This is protected!',
    user: req.user  // JWT payload available here
  });
});

// Admin only route
app.get('/admin-only', createAuth.adminOnly(), (req, res) => {
  res.json({ 
    message: 'Admin access granted!',
    user: req.user 
  });
});
```

### Protect Route Groups

```javascript
const router = express.Router();

// All routes in this router require authentication
router.use(createAuth.protect());

router.get('/dashboard', (req, res) => {
  res.json({ message: 'Dashboard data', user: req.user });
});

router.get('/profile', (req, res) => {
  res.json({ message: 'User profile', user: req.user });
});

app.use('/app', router);
```

## Frontend Integration

### Login Example (JavaScript)

```javascript
async function login(username, password) {
  const response = await fetch('/api/v1/auth/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ username, password })
  });

  const data = await response.json();
  
  if (data.success) {
    // Store token
    localStorage.setItem('authToken', data.token);
    console.log('Logged in as:', data.user.username);
  } else {
    console.error('Login failed:', data.message);
  }
}
```

### Making Authenticated Requests

```javascript
async function makeAuthenticatedRequest(url) {
  const token = localStorage.getItem('authToken');
  
  const response = await fetch(url, {
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    }
  });

  return response.json();
}

// Usage
const userInfo = await makeAuthenticatedRequest('/api/v1/auth/me');
const protectedData = await makeAuthenticatedRequest('/protected');
```

### React Hook Example

```javascript
import { useState, useEffect } from 'react';

function useAuth() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('authToken');
    if (token) {
      fetch('/api/v1/auth/me', {
        headers: { 'Authorization': `Bearer ${token}` }
      })
      .then(res => res.json())
      .then(data => {
        if (data.success) {
          setUser(data.user);
        }
        setLoading(false);
      });
    } else {
      setLoading(false);
    }
  }, []);

  const login = async (username, password) => {
    const response = await fetch('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });

    const data = await response.json();
    if (data.success) {
      localStorage.setItem('authToken', data.token);
      setUser(data.user);
    }
    return data;
  };

  const logout = () => {
    localStorage.removeItem('authToken');
    setUser(null);
  };

  return { user, loading, login, logout };
}
```

## Advanced Usage

### Custom Database Configuration

```javascript
app.use(createAuth({
  database: {
    dialect: 'postgres',
    host: 'localhost',
    port: 5432,
    username: 'dbuser',
    password: 'dbpass',
    database: 'myapp'
  }
}));
```

### Custom JWT Configuration

```javascript
app.use(createAuth({
  jwtSecret: process.env.JWT_SECRET,
  jwtExpiry: '7d',  // 7 days
  saltRounds: 12    // Higher security
}));
```

### Environment Variables

```bash
# .env file
JWT_SECRET=your-super-secret-jwt-key
JWT_EXPIRY=24h
DB_PATH=./production.sqlite
```

```javascript
require('dotenv').config();

app.use(createAuth({
  jwtSecret: process.env.JWT_SECRET,
  jwtExpiry: process.env.JWT_EXPIRY,
  database: {
    storage: process.env.DB_PATH
  }
}));
```

## Error Handling

The middleware provides consistent error responses:

```json
{
  "success": false,
  "message": "Error description"
}
```

Common HTTP status codes:
- `400` - Bad Request (missing fields)
- `401` - Unauthorized (invalid credentials)
- `403` - Forbidden (insufficient permissions)
- `404` - Not Found (user doesn't exist)
- `409` - Conflict (username already exists)
- `500` - Internal Server Error

## Security Features

- **Password Hashing** - Uses bcrypt with configurable salt rounds
- **JWT Tokens** - Secure, stateless authentication
- **Role-Based Access** - Admin and user roles
- **Input Validation** - Validates all user inputs
- **Protected Root User** - Root user cannot be deleted
- **Active User Check** - Only active users can login

## Default Users

When first started, the system creates:
- **Username:** `root`
- **Password:** `changeme`
- **Role:** `admin`

**⚠️ Important:** Change the root password immediately in production!

## Best Practices

1. **Change Default Password**: Always change the root password
2. **Use Environment Variables**: Store JWT secret in environment variables
3. **Use HTTPS**: Always use HTTPS in production
4. **Token Expiry**: Set appropriate token expiry times
5. **Validate Input**: Always validate user input on frontend
6. **Handle Errors**: Implement proper error handling
7. **Logout Handling**: Clear tokens on logout

## Complete Example

```javascript
const express = require('express');
const createAuth = require('@maplex-studio/maauth');

const app = express();

// Configure authentication
app.use(createAuth({
  jwtSecret: process.env.JWT_SECRET || 'dev-secret-change-this',
  jwtExpiry: '24h',
  database: { storage: './myapp.sqlite' }
}));

// Public routes
app.get('/', (req, res) => {
  res.send('Welcome! Login at /api/v1/auth/login');
});

// Protected routes
app.get('/dashboard', createAuth.protect(), (req, res) => {
  res.json({
    message: `Welcome to dashboard, ${req.user.username}!`,
    user: req.user
  });
});

// Admin only routes
app.get('/admin', createAuth.adminOnly(), (req, res) => {
  res.json({
    message: 'Admin panel access granted',
    user: req.user
  });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`👤 Default: root / changeme`);
});
```

## License

MIT License - see LICENSE file for details.