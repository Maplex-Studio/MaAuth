# @maplex-lib/auth

A comprehensive authentication middleware for Express.js applications with JWT token management, user roles, and database integration.

## ✨ Features

- 🔐 **JWT Authentication** - Secure token-based authentication
- 👥 **Role-Based Access Control** - Support for user and admin roles
- 🛡️ **Root User Management** - Special root user with elevated privileges
- 🔑 **Password Management** - Secure password hashing and change functionality
- 📊 **User Management** - Complete CRUD operations for users
- 🗄️ **Database Integration** - Works with @maplex-lib/database
- 🚀 **Easy Setup** - Simple configuration and initialization
- 🔒 **Middleware Protection** - Protect routes with authentication requirements

## 📦 Installation

```bash
npm install @maplex-lib/auth @maplex-lib/database
```

## 🚀 Quick Start

```javascript
import express from 'express';
import { Database } from '@maplex-lib/database';
import createAuth from '@maplex-lib/auth';

const app = express();
const db = new Database();

// Initialize auth middleware
const auth = createAuth({
  database: db,
  jwtSecret: 'your-secret-key',
  rootUsername: 'admin',
  rootPassword: 'secure-password'
});

// Apply auth middleware
app.use(auth);

// Protected route example
app.get('/protected', createAuth.protect({ database: db }), (req, res) => {
  res.json({ message: 'This is a protected route!' });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
```

## ⚙️ Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `database` | `Database` | **Required** | Database instance from @maplex-lib/database |
| `jwtSecret` | `string` | `'your-super-secret-jwt-key-change-this'` | Secret key for JWT signing |
| `jwtExpiry` | `number \| string` | `'24h'` | Token expiration time |
| `apiPrefix` | `string` | `'/api/v1/auth'` | API endpoint prefix |
| `saltRounds` | `number` | `10` | bcrypt salt rounds for password hashing |
| `rootUsername` | `string` | `'root'` | Default root user username |
| `rootPassword` | `string` | `'changeme'` | Default root user password |

## 🛣️ API Endpoints

All endpoints are prefixed with `/api/v1/auth` by default.

### Authentication

#### `POST /login`
Authenticate user and receive JWT token.

**Request Body:**
```json
{
  "username": "string",
  "password": "string"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Login successful",
  "token": "jwt-token-here",
  "user": {
    "id": 1,
    "username": "john_doe",
    "role": "user",
    "isRoot": false,
    "isActive": true
  }
}
```

#### `POST /logout`
Logout user (client-side token removal).

### User Management

#### `GET /me`
Get current user information (requires authentication).

#### `POST /password-change`
Change password (requires authentication).

**Request Body:**
```json
{
  "currentPassword": "string",
  "newPassword": "string",
  "targetUsername": "string" // Optional, admin only
}
```

#### `POST /create-user` (Admin Only)
Create a new user.

**Request Body:**
```json
{
  "username": "string",
  "password": "string",
  "role": "user" // or "admin"
}
```

#### `GET /users` (Admin Only)
Get list of all users.

#### `DELETE /delete-user/:username` (Admin Only)
Delete a user by username.

#### `GET /root` (Root Only)
Get root user information.

## 🛡️ Middleware Protection

### Basic Protection
```javascript
app.get('/protected-route', createAuth.protect({ database: db }), (req, res) => {
  // Only authenticated users can access
  console.log('User:', req.user);
  res.json({ message: 'Protected content' });
});
```

### Admin Only Protection
```javascript
app.get('/admin-only', createAuth.adminOnly({ database: db }), (req, res) => {
  // Only admin users can access
  res.json({ message: 'Admin content' });
});
```

### Root Only Protection
```javascript
app.get('/root-only', createAuth.rootOnly({ database: db }), (req, res) => {
  // Only root user can access
  res.json({ message: 'Root content' });
});
```

## 📊 User Roles

The system supports three levels of access:

| Role | Description | Permissions |
|------|-------------|-------------|
| **User** | Standard user | Basic authenticated access |
| **Admin** | Administrator | User management, all user permissions |
| **Root** | Super administrator | All permissions, cannot be deleted |

## 🔧 Advanced Usage

### Custom Authentication Check
```javascript
import { AuthRequest } from '@maplex-lib/auth';

app.get('/custom-protected', createAuth.protect({ database: db }), (req: AuthRequest, res) => {
  const user = req.user; // Contains: id, username, role, isRoot
  
  if (user?.role === 'admin') {
    res.json({ message: 'Welcome admin!' });
  } else {
    res.json({ message: 'Welcome user!' });
  }
});
```

### Multiple Auth Instances
```javascript
const publicAuth = createAuth({
  database: publicDb,
  apiPrefix: '/api/public/auth'
});

const adminAuth = createAuth({
  database: adminDb,
  apiPrefix: '/api/admin/auth'
});

app.use(publicAuth);
app.use(adminAuth);
```

## 📝 TypeScript Support

Full TypeScript support with comprehensive type definitions:

```typescript
import createAuth, { AuthRequest, UserPayload, AuthOptions } from '@maplex-lib/auth';

interface CustomRequest extends AuthRequest {
  customProperty?: string;
}

app.get('/typed-route', createAuth.protect({ database: db }), (req: CustomRequest, res) => {
  const user: UserPayload = req.user!;
  // Full type safety
});
```

## 🔒 Security Features

- **Password Hashing**: Uses bcrypt with configurable salt rounds
- **JWT Tokens**: Secure token-based authentication
- **Role-Based Access**: Granular permission control
- **Input Validation**: Validates all user inputs
- **Error Handling**: Secure error messages without information leakage
- **Active User Check**: Only active users can authenticate

## 🚨 Important Security Notes

1. **Change Default Credentials**: Always change the default root username and password in production
2. **Use Strong JWT Secret**: Use a cryptographically secure random string for JWT secret
3. **HTTPS Only**: Always use HTTPS in production environments
4. **Token Storage**: Store JWT tokens securely on the client side
5. **Regular Updates**: Keep dependencies updated for security patches

## 📚 Examples

Check out the `/examples` directory for complete implementation examples:

- Basic setup
- Role-based routing
- Custom middleware
- Frontend integration

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

## 📄 License

MIT License - see LICENSE file for details.
