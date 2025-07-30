const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Database, DataTypes } = require('@maplex-studio/madatabase');

class AuthMiddleware {
  constructor(options = {}) {
    this.options = {
      jwtSecret: options.jwtSecret || 'your-super-secret-jwt-key-change-this',
      jwtExpiry: options.jwtExpiry || '24h',
      dbOptions: options.database || {},
      apiPrefix: options.apiPrefix || '/api/v1/auth',
      saltRounds: options.saltRounds || 10,
      ...options
    };

    this.db = null;
    this.router = express.Router();
    this.initialized = false;
  }

  async initialize() {
    if (this.initialized) return;

    // Initialize database
    this.db = new Database({
      storage: './auth.sqlite',
      ...this.options.dbOptions
    });

    await this.db.connect();

    // Create Users table
    this.db.createTable('User', {
      username: {
        type: DataTypes.STRING,
        unique: true,
        allowNull: false
      },
      password: {
        type: DataTypes.STRING,
        allowNull: false
      },
      role: {
        type: DataTypes.STRING,
        defaultValue: 'user'
      },
      isActive: {
        type: DataTypes.BOOLEAN,
        defaultValue: true
      },
      lastLogin: DataTypes.DATE
    });

    await this.db.syncTables();

    // Create root user if not exists
    const existingRoot = await this.db.findOne('User', {
      where: { username: 'root' }
    });

    if (!existingRoot) {
      const hashedPassword = await bcrypt.hash('changeme', this.options.saltRounds);
      await this.db.insert('User', {
        username: 'root',
        password: hashedPassword,
        role: 'admin'
      });
      console.log('✅ Root user created with password "changeme"');
    }

    this.setupRoutes();
    this.initialized = true;
  }

  setupRoutes() {
    // Middleware to parse JSON
    this.router.use(express.json());

    // Login route
    this.router.post('/login', async (req, res) => {
      try {
        const { username, password } = req.body;

        if (!username || !password) {
          return res.status(400).json({
            success: false,
            message: 'Username and password are required'
          });
        }

        // Find user
        const user = await this.db.findOne('User', {
          where: { username, isActive: true }
        });

        if (!user) {
          return res.status(401).json({
            success: false,
            message: 'Invalid credentials'
          });
        }

        // Check password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
          return res.status(401).json({
            success: false,
            message: 'Invalid credentials'
          });
        }

        // Update last login
        await this.db.update('User', 
          { lastLogin: new Date() }, 
          { id: user.id }
        );

        // Generate JWT
        const token = jwt.sign(
          { 
            id: user.id, 
            username: user.username, 
            role: user.role 
          },
          this.options.jwtSecret,
          { expiresIn: this.options.jwtExpiry }
        );

        res.json({
          success: true,
          message: 'Login successful',
          token,
          user: {
            id: user.id,
            username: user.username,
            role: user.role,
            lastLogin: user.lastLogin
          }
        });

      } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
          success: false,
          message: 'Internal server error'
        });
      }
    });

    // Password change route
    this.router.post('/password-change', this.authenticateToken.bind(this), async (req, res) => {
      try {
        const { currentPassword, newPassword, targetUsername } = req.body;
        const currentUser = req.user;

        if (!newPassword) {
          return res.status(400).json({
            success: false,
            message: 'New password is required'
          });
        }

        let targetUser;

        // If targetUsername is provided and user is admin, allow changing other users' passwords
        if (targetUsername && currentUser.role === 'admin') {
          targetUser = await this.db.findOne('User', {
            where: { username: targetUsername }
          });
          
          if (!targetUser) {
            return res.status(404).json({
              success: false,
              message: 'Target user not found'
            });
          }
        } else {
          // Changing own password
          targetUser = await this.db.findById('User', currentUser.id);
          
          if (!currentPassword) {
            return res.status(400).json({
              success: false,
              message: 'Current password is required'
            });
          }

          // Verify current password
          const validPassword = await bcrypt.compare(currentPassword, targetUser.password);
          if (!validPassword) {
            return res.status(401).json({
              success: false,
              message: 'Current password is incorrect'
            });
          }
        }

        // Hash new password
        const hashedNewPassword = await bcrypt.hash(newPassword, this.options.saltRounds);

        // Update password
        await this.db.update('User', 
          { password: hashedNewPassword }, 
          { id: targetUser.id }
        );

        res.json({
          success: true,
          message: `Password changed successfully for ${targetUser.username}`
        });

      } catch (error) {
        console.error('Password change error:', error);
        res.status(500).json({
          success: false,
          message: 'Internal server error'
        });
      }
    });

    // Create user route (admin only)
    this.router.post('/create-user', this.authenticateToken.bind(this), this.requireAdmin.bind(this), async (req, res) => {
      try {
        const { username, password, role = 'user' } = req.body;

        if (!username || !password) {
          return res.status(400).json({
            success: false,
            message: 'Username and password are required'
          });
        }

        // Check if user already exists
        const existingUser = await this.db.findOne('User', {
          where: { username }
        });

        if (existingUser) {
          return res.status(409).json({
            success: false,
            message: 'Username already exists'
          });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, this.options.saltRounds);

        // Create user
        const newUser = await this.db.insert('User', {
          username,
          password: hashedPassword,
          role: ['user', 'admin'].includes(role) ? role : 'user'
        });

        res.json({
          success: true,
          message: 'User created successfully',
          user: {
            id: newUser.id,
            username: newUser.username,
            role: newUser.role,
            isActive: newUser.isActive
          }
        });

      } catch (error) {
        console.error('Create user error:', error);
        res.status(500).json({
          success: false,
          message: 'Internal server error'
        });
      }
    });

    // Delete user route (admin only)
    this.router.delete('/delete-user/:username', this.authenticateToken.bind(this), this.requireAdmin.bind(this), async (req, res) => {
      try {
        const { username } = req.params;
        const currentUser = req.user;

        if (username === 'root') {
          return res.status(403).json({
            success: false,
            message: 'Cannot delete root user'
          });
        }

        if (username === currentUser.username) {
          return res.status(403).json({
            success: false,
            message: 'Cannot delete your own account'
          });
        }

        // Check if user exists
        const userToDelete = await this.db.findOne('User', {
          where: { username }
        });

        if (!userToDelete) {
          return res.status(404).json({
            success: false,
            message: 'User not found'
          });
        }

        // Delete user
        await this.db.delete('User', { username });

        res.json({
          success: true,
          message: `User ${username} deleted successfully`
        });

      } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({
          success: false,
          message: 'Internal server error'
        });
      }
    });

    // Get users route (admin only)
    this.router.get('/users', this.authenticateToken.bind(this), this.requireAdmin.bind(this), async (req, res) => {
      try {
        const users = await this.db.searchFields('User', 
          { isActive: true }, 
          ['id', 'username', 'role', 'createdAt', 'lastLogin']
        );

        res.json({
          success: true,
          users: users
        });

      } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({
          success: false,
          message: 'Internal server error'
        });
      }
    });

    // Get current user info
    this.router.get('/me', this.authenticateToken.bind(this), async (req, res) => {
      try {
        const user = await this.db.findById('User', req.user.id);
        
        res.json({
          success: true,
          user: {
            id: user.id,
            username: user.username,
            role: user.role,
            createdAt: user.createdAt,
            lastLogin: user.lastLogin
          }
        });

      } catch (error) {
        console.error('Get user info error:', error);
        res.status(500).json({
          success: false,
          message: 'Internal server error'
        });
      }
    });

    // Logout route (mainly for frontend to clear token)
    this.router.post('/logout', (req, res) => {
      res.json({
        success: true,
        message: 'Logged out successfully'
      });
    });
  }

  // JWT Authentication middleware
  authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Access token required'
      });
    }

    jwt.verify(token, this.options.jwtSecret, (err, user) => {
      if (err) {
        return res.status(403).json({
          success: false,
          message: 'Invalid or expired token'
        });
      }
      req.user = user;
      next();
    });
  }

  // Admin role middleware
  requireAdmin(req, res, next) {
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }
    next();
  }

  // Main middleware function
  middleware() {
    return async (req, res, next) => {
      if (!this.initialized) {
        await this.initialize();
      }

      // Mount auth routes
      if (req.path.startsWith(this.options.apiPrefix)) {
        const subPath = req.path.substring(this.options.apiPrefix.length);
        req.url = subPath || '/';
        return this.router(req, res, next);
      }

      next();
    };
  }

  // Helper method to get authentication middleware for protecting routes
  protect() {
    return async (req, res, next) => {
      if (!this.initialized) {
        await this.initialize();
      }
      this.authenticateToken(req, res, next);
    };
  }

  // Helper method to get admin middleware for protecting admin routes
  adminOnly() {
    return async (req, res, next) => {
      if (!this.initialized) {
        await this.initialize();
      }
      this.authenticateToken(req, res, (err) => {
        if (err) return next(err);
        this.requireAdmin(req, res, next);
      });
    };
  }
}

// Factory function
function createAuth(options = {}) {
  const authMiddleware = new AuthMiddleware(options);
  return authMiddleware.middleware();
}

// Export additional helpers
createAuth.protect = (options = {}) => {
  const authMiddleware = new AuthMiddleware(options);
  return authMiddleware.protect();
};

createAuth.adminOnly = (options = {}) => {
  const authMiddleware = new AuthMiddleware(options);
  return authMiddleware.adminOnly();
};

module.exports = createAuth;