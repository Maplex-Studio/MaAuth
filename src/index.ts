import express, { Request, Response, NextFunction, Router } from 'express';
import bcrypt from 'bcryptjs';
import jwt, { SignOptions } from 'jsonwebtoken';
import type { StringValue } from "ms";
import { Database, DataTypes } from '@maplex-lib/database';

// Types and Interfaces
interface User {
  id: number;
  username: string;
  password: string;
  role: 'user' | 'admin';
  isActive: boolean;
  isRoot: boolean;
  lastLogin?: Date;
  createdAt?: Date;
  updatedAt?: Date;
}

interface UserPayload {
  id: number;
  username: string;
  role: 'user' | 'admin';
  isRoot: boolean;
}

interface AuthRequest<P = any, ResBody = any, ReqBody = any> extends Request<P, ResBody, ReqBody> {
  user?: UserPayload;
}

interface LoginRequest {
  username: string;
  password: string;
}

interface PasswordChangeRequest {
  currentPassword?: string;
  newPassword: string;
  targetUsername?: string;
}

interface CreateUserRequest {
  username: string;
  password: string;
  role?: 'user' | 'admin';
}

interface AuthOptions {
  database?: Database;
  jwtSecret?: string;
  jwtExpiry?: number | StringValue | undefined;
  dbOptions?: object;
  apiPrefix?: string;
  saltRounds?: number;
  rootUsername?: string;
  rootPassword?: string;
}

interface RequiredAuthOptions {
  database: Database;
  jwtSecret: string;
  jwtExpiry: number | StringValue | undefined;
  dbOptions: object;
  apiPrefix: string;
  saltRounds: number;
  rootUsername: string;
  rootPassword: string;
}

interface ApiResponse<T = any> {
  success: boolean;
  message: string;
  data?: T;
}

interface LoginResponse extends ApiResponse {
  token?: string;
  user?: Omit<User, 'password'>;
}

interface UserResponse extends ApiResponse {
  user?: Omit<User, 'password'>;
  users?: Omit<User, 'password'>[];
}

class AuthMiddleware {
  private options: RequiredAuthOptions;
  private db: Database;
  private router: Router;
  private initialized: boolean = false;
  private rootUserId: number | null = null;

  constructor(options: AuthOptions = {}) {
    if (!options.database) {
      throw new Error('Database instance is required');
    }

    this.options = {
      database: options.database,
      jwtSecret: options.jwtSecret || 'your-super-secret-jwt-key-change-this',
      jwtExpiry: options.jwtExpiry || '24h',
      dbOptions: options.dbOptions || {},
      apiPrefix: options.apiPrefix || '/api/v1/auth',
      saltRounds: options.saltRounds || 10,
      rootUsername: options.rootUsername || 'root',
      rootPassword: options.rootPassword || 'changeme',
    };

    this.db = this.options.database;
    this.router = express.Router();
  }

  async initialize(): Promise<void> {
    if (this.initialized) return;

    // Create User table
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
      isRoot: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
      },
      lastLogin: {
        type: DataTypes.DATE,
        allowNull: true
      }
    });

    await this.db.syncTables();

    // Check for existing root user
    const existingRoot = await this.db.findOne('User', {
      where: { isRoot: true }
    }) as unknown as User | null;

    if (!existingRoot) {
      const hashedPassword = await bcrypt.hash(this.options.rootPassword, this.options.saltRounds);
      const rootUser = await this.db.insert('User', {
        username: this.options.rootUsername,
        password: hashedPassword,
        role: 'admin',
        isRoot: true,
        isActive: true
      }) as unknown as User;
      this.rootUserId = rootUser.id;
      console.log(`✅ Root user created with username "${this.options.rootUsername}" and password "${this.options.rootPassword}"`);
    } else {
      this.rootUserId = existingRoot.id;
      console.log(`✅ Root user found with ID: ${this.rootUserId}`);
    }

    this.setupRoutes();
    this.initialized = true;
  }

  private setupRoutes(): void {
    this.router.use(express.json());

    // Login endpoint
    this.router.post('/login', async (req: Request<{}, LoginResponse, LoginRequest>, res: Response<LoginResponse>) => {
      try {
        const { username, password } = req.body;

        if (!username || !password) {
          return res.status(400).json({
            success: false,
            message: 'Username and password are required'
          });
        }

        const user = await this.db.findOne('User', {
          where: { username, isActive: true }
        }) as unknown as User | null;

        if (!user) {
          return res.status(401).json({
            success: false,
            message: 'Invalid credentials'
          });
        }

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

        const tokenPayload: UserPayload = { 
          id: user.id, 
          username: user.username, 
          role: user.role,
          isRoot: user.isRoot
        };

        const signOptions: SignOptions = {
          expiresIn: this.options.jwtExpiry
        };

        const token = jwt.sign(
          tokenPayload,
          this.options.jwtSecret,
          signOptions
        );

        const { password: _, ...userWithoutPassword } = user;

        res.json({
          success: true,
          message: 'Login successful',
          token,
          user: userWithoutPassword
        });

      } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
          success: false,
          message: 'Internal server error'
        });
      }
    });

    // Password change endpoint
    this.router.post('/password-change', 
      this.authenticateToken.bind(this), 
      async (req: AuthRequest<{}, ApiResponse, PasswordChangeRequest>, res: Response<ApiResponse>) => {
        try {
          const { currentPassword, newPassword, targetUsername } = req.body;
          const currentUser = req.user!;

          if (!newPassword) {
            return res.status(400).json({
              success: false,
              message: 'New password is required'
            });
          }

          let targetUser: User | null;

          // Admin can change other users' passwords
          if (targetUsername && currentUser.role === 'admin') {
            targetUser = await this.db.findOne('User', {
              where: { username: targetUsername }
            }) as unknown as User | null;
            
            if (!targetUser) {
              return res.status(404).json({
                success: false,
                message: 'Target user not found'
              });
            }
          } else {
            // User changing their own password
            targetUser = await this.db.findById('User', currentUser.id) as unknown as User | null;
            
            if (!currentPassword) {
              return res.status(400).json({
                success: false,
                message: 'Current password is required'
              });
            }

            if (!targetUser) {
              return res.status(404).json({
                success: false,
                message: 'User not found'
              });
            }

            const validPassword = await bcrypt.compare(currentPassword, targetUser.password);
            if (!validPassword) {
              return res.status(401).json({
                success: false,
                message: 'Current password is incorrect'
              });
            }
          }

          const hashedNewPassword = await bcrypt.hash(newPassword, this.options.saltRounds);

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
      }
    );

    // Create user endpoint
    this.router.post('/create-user', 
      this.authenticateToken.bind(this), 
      this.requireAdmin.bind(this), 
      async (req: AuthRequest<{}, UserResponse, CreateUserRequest>, res: Response<UserResponse>) => {
        try {
          const { username, password, role = 'user' } = req.body;

          if (!username || !password) {
            return res.status(400).json({
              success: false,
              message: 'Username and password are required'
            });
          }

          const existingUser = await this.db.findOne('User', {
            where: { username }
          }) as unknown as User | null;

          if (existingUser) {
            return res.status(409).json({
              success: false,
              message: 'Username already exists'
            });
          }

          const hashedPassword = await bcrypt.hash(password, this.options.saltRounds);

          const newUser = await this.db.insert('User', {
            username,
            password: hashedPassword,
            role: ['user', 'admin'].includes(role) ? role : 'user',
            isRoot: false,
            isActive: true
          }) as unknown as User;

          const { password: _, ...userWithoutPassword } = newUser;

          res.json({
            success: true,
            message: 'User created successfully',
            user: userWithoutPassword
          });

        } catch (error) {
          console.error('Create user error:', error);
          res.status(500).json({
            success: false,
            message: 'Internal server error'
          });
        }
      }
    );

    // Delete user endpoint
    this.router.delete('/delete-user/:username', 
      this.authenticateToken.bind(this), 
      this.requireAdmin.bind(this), 
      async (req: AuthRequest<{ username: string }>, res: Response<ApiResponse>) => {
        try {
          const { username } = req.params;
          const currentUser = req.user!;

          const userToDelete = await this.db.findOne('User', {
            where: { username }
          }) as unknown as User | null;

          if (!userToDelete) {
            return res.status(404).json({
              success: false,
              message: 'User not found'
            });
          }

          if (userToDelete.isRoot) {
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
      }
    );

    // Get all users endpoint
    this.router.get('/users', 
      this.authenticateToken.bind(this), 
      this.requireAdmin.bind(this), 
      async (req: AuthRequest, res: Response<UserResponse>) => {
        try {
          const users = await this.db.find('User', {
            where: { isActive: true },
            attributes: ['id', 'username', 'role', 'isRoot', 'createdAt', 'lastLogin']
          }) as unknown as User[];

          res.json({
            success: true,
            message: 'Users retrieved successfully',
            users: users
          });

        } catch (error) {
          console.error('Get users error:', error);
          res.status(500).json({
            success: false,
            message: 'Internal server error'
          });
        }
      }
    );

    // Get root user endpoint
    this.router.get('/root', 
      this.authenticateToken.bind(this), 
      this.requireRoot.bind(this), 
      async (req: AuthRequest, res: Response<UserResponse>) => {
        try {
          const rootUser = await this.db.findById('User', this.rootUserId!) as unknown as User | null;
          
          if (!rootUser) {
            return res.status(404).json({
              success: false,
              message: 'Root user not found'
            });
          }

          const { password: _, ...userWithoutPassword } = rootUser;

          res.json({
            success: true,
            message: 'Root user retrieved successfully',
            user: userWithoutPassword
          });

        } catch (error) {
          console.error('Get root user error:', error);
          res.status(500).json({
            success: false,
            message: 'Internal server error'
          });
        }
      }
    );

    // Get current user info endpoint
    this.router.get('/me', 
      this.authenticateToken.bind(this), 
      async (req: AuthRequest, res: Response<UserResponse>) => {
        try {
          const user = await this.db.findById('User', req.user!.id) as unknown as User | null;
          
          if (!user) {
            return res.status(404).json({
              success: false,
              message: 'User not found'
            });
          }

          const { password: _, ...userWithoutPassword } = user;
          
          res.json({
            success: true,
            message: 'User info retrieved successfully',
            user: userWithoutPassword
          });

        } catch (error) {
          console.error('Get user info error:', error);
          res.status(500).json({
            success: false,
            message: 'Internal server error'
          });
        }
      }
    );

    // Logout endpoint
    this.router.post('/logout', (req: Request, res: Response<ApiResponse>) => {
      res.json({
        success: true,
        message: 'Logged out successfully'
      });
    });
  }

  private authenticateToken(req: AuthRequest, res: Response, next: NextFunction): void {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      res.status(401).json({
        success: false,
        message: 'Access token required'
      });
      return;
    }

    jwt.verify(token, this.options.jwtSecret, (err: any, user: any) => {
      if (err) {
        res.status(403).json({
          success: false,
          message: 'Invalid or expired token'
        });
        return;
      }
      req.user = user as UserPayload;
      next();
    });
  }

  private requireAdmin(req: AuthRequest, res: Response, next: NextFunction): void {
    if (req.user?.role !== 'admin') {
      res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
      return;
    }
    next();
  }

  private requireRoot(req: AuthRequest, res: Response, next: NextFunction): void {
    if (!req.user?.isRoot) {
      res.status(403).json({
        success: false,
        message: 'Root access required'
      });
      return;
    }
    next();
  }

  middleware() {
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      if (!this.initialized) {
        await this.initialize();
      }

      if (req.path.startsWith(this.options.apiPrefix)) {
        const subPath = req.path.substring(this.options.apiPrefix.length);
        req.url = subPath || '/';
        this.router(req, res, next);
        return;
      }

      next();
    };
  }

  protect() {
    return async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      if (!this.initialized) {
        await this.initialize();
      }
      this.authenticateToken(req, res, next);
    };
  }

  adminOnly() {
    return async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      if (!this.initialized) {
        await this.initialize();
      }
      this.authenticateToken(req, res, (err?: any) => {
        if (err) {
          next(err);
          return;
        }
        this.requireAdmin(req, res, next);
      });
    };
  }

  rootOnly() {
    return async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      if (!this.initialized) {
        await this.initialize();
      }
      this.authenticateToken(req, res, (err?: any) => {
        if (err) {
          next(err);
          return;
        }
        this.requireRoot(req, res, next);
      });
    };
  }
}

// Factory function with static methods
function createAuth(options: AuthOptions = {}) {
  const authMiddleware = new AuthMiddleware(options);
  return authMiddleware.middleware();
}

createAuth.protect = (options: AuthOptions = {}) => {
  const authMiddleware = new AuthMiddleware(options);
  return authMiddleware.protect();
};

createAuth.adminOnly = (options: AuthOptions = {}) => {
  const authMiddleware = new AuthMiddleware(options);
  return authMiddleware.adminOnly();
};

createAuth.rootOnly = (options: AuthOptions = {}) => {
  const authMiddleware = new AuthMiddleware(options);
  return authMiddleware.rootOnly();
};

export default createAuth;
export { AuthMiddleware, User, UserPayload, AuthOptions, AuthRequest };