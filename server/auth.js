const dotenv = require('dotenv');
dotenv.config();

// 用户角色枚举
const USER_ROLES = {
  ADMIN: 'admin',
  USER: 'user'
};

// 权限枚举
const PERMISSIONS = {
  // 用户管理权限
  KICK_USER: 'kick_user',
  BAN_USER: 'ban_user',
  VIEW_USER_LIST: 'view_user_list',
  
  // 消息管理权限
  DELETE_MESSAGE: 'delete_message',
  MODERATE_CHAT: 'moderate_chat',
  
  // 系统管理权限
  SYSTEM_ANNOUNCE: 'system_announce',
  VIEW_LOGS: 'view_logs'
};

// 角色权限映射
const ROLE_PERMISSIONS = {
  [USER_ROLES.ADMIN]: [
    PERMISSIONS.KICK_USER,
    PERMISSIONS.BAN_USER,
    PERMISSIONS.VIEW_USER_LIST,
    PERMISSIONS.DELETE_MESSAGE,
    PERMISSIONS.MODERATE_CHAT,
    PERMISSIONS.SYSTEM_ANNOUNCE,
    PERMISSIONS.VIEW_LOGS
  ],
  [USER_ROLES.USER]: [
    // 普通用户暂时没有特殊权限
  ]
};

class AuthManager {
  constructor() {
    this.adminAccounts = this.parseAdminAccounts();
  }

  // 解析管理员账户配置
  parseAdminAccounts() {
    const adminAccountsStr = process.env.ADMIN_ACCOUNTS || '';
    const accounts = new Map();
    
    if (adminAccountsStr) {
      const accountPairs = adminAccountsStr.split(',');
      accountPairs.forEach(pair => {
        const [username, password] = pair.split(':');
        if (username && password) {
          accounts.set(username.trim(), password.trim());
        }
      });
    }
    
    return accounts;
  }

  // 检查是否为管理员账户
  isAdminAccount(username, password) {
    const adminPassword = this.adminAccounts.get(username);
    return adminPassword && adminPassword === password;
  }

  // 获取用户角色
  getUserRole(username, password) {
    if (this.isAdminAccount(username, password)) {
      return USER_ROLES.ADMIN;
    }
    return USER_ROLES.USER;
  }

  // 检查用户是否有特定权限
  hasPermission(userRole, permission) {
    const rolePermissions = ROLE_PERMISSIONS[userRole] || [];
    return rolePermissions.includes(permission);
  }

  // 检查用户是否为管理员
  isAdmin(userRole) {
    return userRole === USER_ROLES.ADMIN;
  }

  // 获取角色的所有权限
  getRolePermissions(role) {
    return ROLE_PERMISSIONS[role] || [];
  }

  // 验证权限中间件
  requirePermission(permission) {
    return (socket, next) => {
      const user = socket.user;
      if (!user || !this.hasPermission(user.role, permission)) {
        return next(new Error('权限不足'));
      }
      next();
    };
  }

  // 验证管理员权限中间件
  requireAdmin() {
    return (socket, next) => {
      const user = socket.user;
      if (!user || !this.isAdmin(user.role)) {
        return next(new Error('需要管理员权限'));
      }
      next();
    };
  }
}

module.exports = {
  AuthManager,
  USER_ROLES,
  PERMISSIONS,
  ROLE_PERMISSIONS
};