const db=require("./db");
const util=require("./utils")
const fs=require('fs')
const bcrypt = require('bcrypt')
const { AuthManager, USER_ROLES } = require('./auth');

const authManager = new AuthManager();
module.exports ={
  saveUser(user,status){
    console.log(user.name,status);
    if(status==='login' || status==='register'){
      return new Promise((resolve, reject) => {
        db.user.insert(user,(err,newUser) => {
          if(err){
            console.error('保存用户失败:', err);
            reject(err)
          }else {
            console.log('用户保存成功:', newUser);
            resolve(newUser)
          }
        })
      })
    }else{
      return Promise.resolve(null);
    }
  },
  saveMessage(from,to,message,type){
    if(type==='image'){
      const base64Data = message.replace(/^data:image\/\w+;base64,/, "")
      const dataBuffer = new Buffer.from(base64Data,'base64')
      const filename = util.MD5(base64Data)
      fs.writeFileSync(`./upload/${filename}.png`,dataBuffer)
      message=`/assets/images/${filename}.png`
    }
    console.log("\x1b[36m"+from.name+"\x1b[0m对<\x1b[36m"+to.name+"\x1b[0m>:\x1b[32m"+message+"\x1b[0m")
    // 只存储用户ID和基本信息，不存储完整用户对象
    const doc={
      fromId: from.id || from.name, // 使用ID作为主键，如果没有ID则使用name
      toId: to.id || to.name,
      fromName: from.name, // 保留用户名用于快速显示
      toName: to.name,
      content:message,
      type,
      time:new Date().getTime()
    }
    return new Promise((resolve, reject) => {
      db.message.insert(doc,(err,newDoc) => {
        if(err){
          reject(err)
        }else {
          resolve(newDoc)
        }
      })
    })
  },
  getMessages() {
    return new Promise((resolve, reject) => {
      db.message.find({}).sort({time:1}).skip(0).limit(100).exec(async (err,docs) => {
        if(err){
          reject(err)
        }else {
          // 为了兼容性，重构消息格式以匹配前端期望的结构
          const messagesWithUserInfo = await Promise.all(docs.map(async (doc) => {
            // 如果是新格式（有fromId字段），则构建兼容的用户对象
            if(doc.fromId) {
              const fromUser = await this.getUserByName(doc.fromName) || { name: doc.fromName, id: doc.fromId };
              const toUser = await this.getUserByName(doc.toName) || { name: doc.toName, id: doc.toId };
              
              return {
                ...doc,
                from: {
                  name: fromUser.name,
                  id: fromUser.id || doc.fromId,
                  avatarUrl: fromUser.avatarUrl || 'static/img/avatar/default.jpg'
                },
                to: {
                  name: toUser.name,
                  id: toUser.id || doc.toId,
                  avatarUrl: toUser.avatarUrl || 'static/img/avatar/default.jpg'
                }
              };
            }
            // 如果是旧格式，直接返回
            return doc;
          }));
          resolve(messagesWithUserInfo)
        }
      })
    })
  },
  getUsers(){
    return new Promise((resolve, reject) => {
      db.user.find({}).sort({time:1}).skip(0).limit(100).exec((err,docs) => {
        if(err){
          reject(err)
        }else {
          resolve(docs)
        }
      })
    })
  },
  // 根据用户名查找用户
  getUserByName(name){
    return new Promise((resolve, reject) => {
      db.user.findOne({name: name}, (err, doc) => {
        if(err){
          reject(err)
        }else {
          resolve(doc)
        }
      })
    })
  },
  // 密码加密
  async hashPassword(password){
    const saltRounds = 10;
    return await bcrypt.hash(password, saltRounds);
  },
  // 密码验证
  async verifyPassword(inputPassword, hashedPassword){
    return await bcrypt.compare(inputPassword, hashedPassword);
  },
  
  // 验证用户登录并返回角色信息
  async verifyUserLogin(username, password) {
    // 首先检查是否为管理员账户
    if (authManager.isAdminAccount(username, password)) {
      return {
        isValid: true,
        role: USER_ROLES.ADMIN,
        isAdmin: true,
        user: null // 管理员不需要从数据库获取
      };
    }
    
    // 检查普通用户
    const user = await this.getUserByName(username);
    if (user) {
      const isPasswordValid = await this.verifyPassword(password, user.password);
      if (isPasswordValid) {
        return {
          isValid: true,
          role: USER_ROLES.USER,
          isAdmin: false,
          user: user
        };
      }
    }
    
    return {
      isValid: false,
      role: null,
      isAdmin: false,
      user: null
    };
  },
  
  // 保存用户时包含角色信息
  async saveUserWithRole(user, status, role = USER_ROLES.USER) {
    user.role = role;
    return this.saveUser(user, status);
  },
  
  // 获取用户角色
  getUserRole(username, password) {
    return authManager.getUserRole(username, password);
  },
  
  // 检查用户权限
  hasPermission(userRole, permission) {
    return authManager.hasPermission(userRole, permission);
  },
  
  // 检查是否为管理员
  isAdmin(userRole) {
    return authManager.isAdmin(userRole);
  }
};
