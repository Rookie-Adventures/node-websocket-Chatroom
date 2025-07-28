const io = require('socket.io')({
  cors: {
    origin: '*',
    allowedHeaders: ["my-custom-header"],
    credentials: true,
  },
  serveClient:false
});
const jwt=require("./jwt");
const store=require("./store");
const { AuthManager, USER_ROLES, PERMISSIONS } = require('./auth');
const FingerprintManager = require('./fingerprint');

const authManager = new AuthManager();
const fingerprintManager = new FingerprintManager();
const util={
  async login(user,socket,isReconnect) {
    let ip=socket.handshake.address.replace(/::ffff:/,"");
    const headers = socket.handshake.headers;
    const realIP = headers['x-forwarded-for'];
    ip=realIP?realIP:ip;
    const deviceType=this.getDeviceType(socket.handshake.headers["user-agent"].toLowerCase());
    user.ip=ip;
    user.deviceType=deviceType;
    user.roomId=socket.id;
    user.type='user';
    if(isReconnect){
      this.loginSuccess(user,socket);
      console.log(`用户<${user.name}>重新链接成功！`)
    }else {
      // 检查用户名和密码是否为空
      if(!user.name || !user.password) {
        console.log(`登录失败,用户名或密码为空!`)
        socket.emit('loginFail','用户名和密码不能为空!')
        return;
      }
      
      // 使用新的权限系统验证用户登录
      const loginResult = await store.verifyUserLogin(user.name, user.password);
      
      if(loginResult.isValid) {
        // 已存在用户（管理员或普通用户）登录成功
        const isOnline = await this.isHaveName(user.name);
        if(!isOnline){
          // 设置用户角色和基本信息
          user.role = loginResult.role;
          user.isAdmin = loginResult.isAdmin;
          user.id = socket.id;
          user.time = new Date().getTime();
          
          // 设备指纹验证（登录）
          if(user.fingerprintData) {
            const fingerprintResult = await fingerprintManager.validateLogin(
              user.name, 
              user.fingerprintData, 
              loginResult.isAdmin
            );
            
            if(!fingerprintResult.allowed) {
              console.log(`登录失败,设备指纹验证失败: ${user.name} - ${fingerprintResult.message}`);
              socket.emit('loginFail', fingerprintResult.message);
              return;
            }
            
            console.log(`设备指纹验证通过: ${user.name} - ${fingerprintResult.message}`);
          }
          
          if(loginResult.isAdmin) {
            console.log(`管理员<${user.name}>登录成功！`);
          } else {
            console.log(`用户<${user.name}>登录成功！`);
          }
          
          this.loginSuccess(user,socket);
        }else{
          console.log(`登录失败,用户<${user.name}>已在线!`)
          socket.emit('loginFail','该用户已在线，请稍后再试!')
        }
      } else {
        // 登录失败，需要区分是用户不存在还是密码错误
        const existingUser = await store.getUserByName(user.name);
        
        if (existingUser) {
          // 用户存在但密码错误
          console.log(`登录失败,用户<${user.name}>密码错误!`)
          socket.emit('loginFail','用户名或密码错误!');
          return;
        }
        
        // 用户不存在，尝试注册新用户（仅限普通用户）
        const isOnline = await this.isHaveName(user.name);
        if(!isOnline){
          // 设备指纹验证（注册）
          if(user.fingerprintData) {
            const fingerprintResult = await fingerprintManager.validateRegistration(
              user.name, 
              user.fingerprintData, 
              ip, 
              false // 新注册用户不是管理员
            );
            
            if(!fingerprintResult.allowed) {
              console.log(`注册失败,设备指纹验证失败: ${user.name} - ${fingerprintResult.message}`);
              socket.emit('loginFail', fingerprintResult.message);
              return;
            }
            
            console.log(`设备指纹验证通过: ${user.name} - ${fingerprintResult.message}`);
          } else {
            console.log(`注册失败,缺少设备指纹数据: ${user.name}`);
            socket.emit('loginFail', '设备验证失败，请刷新页面重试');
            return;
          }
          
          // 新用户注册
          user.role = USER_ROLES.USER;
          user.isAdmin = false;
          user.id = socket.id;
          user.time = new Date().getTime();
          
          const hashedPassword = await store.hashPassword(user.password);
          const userToSave = {...user, password: hashedPassword};
          await store.saveUserWithRole(userToSave, 'register', USER_ROLES.USER);
          console.log(`新用户<${user.name}>注册并登录成功！`);
          
          this.loginSuccess(user,socket);
        }else{
          console.log(`登录失败,用户<${user.name}>已在线!`)
          socket.emit('loginFail','该用户已在线，请稍后再试!')
        }
      }
    }
  },
  async loginSuccess(user, socket) {
    const data={
      user:user,
      token:jwt.createTokenWithRole(user)
    };
    
    // 根据用户角色决定广播范围
    const clients = await io.fetchSockets();
    if(user.isAdmin) {
      // 管理员登录时，向所有用户广播（管理员和普通用户都能看到管理员）
      clients.forEach((client) => {
        if(client.user) {
          client.emit('system', user, 'join');
        }
      });
    } else {
      // 普通用户登录时，只向管理员广播
      clients.forEach((client) => {
        if(client.user && client.user.isAdmin) {
          client.emit('system', user, 'join');
        }
      });
    }
    socket.on('message',(from, to,message,type)=> {
      // 只允许私聊，且普通用户只能与管理员私聊
      if(to.type==='user'){
        // 检查权限：普通用户只能与管理员私聊
        if(!socket.user.isAdmin && !to.isAdmin) {
          socket.emit('message-error', '您只能与管理员私聊');
          return;
        }
        
        socket.broadcast.to(to.roomId).emit('message', socket.user, to,message,type);
        // 保存私聊消息
        store.saveMessage(from,to,message,type);
      }
      // 移除群聊功能
    });
    
    // 管理员专用功能
    if(user.isAdmin) {
      // 踢出用户
      socket.on('admin:kick-user', async (targetUserId, reason) => {
        if(!authManager.hasPermission(user.role, PERMISSIONS.KICK_USER)) {
          socket.emit('admin:error', '权限不足');
          return;
        }
        
        const clients = await io.fetchSockets();
        const targetSocket = clients.find(client => client.user && client.user.id === targetUserId);
        
        if(targetSocket) {
          targetSocket.emit('admin:kicked', reason || '您已被管理员踢出');
          targetSocket.disconnect(true);
          socket.broadcast.emit('system-message', {
            type: 'kick',
            message: `用户 ${targetSocket.user.name} 被管理员踢出`,
            admin: user.name,
            reason: reason
          });
          console.log(`管理员 ${user.name} 踢出了用户 ${targetSocket.user.name}`);
        } else {
          socket.emit('admin:error', '用户不在线');
        }
      });
      
      // 系统公告
      socket.on('admin:system-announce', (message) => {
        if(!authManager.hasPermission(user.role, PERMISSIONS.SYSTEM_ANNOUNCE)) {
          socket.emit('admin:error', '权限不足');
          return;
        }
        
        io.emit('system-message', {
          type: 'announce',
          message: message,
          admin: user.name,
          time: new Date().getTime()
        });
        console.log(`管理员 ${user.name} 发布系统公告: ${message}`);
      });
      
      // 获取在线用户列表（管理员视图）
      socket.on('admin:get-users', async () => {
        if(!authManager.hasPermission(user.role, PERMISSIONS.VIEW_USER_LIST)) {
          socket.emit('admin:error', '权限不足');
          return;
        }
        
        const users = await this.getOnlineUsers(); // 管理员可以看到所有用户
        const adminUsers = users.map(u => ({
          ...u,
          role: u.role || USER_ROLES.USER,
          isAdmin: u.isAdmin || false,
          ip: u.ip,
          deviceType: u.deviceType,
          loginTime: u.time
        }));
        
        socket.emit('admin:users-list', adminUsers);
      });
    }
    const users=await this.getOnlineUsers(user);
    socket.user=user;
    socket.emit('loginSuccess', data, users);
  },
  //根据useragent判读设备类型
  getDeviceType(userAgent){
    let bIsIpad = userAgent.match(/ipad/i) == "ipad";
    let bIsIphoneOs = userAgent.match(/iphone os/i) == "iphone os";
    let bIsMidp = userAgent.match(/midp/i) == "midp";
    let bIsUc7 = userAgent.match(/rv:1.2.3.4/i) == "rv:1.2.3.4";
    let bIsUc = userAgent.match(/ucweb/i) == "ucweb";
    let bIsAndroid = userAgent.match(/android/i) == "android";
    let bIsCE = userAgent.match(/windows ce/i) == "windows ce";
    let bIsWM = userAgent.match(/windows mobile/i) == "windows mobile";
    if (bIsIpad || bIsIphoneOs || bIsMidp || bIsUc7 || bIsUc || bIsAndroid || bIsCE || bIsWM) {
      return "phone";
    } else {
      return "pc";
    }
  },
  //获取在线用户列表（根据用户角色过滤）
  async getOnlineUsers(currentUser = null){
    const users = [];
    const clients = await io.fetchSockets();
    
    clients.forEach((item) => {
      if(item.user){
        // 如果当前用户是管理员，可以看到所有用户
        if(currentUser && currentUser.isAdmin) {
          users.push(item.user);
        }
        // 如果当前用户是普通用户，只能看到管理员
        else if(currentUser && !currentUser.isAdmin) {
          if(item.user.isAdmin) {
            users.push(item.user);
          }
        }
        // 如果没有指定当前用户，返回所有用户（用于系统内部调用）
        else if(!currentUser) {
          users.push(item.user);
        }
      }
    });
    
    return users;
  },
  //判断用户是否已经存在
  async isHaveName(name){
    const users=await this.getOnlineUsers();
    return users.some(item => item.name===name)
  },
};
io.sockets.on('connection',(socket)=>{
  const token=socket.handshake.headers.token;
  let decode=null;
  if(token){
    decode=jwt.decode(token);
  }
  let user=decode?decode.data:{};
  socket.on("disconnect",async (reason)=>{
    //判断是否是已登录用户
    if (socket.user&&socket.user.id) {
      //根据用户角色决定退出广播范围
      const clients = await io.fetchSockets();
      if(socket.user.isAdmin) {
        // 管理员退出时，向所有用户广播
        clients.forEach((client) => {
          if(client.user) {
            client.emit('system', socket.user, 'logout');
          }
        });
      } else {
        // 普通用户退出时，只向管理员广播
        clients.forEach((client) => {
          if(client.user && client.user.isAdmin) {
            client.emit('system', socket.user, 'logout');
          }
        });
      }
      store.saveUser(socket.user,'logout')
    }
    console.log(reason)
  });
  //判断链接用户是否已经登录
  if(user&&user.id){
    //已登录的用户重新登录
    util.login(user,socket,true);
  }else {
    //监听用户登录事件
    socket.on('login',(user)=>{
      util.login(user,socket,false)
    });
    
    //监听token登录事件
    socket.on('tokenLogin', (token) => {
      const decode = jwt.decode(token);
      if(decode && decode.data) {
        // token有效，使用解码的用户信息重新登录
        util.login(decode.data, socket, true);
      } else {
        // token无效或过期
        socket.emit('tokenLoginFail', 'Token已过期或无效');
      }
    });
  }
});
module.exports=io;
