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
      // 检查用户是否存在
      const existingUser = await store.getUserByName(user.name);
      if(existingUser){
        // 用户存在，验证密码
        const isPasswordValid = await store.verifyPassword(user.password, existingUser.password);
        if(isPasswordValid){
          // 检查用户是否已在线
          const isOnline = await this.isHaveName(user.name);
          if(!isOnline){
            user.id = socket.id;
            user.time = new Date().getTime();
            this.loginSuccess(user,socket);
            const messages = await store.getMessages();
            socket.emit("history-message","group_001",messages);
          }else{
            console.log(`登录失败,用户<${user.name}>已在线!`)
            socket.emit('loginFail','该用户已在线，请稍后再试!')
          }
        }else{
          console.log(`登录失败,用户<${user.name}>密码错误!`)
          socket.emit('loginFail','用户名或密码错误!')
        }
      }else{
        // 用户不存在，注册新用户
        const hashedPassword = await store.hashPassword(user.password);
        user.password = hashedPassword;
        user.id=socket.id;
        user.time=new Date().getTime();
        this.loginSuccess(user,socket);
        await store.saveUser(user,'register')
        const messages = await store.getMessages();
        socket.emit("history-message","group_001",messages);
        console.log(`新用户<${user.name}>注册并登录成功！`)
      }
    }
  },
  async loginSuccess(user, socket) {
    const data={
      user:user,
      token:jwt.token(user)
    };
    socket.broadcast.emit('system', user, 'join');
    socket.on('message',(from, to,message,type)=> {
      if(to.type==='user'){
        socket.broadcast.to(to.roomId).emit('message', socket.user, to,message,type);
      }
      if(to.type==='group'){
        socket.broadcast.emit('message', socket.user,to,message,type);
        store.saveMessage(from,to,message,type)
      }
    });
    const users=await this.getOnlineUsers();
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
  //获取在线用户列表
  async getOnlineUsers(){
    const users=[
      {
        id:"group_001",
        name:"群聊天室",
        avatarUrl:"static/img/avatar/group-icon.png",
        type:"group"
      }
    ];
    const clients=await io.fetchSockets();
    clients.forEach((item) => {
      if(item.user){
        users.push(item.user)
      }
    })
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
  socket.on("disconnect",(reason)=>{
    //判断是否是已登录用户
    if (socket.user&&socket.user.id) {
      //删除登录用户信息,并通知所有在线用户
      socket.broadcast.emit('system', socket.user, 'logout');
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
  }
});
module.exports=io;
