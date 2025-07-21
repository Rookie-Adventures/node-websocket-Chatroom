const JWT=require("jsonwebtoken");
const dotenv = require('dotenv');
dotenv.config();

const auth={
  secret: process.env.JWT_SECRET || "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
  token(data){
    return JWT.sign({data},this.secret,{
      expiresIn:"1d"
    })
  },
  decode(token){
    try {
      return JWT.verify(token,this.secret);
    }catch (e) {
      return null
    }
  },
  // 创建包含角色信息的token
  createTokenWithRole(user){
    const tokenData = {
      id: user.id,
      name: user.name,
      role: user.role,
      avatarUrl: user.avatarUrl,
      deviceType: user.deviceType,
      ip: user.ip
    };
    return JWT.sign({data: tokenData}, this.secret, {
      expiresIn: "1d"
    });
  }
};
module.exports=auth;
