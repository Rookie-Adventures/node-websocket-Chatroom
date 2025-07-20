const db=require("./db");
const util=require("./utils")
const fs=require('fs')
const bcrypt = require('bcrypt')
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
    const doc={
      from,
      to,
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
      db.message.find({}).sort({time:1}).skip(0).limit(100).exec((err,docs) => {
        if(err){
          reject(err)
        }else {
          resolve(docs)
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
  }
};
