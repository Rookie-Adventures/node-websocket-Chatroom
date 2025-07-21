const crypto = require('crypto');

/**
 * 设备指纹管理器
 * 用于防止用户重复注册，实现一机一号
 */
class FingerprintManager {
  constructor() {
    // 初始化设备指纹数据库
    this.initFingerprintDB();
  }

  /**
   * 初始化设备指纹数据库
   */
  initFingerprintDB() {
    const Datastore = require('nedb');
    this.fingerprintDB = new Datastore({
      filename: './db/fingerprints.db',
      autoload: true
    });
    
    // 创建索引以提高查询性能
    this.fingerprintDB.ensureIndex({ fieldName: 'fingerprintHash' });
    this.fingerprintDB.ensureIndex({ fieldName: 'username' });
    this.fingerprintDB.ensureIndex({ fieldName: 'createdAt' });
  }

  /**
   * 生成设备指纹哈希
   * @param {Object} fingerprintData - 客户端发送的指纹数据
   * @returns {string} - 设备指纹哈希值
   */
  generateFingerprintHash(fingerprintData) {
    // 提取关键指纹特征
    const keyFeatures = {
      // 浏览器指纹
      userAgent: fingerprintData.userAgent || '',
      language: fingerprintData.language || '',
      platform: fingerprintData.platform || '',
      
      // 屏幕特征
      screenResolution: fingerprintData.screenResolution || '',
      colorDepth: fingerprintData.colorDepth || '',
      pixelRatio: fingerprintData.pixelRatio || '',
      
      // Canvas指纹
      canvasFingerprint: fingerprintData.canvasFingerprint || '',
      
      // WebGL指纹
      webglVendor: fingerprintData.webglVendor || '',
      webglRenderer: fingerprintData.webglRenderer || '',
      webglFingerprint: fingerprintData.webglFingerprint || '',
      
      // 音频指纹
      audioFingerprint: fingerprintData.audioFingerprint || '',
      
      // 硬件特征
      hardwareConcurrency: fingerprintData.hardwareConcurrency || '',
      deviceMemory: fingerprintData.deviceMemory || '',
      
      // 时区和语言
      timezone: fingerprintData.timezone || '',
      timezoneOffset: fingerprintData.timezoneOffset || '',
      
      // 字体指纹
      fonts: fingerprintData.fonts || [],
      
      // 插件信息
      plugins: fingerprintData.plugins || [],
      
      // 触摸支持
      touchSupport: fingerprintData.touchSupport || false,
      
      // 其他特征
      cookieEnabled: fingerprintData.cookieEnabled || false,
      doNotTrack: fingerprintData.doNotTrack || '',
      localStorage: fingerprintData.localStorage || false,
      sessionStorage: fingerprintData.sessionStorage || false
    };

    // 将特征数据序列化并生成哈希
    const fingerprintString = JSON.stringify(keyFeatures, Object.keys(keyFeatures).sort());
    return crypto.createHash('sha256').update(fingerprintString).digest('hex');
  }

  /**
   * 检查设备指纹是否已存在
   * @param {string} fingerprintHash - 设备指纹哈希
   * @returns {Promise<Object|null>} - 如果存在返回记录，否则返回null
   */
  async checkFingerprintExists(fingerprintHash) {
    return new Promise((resolve, reject) => {
      this.fingerprintDB.findOne({ fingerprintHash }, (err, doc) => {
        if (err) {
          reject(err);
        } else {
          resolve(doc);
        }
      });
    });
  }

  /**
   * 保存设备指纹记录
   * @param {string} username - 用户名
   * @param {string} fingerprintHash - 设备指纹哈希
   * @param {Object} fingerprintData - 完整的指纹数据
   * @param {string} ip - 用户IP地址
   * @returns {Promise<Object>} - 保存的记录
   */
  async saveFingerprintRecord(username, fingerprintHash, fingerprintData, ip) {
    const record = {
      username,
      fingerprintHash,
      fingerprintData,
      ip,
      createdAt: new Date().getTime(),
      lastUsed: new Date().getTime()
    };

    return new Promise((resolve, reject) => {
      this.fingerprintDB.insert(record, (err, newDoc) => {
        if (err) {
          reject(err);
        } else {
          resolve(newDoc);
        }
      });
    });
  }

  /**
   * 更新设备指纹的最后使用时间
   * @param {string} fingerprintHash - 设备指纹哈希
   * @returns {Promise<number>} - 更新的记录数
   */
  async updateLastUsed(fingerprintHash) {
    return new Promise((resolve, reject) => {
      this.fingerprintDB.update(
        { fingerprintHash },
        { $set: { lastUsed: new Date().getTime() } },
        {},
        (err, numReplaced) => {
          if (err) {
            reject(err);
          } else {
            resolve(numReplaced);
          }
        }
      );
    });
  }

  /**
   * 验证用户注册时的设备指纹
   * @param {string} username - 用户名
   * @param {Object} fingerprintData - 设备指纹数据
   * @param {string} ip - 用户IP地址
   * @param {boolean} isAdmin - 是否为管理员
   * @returns {Promise<Object>} - 验证结果
   */
  async validateRegistration(username, fingerprintData, ip, isAdmin = false) {
    try {
      // 管理员不受设备限制
      if (isAdmin) {
        return {
          allowed: true,
          reason: 'admin_bypass',
          message: '管理员账户不受设备限制'
        };
      }

      // 生成设备指纹哈希
      const fingerprintHash = this.generateFingerprintHash(fingerprintData);
      
      // 检查该设备是否已经注册过用户
      const existingRecord = await this.checkFingerprintExists(fingerprintHash);
      
      if (existingRecord) {
        // 设备已被使用，拒绝注册
        return {
          allowed: false,
          reason: 'device_already_used',
          message: '该设备已经注册过账户，一台设备只能注册一个账户',
          existingUsername: existingRecord.username,
          registrationDate: new Date(existingRecord.createdAt).toLocaleString()
        };
      }

      // 设备未被使用，允许注册并保存指纹记录
      await this.saveFingerprintRecord(username, fingerprintHash, fingerprintData, ip);
      
      return {
        allowed: true,
        reason: 'new_device',
        message: '设备验证通过，允许注册',
        fingerprintHash
      };
    } catch (error) {
      console.error('设备指纹验证失败:', error);
      return {
        allowed: false,
        reason: 'validation_error',
        message: '设备验证失败，请稍后重试'
      };
    }
  }

  /**
   * 验证用户登录时的设备指纹
   * @param {string} username - 用户名
   * @param {Object} fingerprintData - 设备指纹数据
   * @param {boolean} isAdmin - 是否为管理员
   * @returns {Promise<Object>} - 验证结果
   */
  async validateLogin(username, fingerprintData, isAdmin = false) {
    try {
      // 管理员不受设备限制
      if (isAdmin) {
        return {
          allowed: true,
          reason: 'admin_bypass',
          message: '管理员账户不受设备限制'
        };
      }

      // 生成设备指纹哈希
      const fingerprintHash = this.generateFingerprintHash(fingerprintData);
      
      // 检查该设备是否属于该用户
      const userRecord = await this.getUserFingerprintRecord(username);
      
      if (!userRecord) {
        // 用户没有设备记录，需要进一步验证
        // 检查是否有其他用户使用了相同的设备指纹
        const existingRecord = await this.checkFingerprintExists(fingerprintHash);
        
        if (existingRecord && existingRecord.username !== username) {
          // 该设备已被其他用户使用，拒绝登录
          return {
            allowed: false,
            reason: 'device_used_by_other',
            message: '该设备已被其他用户使用，无法登录'
          };
        }
        
        // 设备未被使用，可能是老用户，允许登录但记录指纹
        await this.saveFingerprintRecord(username, fingerprintHash, fingerprintData, '');
        return {
          allowed: true,
          reason: 'legacy_user',
          message: '用户设备信息已记录'
        };
      }

      if (userRecord.fingerprintHash === fingerprintHash) {
        // 设备匹配，更新最后使用时间
        await this.updateLastUsed(fingerprintHash);
        return {
          allowed: true,
          reason: 'device_match',
          message: '设备验证通过'
        };
      } else {
        // 设备不匹配，拒绝登录
        return {
          allowed: false,
          reason: 'device_mismatch',
          message: '检测到异常登录设备，为了账户安全，请使用注册时的设备登录'
        };
      }
    } catch (error) {
      console.error('登录设备验证失败:', error);
      return {
        allowed: true, // 验证失败时允许登录，避免影响正常用户
        reason: 'validation_error',
        message: '设备验证失败，已允许登录'
      };
    }
  }

  /**
   * 获取用户的设备指纹记录
   * @param {string} username - 用户名
   * @returns {Promise<Object|null>} - 用户的设备记录
   */
  async getUserFingerprintRecord(username) {
    return new Promise((resolve, reject) => {
      this.fingerprintDB.findOne({ username }, (err, doc) => {
        if (err) {
          reject(err);
        } else {
          resolve(doc);
        }
      });
    });
  }

  /**
   * 获取所有设备指纹记录（管理员功能）
   * @returns {Promise<Array>} - 所有设备记录
   */
  async getAllFingerprintRecords() {
    return new Promise((resolve, reject) => {
      this.fingerprintDB.find({}).sort({ createdAt: -1 }).exec((err, docs) => {
        if (err) {
          reject(err);
        } else {
          resolve(docs);
        }
      });
    });
  }

  /**
   * 删除用户的设备指纹记录（管理员功能）
   * @param {string} username - 用户名
   * @returns {Promise<number>} - 删除的记录数
   */
  async deleteFingerprintRecord(username) {
    return new Promise((resolve, reject) => {
      this.fingerprintDB.remove({ username }, {}, (err, numRemoved) => {
        if (err) {
          reject(err);
        } else {
          resolve(numRemoved);
        }
      });
    });
  }
}

module.exports = FingerprintManager;