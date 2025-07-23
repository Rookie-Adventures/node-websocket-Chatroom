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
   * 检测设备特征相似度（多维度比对）
   * @param {Object} fingerprintData1 - 第一个设备指纹数据
   * @param {Object} fingerprintData2 - 第二个设备指纹数据
   * @returns {Object} - 相似度分析结果
   */
  analyzeFingerprintSimilarity(fingerprintData1, fingerprintData2) {
    const similarities = [];
    let matchCount = 0;
    
    // 定义关键特征及其权重
    const keyFeatures = [
      { path: 'userAgent', weight: 2, name: '浏览器标识' },
      { path: 'screenResolution', weight: 3, name: '屏幕分辨率' },
      { path: 'timezone', weight: 2, name: '时区' },
      { path: 'hardwareConcurrency', weight: 3, name: 'CPU核心数' },
      { path: 'deviceMemory', weight: 3, name: '设备内存' },
      { path: 'canvasFingerprint', weight: 4, name: 'Canvas指纹' },
      { path: 'webglVendor', weight: 3, name: 'WebGL厂商' },
      { path: 'webglRenderer', weight: 3, name: 'WebGL渲染器' },
      { path: 'audioFingerprint', weight: 4, name: '音频指纹' },
      { path: 'fonts', weight: 2, name: '字体列表' },
      { path: 'fingerprintjs.visitorId', weight: 5, name: 'FingerprintJS ID' }
    ];
    
    // 获取嵌套属性值
    const getNestedValue = (obj, path) => {
      return path.split('.').reduce((current, key) => current && current[key], obj);
    };
    
    // 比较每个特征
    keyFeatures.forEach(feature => {
      const value1 = getNestedValue(fingerprintData1, feature.path);
      const value2 = getNestedValue(fingerprintData2, feature.path);
      
      if (value1 && value2) {
        let isMatch = false;
        
        if (feature.path === 'fonts') {
          // 字体列表比较（数组）
          const fonts1 = Array.isArray(value1) ? value1 : [];
          const fonts2 = Array.isArray(value2) ? value2 : [];
          const commonFonts = fonts1.filter(font => fonts2.includes(font));
          isMatch = commonFonts.length >= Math.min(fonts1.length, fonts2.length) * 0.8;
        } else if (typeof value1 === 'string' && typeof value2 === 'string') {
          // 字符串精确匹配
          isMatch = value1 === value2;
        } else {
          // 其他类型精确匹配
          isMatch = JSON.stringify(value1) === JSON.stringify(value2);
        }
        
        if (isMatch) {
          matchCount += feature.weight;
          similarities.push({
            feature: feature.name,
            weight: feature.weight,
            matched: true
          });
        } else {
          similarities.push({
            feature: feature.name,
            weight: feature.weight,
            matched: false
          });
        }
      }
    });
    
    const totalWeight = keyFeatures.reduce((sum, f) => sum + f.weight, 0);
    const similarityScore = matchCount / totalWeight;
    
    return {
       similarityScore,
       matchCount,
       totalWeight,
       similarities,
       isSuspicious: similarityScore >= 0.4, // 40%以上相似度认为可疑
       isHighlySuspicious: similarityScore >= 0.5 // 50%以上相似度认为高度可疑
     };
  }

  /**
   * 检查是否存在相似设备（多维度检测）
   * @param {Object} fingerprintData - 当前设备指纹数据
   * @param {string} excludeUsername - 排除的用户名（用于登录验证）
   * @returns {Promise<Object|null>} - 相似设备记录和分析结果
   */
  async checkSimilarDevices(fingerprintData, excludeUsername = null) {
    return new Promise((resolve, reject) => {
      const query = excludeUsername ? { username: { $ne: excludeUsername } } : {};
      
      this.fingerprintDB.find(query, (err, docs) => {
        if (err) {
          reject(err);
          return;
        }
        
        let mostSimilar = null;
        let highestScore = 0;
        
        docs.forEach(record => {
          const analysis = this.analyzeFingerprintSimilarity(fingerprintData, record.fingerprintData);
          
          if (analysis.isSuspicious && analysis.similarityScore > highestScore) {
            highestScore = analysis.similarityScore;
            mostSimilar = {
              record,
              analysis
            };
          }
        });
        
        resolve(mostSimilar);
      });
    });
  }

  /**
   * 检查IP是否已被使用
   * @param {string} ip - IP地址
   * @returns {Promise<Object|null>} - 已使用该IP的用户记录
   */
  async checkIPExists(ip) {
    return new Promise((resolve, reject) => {
      this.fingerprintDB.findOne({ ip }, (err, doc) => {
        if (err) {
          reject(err);
        } else {
          resolve(doc);
        }
      });
    });
  }

  /**
   * 验证用户注册时的设备指纹（增强版多维度检测 + IP限制）
   * @param {string} username - 用户名
   * @param {Object} fingerprintData - 设备指纹数据
   * @param {string} ip - 用户IP地址
   * @param {boolean} isAdmin - 是否为管理员
   * @returns {Promise<Object>} - 验证结果
   */
  async validateRegistration(username, fingerprintData, ip, isAdmin = false) {
    try {
      // 检查是否为隐私模式
      if (fingerprintData && fingerprintData.isPrivateMode) {
        return {
          allowed: false,
          reason: 'private_mode_detected',
          message: '检测到隐私浏览模式，为了账户安全，请使用正常浏览模式进行注册'
        };
      }
      
      // 管理员不受设备限制
      if (isAdmin) {
        return {
          allowed: true,
          reason: 'admin_bypass',
          message: '管理员账户不受设备限制'
        };
      }

      // 检查IP是否已被使用（同IP限制）
      if (ip) {
        const existingIPRecord = await this.checkIPExists(ip);
        if (existingIPRecord && existingIPRecord.username !== username) {
          return {
            allowed: false,
            reason: 'ip_already_used',
            message: `该IP地址已被用户"${existingIPRecord.username}"注册过账户，一个IP只能注册一个账户`,
            existingUsername: existingIPRecord.username,
            registrationDate: new Date(existingIPRecord.createdAt).toLocaleString(),
            matchType: 'ip',
            userIP: ip
          };
        }
      }

      // 生成设备指纹哈希
      const fingerprintHash = this.generateFingerprintHash(fingerprintData);
      
      // 首先检查完全相同的设备指纹
      const exactMatch = await this.checkFingerprintExists(fingerprintHash);
      
      if (exactMatch) {
        return {
          allowed: false,
          reason: 'device_already_used',
          message: '该设备已经注册过账户，一台设备只能注册一个账户',
          existingUsername: exactMatch.username,
          registrationDate: new Date(exactMatch.createdAt).toLocaleString(),
          matchType: 'exact'
        };
      }
      
      // 进行多维度相似性检测
      const similarDevice = await this.checkSimilarDevices(fingerprintData);
      
      if (similarDevice && similarDevice.analysis.isHighlySuspicious) {
        // 高度可疑的相似设备，拒绝注册
        const matchedFeatures = similarDevice.analysis.similarities
          .filter(s => s.matched)
          .map(s => s.feature)
          .join('、');
          
        return {
          allowed: false,
          reason: 'similar_device_detected',
          message: `检测到疑似重复注册：与用户"${similarDevice.record.username}"的设备在${matchedFeatures}等特征高度相似（相似度：${Math.round(similarDevice.analysis.similarityScore * 100)}%）`,
          existingUsername: similarDevice.record.username,
          registrationDate: new Date(similarDevice.record.createdAt).toLocaleString(),
          matchType: 'similar',
          similarityScore: similarDevice.analysis.similarityScore,
          matchedFeatures: matchedFeatures
        };
      } else if (similarDevice && similarDevice.analysis.isSuspicious) {
        // 中等可疑，记录警告但允许注册
        console.warn(`注册警告：用户"${username}"的设备与用户"${similarDevice.record.username}"相似度为${Math.round(similarDevice.analysis.similarityScore * 100)}%`);
      }

      // 设备检测通过，允许注册并保存指纹记录
      await this.saveFingerprintRecord(username, fingerprintHash, fingerprintData, ip);
      
      return {
        allowed: true,
        reason: 'new_device',
        message: '设备验证通过，允许注册',
        fingerprintHash,
        similarityWarning: similarDevice ? {
          similarUser: similarDevice.record.username,
          similarityScore: similarDevice.analysis.similarityScore
        } : null
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
   * 验证用户登录时的设备指纹（增强版多维度检测）
   * @param {string} username - 用户名
   * @param {Object} fingerprintData - 设备指纹数据
   * @param {string} ip - 用户IP地址
   * @param {boolean} isAdmin - 是否为管理员
   * @returns {Promise<Object>} - 验证结果
   */
  async validateLogin(username, fingerprintData, ip, isAdmin = false) {
    try {
      // 检查是否为隐私模式
      if (fingerprintData && fingerprintData.isPrivateMode) {
        return {
          allowed: false,
          reason: 'private_mode_detected',
          message: '检测到隐私浏览模式，为了账户安全，请使用正常浏览模式进行登录'
        };
      }
      
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
        await this.saveFingerprintRecord(username, fingerprintHash, fingerprintData, ip || '');
        return {
          allowed: true,
          reason: 'legacy_user',
          message: '用户设备信息已记录'
        };
      }

      if (userRecord.fingerprintHash === fingerprintHash) {
        // 设备完全匹配，更新最后使用时间
        await this.updateLastUsed(username, ip);
        return {
          allowed: true,
          reason: 'device_match',
          message: '设备验证通过',
          fingerprintHash,
          matchType: 'exact'
        };
      } else {
        // 设备指纹不完全匹配，进行相似度分析
        const similarity = this.analyzeFingerprintSimilarity(fingerprintData, userRecord.fingerprintData);
        
        if (similarity.similarityScore >= 0.7) {
           // 70%以上相似，可能是同一设备的指纹变化（浏览器更新、插件变化等）
           console.log(`登录警告：用户"${username}"使用了相似设备登录，相似度：${Math.round(similarity.similarityScore * 100)}%`);
           
           // 更新设备指纹记录为新的指纹
           await this.updateFingerprintRecord(username, fingerprintHash, fingerprintData, ip);
           
           const matchedFeatures = similarity.similarities
             .filter(s => s.matched)
             .map(s => s.feature)
             .join('、');
           
           return {
              allowed: true,
              reason: 'similar_device_accepted',
              message: `设备特征相似，允许登录并更新设备记录（相似度：${Math.round(similarity.similarityScore * 100)}%）`,
              fingerprintHash,
              matchType: 'similar',
              similarityScore: similarity.similarityScore,
              matchedFeatures: matchedFeatures,
              deviceUpdated: true
            };
        } else if (similarity.isSuspicious) {
          // 中等相似，需要额外验证或记录
          const matchedFeatures = similarity.similarities
            .filter(s => s.matched)
            .map(s => s.feature)
            .join('、');
            
          return {
            allowed: false,
            reason: 'device_partially_similar',
            message: `设备验证失败：当前设备与注册设备部分相似但差异较大（相似度：${Math.round(similarity.similarityScore * 100)}%），请使用注册时的设备登录`,
            registeredDevice: {
              registrationDate: new Date(userRecord.createdAt).toLocaleString(),
              lastUsed: userRecord.lastUsed ? new Date(userRecord.lastUsed).toLocaleString() : '从未使用'
            },
            similarityScore: similarity.similarityScore,
            matchedFeatures: matchedFeatures
          };
        } else {
          // 设备差异太大，拒绝登录
          return {
            allowed: false,
            reason: 'device_mismatch',
            message: '检测到异常登录设备，为了账户安全，请使用注册时的设备登录',
            registeredDevice: {
              registrationDate: new Date(userRecord.createdAt).toLocaleString(),
              lastUsed: userRecord.lastUsed ? new Date(userRecord.lastUsed).toLocaleString() : '从未使用'
            },
            similarityScore: similarity.similarityScore
          };
        }
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
   * 更新用户设备指纹记录（用于设备变化时）
   * @param {string} username - 用户名
   * @param {string} fingerprintHash - 新的指纹哈希
   * @param {Object} fingerprintData - 新的指纹数据
   * @param {string} ip - IP地址
   * @returns {Promise<void>}
   */
  async updateFingerprintRecord(username, fingerprintHash, fingerprintData, ip) {
    return new Promise((resolve, reject) => {
      this.fingerprintDB.update(
        { username },
        { 
          $set: { 
            fingerprintHash,
            fingerprintData,
            lastUsed: new Date().getTime(),
            lastIP: ip,
            updatedAt: new Date().getTime()
          }
        },
        {},
        (err) => {
          if (err) {
            reject(err);
          } else {
            console.log(`已更新用户"${username}"的设备指纹记录`);
            resolve();
          }
        }
      );
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