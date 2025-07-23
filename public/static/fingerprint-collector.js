/* global FingerprintJS */
/**
 * 设备指纹收集器
 * 收集浏览器和设备的各种特征用于生成唯一指纹
 */
class FingerprintCollector {
  constructor() {
    this.fingerprintData = {};
  }

  /**
   * 检测隐私模式
   * @returns {Promise<boolean>} 是否为隐私模式
   */
  detectPrivateMode() {
    return new Promise((resolve) => {
      // 方法1: 检测localStorage在隐私模式下的行为
      try {
        const testKey = '__private_mode_test__';
        localStorage.setItem(testKey, 'test');
        localStorage.removeItem(testKey);
        
        // 方法2: 检测indexedDB
        if (!window.indexedDB) {
          resolve(true);
          return;
        }
        
        // 方法3: 检测WebRTC
        if (!window.RTCPeerConnection && !window.webkitRTCPeerConnection && !window.mozRTCPeerConnection) {
          resolve(true);
          return;
        }
        
        // 方法4: 检测requestFileSystem (Chrome)
        if (window.webkitRequestFileSystem) {
          window.webkitRequestFileSystem(
            window.TEMPORARY, 1,
            () => resolve(false),
            () => resolve(true)
          );
        } else {
          resolve(false);
        }
      } catch (e) {
        // localStorage访问失败通常表示隐私模式
        resolve(true);
      }
    });
  }

  /**
   * 收集所有设备指纹数据
   * @returns {Promise<Object>} 完整的设备指纹数据
   */
  async collectFingerprint() {
    try {
      // 检测隐私模式
      const isPrivateMode = await this.detectPrivateMode();
      if (isPrivateMode) {
        // 隐私模式下返回特殊标记的指纹数据
        return {
          isPrivateMode: true,
          fingerprint: 'PRIVATE_MODE_DETECTED',
          userAgent: navigator.userAgent,
          timestamp: Date.now()
        };
      }
      
      // 使用FingerprintJS获取基础指纹
      let fpjsFingerprint = null;
      if (window.FingerprintJS) {
        const fp = await FingerprintJS.load();
        const result = await fp.get();
        fpjsFingerprint = {
          visitorId: result.visitorId,
          components: result.components
        };
      }

      // 并行收集各种指纹数据
      const [canvasFingerprint, webglFingerprint, audioFingerprint] = await Promise.all([
        this.getCanvasFingerprint(),
        this.getWebGLFingerprint(),
        this.getAudioFingerprint()
      ]);

      this.fingerprintData = {
        // FingerprintJS数据
        fingerprintjs: fpjsFingerprint,
        
        // 基础浏览器信息
        userAgent: navigator.userAgent,
        language: navigator.language,
        languages: navigator.languages ? navigator.languages.join(',') : '',
        platform: navigator.platform,
        cookieEnabled: navigator.cookieEnabled,
        doNotTrack: navigator.doNotTrack || '',
        
        // 屏幕特征
        screenResolution: `${screen.width}x${screen.height}`,
        availableScreenResolution: `${screen.availWidth}x${screen.availHeight}`,
        colorDepth: screen.colorDepth,
        pixelRatio: window.devicePixelRatio || 1,
        
        // 窗口特征
        windowResolution: `${window.innerWidth}x${window.innerHeight}`,
        
        // 硬件信息
        hardwareConcurrency: navigator.hardwareConcurrency || 0,
        deviceMemory: navigator.deviceMemory || 0,
        
        // 时区信息
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        timezoneOffset: new Date().getTimezoneOffset(),
        
        // 存储支持
        localStorage: this.hasLocalStorage(),
        sessionStorage: this.hasSessionStorage(),
        indexedDB: this.hasIndexedDB(),
        
        // 触摸支持
        touchSupport: this.getTouchSupport(),
        
        // 字体检测
        fonts: await this.getAvailableFonts(),
        
        // 插件信息
        plugins: this.getPlugins(),
        
        // Canvas指纹
        canvasFingerprint: canvasFingerprint,
        
        // WebGL指纹
        webglVendor: webglFingerprint.vendor,
        webglRenderer: webglFingerprint.renderer,
        webglFingerprint: webglFingerprint.fingerprint,
        
        // 音频指纹
        audioFingerprint: audioFingerprint,
        
        // 其他特征
        cpuClass: navigator.cpuClass || '',
        oscpu: navigator.oscpu || '',
        buildID: navigator.buildID || '',
        
        // 媒体设备
        mediaDevices: await this.getMediaDevices(),
        
        // 网络信息
        connection: this.getConnectionInfo(),
        
        // 电池信息（如果可用）
        battery: await this.getBatteryInfo(),
        
        // 权限状态
        permissions: await this.getPermissions(),
        
        // 收集时间戳
        timestamp: Date.now()
      };

      return this.fingerprintData;
    } catch (error) {
      console.error('设备指纹收集失败:', error);
      return this.getBasicFingerprint();
    }
  }

  /**
   * 获取Canvas指纹
   * @returns {string} Canvas指纹字符串
   */
  getCanvasFingerprint() {
    try {
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      
      // 设置canvas尺寸
      canvas.width = 200;
      canvas.height = 50;
      
      // 绘制文本
      ctx.textBaseline = 'top';
      ctx.font = '14px Arial';
      ctx.fillStyle = '#f60';
      ctx.fillRect(125, 1, 62, 20);
      ctx.fillStyle = '#069';
      ctx.fillText('🌟 Device Fingerprint 🔒', 2, 15);
      ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
      ctx.fillText('Canvas fingerprint', 4, 35);
      
      // 绘制几何图形
      ctx.globalCompositeOperation = 'multiply';
      ctx.fillStyle = 'rgb(255,0,255)';
      ctx.beginPath();
      ctx.arc(50, 50, 50, 0, Math.PI * 2, true);
      ctx.closePath();
      ctx.fill();
      ctx.fillStyle = 'rgb(0,255,255)';
      ctx.beginPath();
      ctx.arc(100, 50, 50, 0, Math.PI * 2, true);
      ctx.closePath();
      ctx.fill();
      ctx.fillStyle = 'rgb(255,255,0)';
      ctx.beginPath();
      ctx.arc(75, 100, 50, 0, Math.PI * 2, true);
      ctx.closePath();
      ctx.fill();
      
      return canvas.toDataURL();
    } catch (error) {
      return 'canvas_error';
    }
  }

  /**
   * 获取WebGL指纹
   * @returns {Object} WebGL指纹信息
   */
  getWebGLFingerprint() {
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      
      if (!gl) {
        return { vendor: 'no_webgl', renderer: 'no_webgl', fingerprint: 'no_webgl' };
      }
      
      const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
      const vendor = debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : 'unknown';
      const renderer = debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 'unknown';
      
      // 创建WebGL指纹
      const vertexShader = gl.createShader(gl.VERTEX_SHADER);
      gl.shaderSource(vertexShader, 'attribute vec2 attrVertex;varying vec2 varyinTexCoordinate;uniform vec2 uniformOffset;void main(){varyinTexCoordinate=attrVertex+uniformOffset;gl_Position=vec4(attrVertex,0,1);}');
      gl.compileShader(vertexShader);
      
      const fragmentShader = gl.createShader(gl.FRAGMENT_SHADER);
      gl.shaderSource(fragmentShader, 'precision mediump float;varying vec2 varyinTexCoordinate;void main() {gl_FragColor=vec4(varyinTexCoordinate,0,1);}');
      gl.compileShader(fragmentShader);
      
      const program = gl.createProgram();
      gl.attachShader(program, vertexShader);
      gl.attachShader(program, fragmentShader);
      gl.linkProgram(program);
      gl.useProgram(program);
      
      program.attrVertex = gl.getAttribLocation(program, 'attrVertex');
      program.uniformOffset = gl.getUniformLocation(program, 'uniformOffset');
      
      const buffer = gl.createBuffer();
      gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
      gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-0.2, -0.9, 0, 0.4, -0.26, 0, 0, 0.7321, 0]), gl.STATIC_DRAW);
      gl.enableVertexAttribArray(program.attrVertex);
      gl.vertexAttribPointer(program.attrVertex, 2, gl.FLOAT, false, 0, 0);
      gl.uniform2f(program.uniformOffset, 1, 1);
      gl.drawArrays(gl.TRIANGLE_STRIP, 0, 3);
      
      const fingerprint = canvas.toDataURL();
      
      return { vendor, renderer, fingerprint };
    } catch (error) {
      return { vendor: 'webgl_error', renderer: 'webgl_error', fingerprint: 'webgl_error' };
    }
  }

  /**
   * 获取音频指纹
   * @returns {Promise<string>} 音频指纹字符串
   */
  async getAudioFingerprint() {
    return new Promise((resolve) => {
      try {
        const audioContext = new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = audioContext.createOscillator();
        const analyser = audioContext.createAnalyser();
        const gainNode = audioContext.createGain();
        const scriptProcessor = audioContext.createScriptProcessor(4096, 1, 1);
        
        oscillator.type = 'triangle';
        oscillator.frequency.setValueAtTime(10000, audioContext.currentTime);
        
        gainNode.gain.setValueAtTime(0, audioContext.currentTime);
        
        oscillator.connect(analyser);
        analyser.connect(scriptProcessor);
        scriptProcessor.connect(gainNode);
        gainNode.connect(audioContext.destination);
        
        scriptProcessor.onaudioprocess = function(bins) {
          bins.outputBuffer.getChannelData(0).set(bins.inputBuffer.getChannelData(0));
          
          const data = new Float32Array(analyser.frequencyBinCount);
          analyser.getFloatFrequencyData(data);
          
          const fingerprint = data.slice(0, 30).join(',');
          
          oscillator.disconnect();
          scriptProcessor.disconnect();
          audioContext.close();
          
          resolve(fingerprint);
        };
        
        oscillator.start(0);
        
        // 超时处理
        setTimeout(() => {
          try {
            oscillator.disconnect();
            scriptProcessor.disconnect();
            audioContext.close();
          } catch (e) {
            // 忽略断开连接时的错误
          }
          resolve('audio_timeout');
        }, 1000);
        
      } catch (error) {
        resolve('audio_error');
      }
    });
  }

  /**
   * 检测可用字体
   * @returns {Promise<Array>} 可用字体列表
   */
  async getAvailableFonts() {
    const baseFonts = ['monospace', 'sans-serif', 'serif'];
    const testFonts = [
      'Arial', 'Arial Black', 'Arial Narrow', 'Arial Rounded MT Bold',
      'Calibri', 'Cambria', 'Candara', 'Century Gothic', 'Comic Sans MS',
      'Consolas', 'Courier', 'Courier New', 'Georgia', 'Helvetica',
      'Impact', 'Lucida Console', 'Lucida Sans Unicode', 'Microsoft Sans Serif',
      'Palatino', 'Tahoma', 'Times', 'Times New Roman', 'Trebuchet MS',
      'Verdana', 'Wingdings', 'SimSun', 'Microsoft YaHei', 'SimHei'
    ];
    
    const availableFonts = [];
    const testString = 'mmmmmmmmmmlli';
    const testSize = '72px';
    
    const canvas = document.createElement('canvas');
    const context = canvas.getContext('2d');
    
    // 获取基础字体的尺寸
    const baseSizes = {};
    for (const baseFont of baseFonts) {
      context.font = testSize + ' ' + baseFont;
      baseSizes[baseFont] = context.measureText(testString).width;
    }
    
    // 测试每个字体
    for (const testFont of testFonts) {
      let detected = false;
      for (const baseFont of baseFonts) {
        context.font = testSize + ' ' + testFont + ',' + baseFont;
        const width = context.measureText(testString).width;
        if (width !== baseSizes[baseFont]) {
          detected = true;
          break;
        }
      }
      if (detected) {
        availableFonts.push(testFont);
      }
    }
    
    return availableFonts;
  }

  /**
   * 获取插件信息
   * @returns {Array} 插件列表
   */
  getPlugins() {
    const plugins = [];
    for (let i = 0; i < navigator.plugins.length; i++) {
      const plugin = navigator.plugins[i];
      plugins.push({
        name: plugin.name,
        filename: plugin.filename,
        description: plugin.description
      });
    }
    return plugins;
  }

  /**
   * 检测触摸支持
   * @returns {Object} 触摸支持信息
   */
  getTouchSupport() {
    let maxTouchPoints = 0;
    let touchEvent = false;
    
    if (typeof navigator.maxTouchPoints !== 'undefined') {
      maxTouchPoints = navigator.maxTouchPoints;
    } else if (typeof navigator.msMaxTouchPoints !== 'undefined') {
      maxTouchPoints = navigator.msMaxTouchPoints;
    }
    
    try {
      document.createEvent('TouchEvent');
      touchEvent = true;
    } catch (e) {
      // 不支持TouchEvent
    }
    
    const touchStart = 'ontouchstart' in window;
    
    return {
      maxTouchPoints: maxTouchPoints,
      touchEvent: touchEvent,
      touchStart: touchStart
    };
  }

  /**
   * 检测本地存储支持
   * @returns {boolean} 是否支持localStorage
   */
  hasLocalStorage() {
    try {
      return !!window.localStorage;
    } catch (e) {
      return false;
    }
  }

  /**
   * 检测会话存储支持
   * @returns {boolean} 是否支持sessionStorage
   */
  hasSessionStorage() {
    try {
      return !!window.sessionStorage;
    } catch (e) {
      return false;
    }
  }

  /**
   * 检测IndexedDB支持
   * @returns {boolean} 是否支持IndexedDB
   */
  hasIndexedDB() {
    try {
      return !!window.indexedDB;
    } catch (e) {
      return false;
    }
  }

  /**
   * 获取媒体设备信息
   * @returns {Promise<Object>} 媒体设备信息
   */
  async getMediaDevices() {
    try {
      if (!navigator.mediaDevices || !navigator.mediaDevices.enumerateDevices) {
        return { error: 'not_supported' };
      }
      
      const devices = await navigator.mediaDevices.enumerateDevices();
      const deviceCounts = {
        audioinput: 0,
        audiooutput: 0,
        videoinput: 0
      };
      
      devices.forEach(device => {
        if (Object.prototype.hasOwnProperty.call(deviceCounts, device.kind)) {
          deviceCounts[device.kind]++;
        }
      });
      
      return deviceCounts;
    } catch (error) {
      return { error: 'permission_denied' };
    }
  }

  /**
   * 获取网络连接信息
   * @returns {Object} 网络连接信息
   */
  getConnectionInfo() {
    const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    if (connection) {
      return {
        effectiveType: connection.effectiveType,
        downlink: connection.downlink,
        rtt: connection.rtt,
        saveData: connection.saveData
      };
    }
    return { error: 'not_supported' };
  }

  /**
   * 获取电池信息
   * @returns {Promise<Object>} 电池信息
   */
  async getBatteryInfo() {
    try {
      if ('getBattery' in navigator) {
        const battery = await navigator.getBattery();
        return {
          charging: battery.charging,
          level: Math.round(battery.level * 100),
          chargingTime: battery.chargingTime,
          dischargingTime: battery.dischargingTime
        };
      }
      return { error: 'not_supported' };
    } catch (error) {
      return { error: 'permission_denied' };
    }
  }

  /**
   * 获取权限状态
   * @returns {Promise<Object>} 权限状态
   */
  async getPermissions() {
    const permissions = {};
    const permissionNames = ['camera', 'microphone', 'geolocation', 'notifications'];
    
    for (const name of permissionNames) {
      try {
        if ('permissions' in navigator) {
          const result = await navigator.permissions.query({ name });
          permissions[name] = result.state;
        }
      } catch (error) {
        permissions[name] = 'unknown';
      }
    }
    
    return permissions;
  }

  /**
   * 获取基础指纹（当完整收集失败时的备用方案）
   * @returns {Object} 基础设备指纹
   */
  getBasicFingerprint() {
    return {
      userAgent: navigator.userAgent,
      language: navigator.language,
      languages: navigator.languages ? navigator.languages.join(',') : '',
      platform: navigator.platform,
      cookieEnabled: navigator.cookieEnabled,
      doNotTrack: navigator.doNotTrack || 'unknown',
      
      // 屏幕信息
      screenWidth: screen.width,
      screenHeight: screen.height,
      screenColorDepth: screen.colorDepth,
      screenPixelDepth: screen.pixelDepth,
      availWidth: screen.availWidth,
      availHeight: screen.availHeight,
      
      // 时区信息
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      timezoneOffset: new Date().getTimezoneOffset(),
      
      // 硬件信息
      hardwareConcurrency: navigator.hardwareConcurrency || 'unknown',
      deviceMemory: navigator.deviceMemory || 'unknown',
      
      // 增强特征（更稳定的指纹特征）
      cpuClass: navigator.cpuClass || 'unknown',
      oscpu: navigator.oscpu || 'unknown',
      vendor: navigator.vendor || 'unknown',
      vendorSub: navigator.vendorSub || 'unknown',
      productSub: navigator.productSub || 'unknown',
      buildID: navigator.buildID || 'unknown',
      
      // 显示器特征
      pixelRatio: window.devicePixelRatio || 1,
      
      // 其他特征
      touchSupport: this.getTouchSupport(),
      localStorage: this.hasLocalStorage(),
      sessionStorage: this.hasSessionStorage(),
      indexedDB: this.hasIndexedDB(),
      
      timestamp: Date.now()
    };
  }
}

// 导出类供其他脚本使用
if (typeof module !== 'undefined' && module.exports) {
  module.exports = FingerprintCollector;
} else {
  window.FingerprintCollector = FingerprintCollector;
}