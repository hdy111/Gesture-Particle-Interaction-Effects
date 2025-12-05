// 3D粒子交互系统 - 独立JS文件
// 依赖：Three.js r128、TensorFlow.js、HandPoseDetection、MediaPipe Hands
// 需在HTML中先引入上述依赖库后再引入此文件

// 全局变量
let scene, camera, renderer, particles, particleSystem;
let handDetector = null;
let isDetecting = false;
let lastHandDistance = 0;
let currentShape = 'heart';
let particleCount = 10000;
let particleSize = 0.33;
let color1 = '#ff6ec7';
let color2 = '#7873f5';
let useGradient = true;
// 拖尾效果变量
let useTrailEffect = true; // 默认开启拖尾效果，让用户能立即看到效果
let trailStrength = 0.9; // 默认拖尾强度设为0.9，更易观察效果
let useInnerParticles = true; // 默认填充形状内部粒子
// 用于平滑过渡的变量
let targetScale = 1.0;
let isFullscreen = false;
let animationId = null;
let isUIVisible = true;
let isRotating = false;
let previousMousePosition = { x: 0, y: 0 };
// 速度控制变量
let zoomSpeed = 10; // 鼠标滚轮缩放速度
let particleSpeed = 10; // 粒子缩放动画速度
// 音乐播放变量
let audioElement = null;
let currentMusic = null;
// 存储自定义图像数据
let customImageData = null;
// 粒子历史位置（用于拖尾效果）
let particleHistory = [];

// 初始化Three.js场景
function initThreeJS() {
    // 创建场景
    scene = new THREE.Scene();
    scene.background = new THREE.Color(0x0c0c0c);
    
    // 创建相机
    camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
    camera.position.z = 30;
    
    // 创建渲染器
    renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setPixelRatio(window.devicePixelRatio);
    document.getElementById('canvas-container').appendChild(renderer.domElement);
    
    // 添加光源
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.6);
    scene.add(ambientLight);
    
    const directionalLight = new THREE.DirectionalLight(0xffffff, 0.8);
    directionalLight.position.set(10, 10, 5);
    scene.add(directionalLight);
    
    // 创建粒子系统
    createParticleSystem();
    
    // 添加鼠标拖动旋转功能
    addMouseRotationControls();
    
    // 窗口大小调整事件
    window.addEventListener('resize', onWindowResize);
}

// 创建粒子系统
function createParticleSystem() {
    // 如果已存在粒子系统，则从场景中移除
    if (particleSystem) {
        scene.remove(particleSystem);
        particleSystem.geometry.dispose();
        particleSystem.material.dispose();
    }
    
    // 创建粒子几何体
    const geometry = new THREE.BufferGeometry();
    const positions = new Float32Array(particleCount * 3);
    const colors = new Float32Array(particleCount * 3);
    
    // 根据选择的形状设置粒子位置
    setParticlePositions(positions, currentShape);
    
    // 设置粒子颜色
    updateParticleColors(colors);
    
    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));
    
    // 创建粒子材质
    const material = new THREE.PointsMaterial({
        size: particleSize,
        vertexColors: true,
        transparent: true,
        opacity: 0.8,
        sizeAttenuation: true,
        alphaTest: 0.5, // 启用alpha测试，使边缘更平滑
        blending: THREE.AdditiveBlending, // 使用加法混合，使粒子更明亮
        // 使用圆形纹理（可选）
        map: generateCircleTexture()
    });
    
    // 保存每个粒子的基础位置和缩放属性
    const basePositions = new Float32Array(particleCount * 3);
    const particleScales = new Float32Array(particleCount);
    const particleVelocities = new Float32Array(particleCount);
    const particleInertias = new Float32Array(particleCount);
    
    // 初始化粒子的基础位置和缩放属性
    for (let i = 0; i < particleCount; i++) {
        // 保存基础位置
        basePositions[i * 3] = positions[i * 3];
        basePositions[i * 3 + 1] = positions[i * 3 + 1];
        basePositions[i * 3 + 2] = positions[i * 3 + 2];
        
        // 初始缩放为1
        particleScales[i] = 1.0;
        
        // 随机速度：0.01到0.08之间
        particleVelocities[i] = 0.01 + Math.random() * 0.07;
        
        // 随机惯性：0.9到0.98之间，值越大惯性越大
        particleInertias[i] = 0.9 + Math.random() * 0.08;
    }
    
    // 创建圆形纹理的函数
    function generateCircleTexture() {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        const size = 64;
        canvas.width = size;
        canvas.height = size;
        
        // 创建径向渐变
        const gradient = ctx.createRadialGradient(size/2, size/2, 0, size/2, size/2, size/2);
        gradient.addColorStop(0, 'rgba(255, 255, 255, 1)');
        gradient.addColorStop(0.7, 'rgba(255, 255, 255, 0.8)');
        gradient.addColorStop(1, 'rgba(255, 255, 255, 0)');
        
        ctx.fillStyle = gradient;
        ctx.beginPath();
        ctx.arc(size/2, size/2, size/2, 0, Math.PI * 2);
        ctx.fill();
        
        // 创建纹理
        const texture = new THREE.CanvasTexture(canvas);
        texture.needsUpdate = true;
        
        return texture;
    }
    
    // 创建粒子系统
    particleSystem = new THREE.Points(geometry, material);
    
    // 初始化基础缩放值，与滚轮缩放使用相同的机制
    particleSystem.userData.baseScale = { x: 1, y: 1, z: 1 };
    
    // 保存粒子的基础位置和缩放属性
    particleSystem.userData.basePositions = basePositions;
    particleSystem.userData.particleScales = particleScales;
    particleSystem.userData.particleVelocities = particleVelocities;
    particleSystem.userData.particleInertias = particleInertias;
    
    // 保存原始目标缩放值
    particleSystem.userData.originalTargetScale = targetScale;
    
    scene.add(particleSystem);
    particles = geometry.attributes.position.array;
    
    // 初始化粒子历史位置
    particleHistory = [];
    for (let i = 0; i < particleCount; i++) {
        particleHistory[i] = [];
    }
}

// 根据形状设置粒子位置
function setParticlePositions(positions, shape) {
    const scale = 15;
    
    switch(shape) {
        case 'custom-image':
            // 生成平面的照片效果粒子，1:1还原图片颜色
            if (customImageData && customImageData.points && customImageData.colors) {
                // 获取从图像中提取的点和颜色数据
                const points = customImageData.points;
                const colors = customImageData.colors;
                
                // 确保有足够的点和颜色数据
                if (points.length > 0 && colors.length > 0) {
                    // 计算点的数量
                    const pointCount = Math.min(points.length, colors.length);
                    
                    // 将粒子分配到图像的点上
                    for (let i = 0; i < particleCount; i++) {
                        // 从图像数据中选择点和颜色，如果点不够则循环使用
                        const index = i % pointCount;
                        const point = points[index];
                        const color = colors[index];
                        
                        // 设置粒子位置（平面效果，Z轴固定为0）
                        positions[i * 3] = point.x;
                        positions[i * 3 + 1] = point.y;
                        positions[i * 3 + 2] = 0; // 固定在Z轴0位置，形成平面效果
                    }
                } else {
                    // 如果没有足够的点和颜色数据，使用默认的平面分布
                    for (let i = 0; i < particleCount; i++) {
                        positions[i * 3] = (Math.random() - 0.5) * 20;
                        positions[i * 3 + 1] = (Math.random() - 0.5) * 20;
                        positions[i * 3 + 2] = 0;
                    }
                }
            } else if (customImageData && customImageData.img) {
                // 备选方案：直接从图像中获取像素信息
                const img = customImageData.img;
                const canvas = document.createElement('canvas');
                const ctx = canvas.getContext('2d');
                
                // 调整图像大小
                const maxSize = 200;
                let width = img.width;
                let height = img.height;
                
                if (width > height) {
                    if (width > maxSize) {
                        height = Math.round(height * (maxSize / width));
                        width = maxSize;
                    }
                } else {
                    if (height > maxSize) {
                        width = Math.round(width * (maxSize / height));
                        height = maxSize;
                    }
                }
                
                canvas.width = width;
                canvas.height = height;
                ctx.drawImage(img, 0, 0, width, height);
                
                // 获取图像数据
                const imageData = ctx.getImageData(0, 0, width, height);
                const data = imageData.data;
                
                // 创建粒子网格并同时设置颜色
                let particleIndex = 0;
                for (let y = 0; y < height; y++) {
                    for (let x = 0; x < width; x++) {
                        if (particleIndex >= particleCount) break;
                        
                        // 计算像素位置和索引
                        const pixelIndex = (y * width + x) * 4;
                        const alpha = data[pixelIndex + 3];
                        
                        // 如果像素不透明，创建粒子
                        if (alpha > 128) {
                            // 设置粒子位置
                            positions[particleIndex * 3] = (x - width / 2) * 0.15;
                            positions[particleIndex * 3 + 1] = (height / 2 - y) * 0.15;
                            positions[particleIndex * 3 + 2] = 0;
                            
                            particleIndex++;
                        }
                    }
                    if (particleIndex >= particleCount) break;
                }
                
                // 如果粒子数量不够，补充剩余粒子
                for (; particleIndex < particleCount; particleIndex++) {
                    positions[particleIndex * 3] = (Math.random() - 0.5) * width * 0.15;
                    positions[particleIndex * 3 + 1] = (Math.random() - 0.5) * height * 0.15;
                    positions[particleIndex * 3 + 2] = 0;
                }
            } else {
                // 如果没有图像数据，默认使用平面分布
                for (let i = 0; i < particleCount; i++) {
                    positions[i * 3] = (Math.random() - 0.5) * 20;
                    positions[i * 3 + 1] = (Math.random() - 0.5) * 20;
                    positions[i * 3 + 2] = 0;
                }
            }
            break;
        case 'heart':
            // 爱心形状
            for (let i = 0; i < particleCount; i++) {
                const t = (i / particleCount) * Math.PI * 2;
                const x = 16 * Math.pow(Math.sin(t), 3);
                const y = 13 * Math.cos(t) - 5 * Math.cos(2*t) - 2 * Math.cos(3*t) - Math.cos(4*t);
                const z = (Math.random() - 0.5) * 5;
                
                let scaleFactor;
                if (useInnerParticles) {
                    // 内部和外部都有粒子
                    scaleFactor = scale * Math.random();
                } else {
                    // 只有外部轮廓的粒子
                    scaleFactor = scale;
                }
                
                positions[i * 3] = x / 10 * scaleFactor;
                positions[i * 3 + 1] = -y / 10 * scaleFactor;
                positions[i * 3 + 2] = z;
            }
            break;
            
        case 'flower':
            // 花朵形状
            for (let i = 0; i < particleCount; i++) {
                const t = (i / particleCount) * Math.PI * 8;
                let r;
                if (useInnerParticles) {
                    // 内部和外部都有粒子
                    r = (5 + 3 * Math.cos(7 * t)) * Math.random();
                } else {
                    // 只有外部轮廓的粒子
                    r = 5 + 3 * Math.cos(7 * t);
                }
                const x = r * Math.cos(t);
                const y = r * Math.sin(t);
                const z = (Math.random() - 0.5) * 8;
                
                positions[i * 3] = x;
                positions[i * 3 + 1] = y;
                positions[i * 3 + 2] = z;
            }
            break;
            
        case 'saturn':
            // 土星形状（带环的行星）
            for (let i = 0; i < particleCount; i++) {
                if (useInnerParticles) {
                    // 70%的粒子在球体上
                    if (i < particleCount * 0.7) {
                        const phi = Math.random() * Math.PI * 2;
                        const theta = Math.random() * Math.PI;
                        const radius = 8;
                        
                        positions[i * 3] = radius * Math.sin(theta) * Math.cos(phi);
                        positions[i * 3 + 1] = radius * Math.cos(theta);
                        positions[i * 3 + 2] = radius * Math.sin(theta) * Math.sin(phi);
                    } 
                    // 30%的粒子在环上
                    else {
                        const angle = Math.random() * Math.PI * 2;
                        const ringRadius = 12 + (Math.random() - 0.5) * 2;
                        const ringHeight = (Math.random() - 0.5) * 1.5;
                        
                        positions[i * 3] = ringRadius * Math.cos(angle);
                        positions[i * 3 + 1] = ringHeight;
                        positions[i * 3 + 2] = ringRadius * Math.sin(angle);
                    }
                } else {
                    // 只有土星环，没有内部球体
                    const angle = Math.random() * Math.PI * 2;
                    const ringRadius = 12 + (Math.random() - 0.5) * 2;
                    const ringHeight = (Math.random() - 0.5) * 1.5;
                    
                    positions[i * 3] = ringRadius * Math.cos(angle);
                    positions[i * 3 + 1] = ringHeight;
                    positions[i * 3 + 2] = ringRadius * Math.sin(angle);
                }
            }
            break;
            
        case 'star':
            // 星形
            for (let i = 0; i < particleCount; i++) {
                let t, r;
                if (useInnerParticles) {
                    // 内部和外部都有粒子
                    t = (i / particleCount) * Math.PI * 2;
                    r = 10 * Math.abs(Math.sin(5 * t)) * Math.abs(Math.cos(5 * t)) * Math.random();
                } else {
                    // 只有外部轮廓的粒子
                    t = (i / particleCount) * Math.PI * 2;
                    r = 10 * Math.abs(Math.sin(5 * t)) * Math.abs(Math.cos(5 * t));
                }
                const x = r * Math.cos(t);
                const y = r * Math.sin(t);
                const z = (Math.random() - 0.5) * 5;
                
                positions[i * 3] = x;
                positions[i * 3 + 1] = y;
                positions[i * 3 + 2] = z;
            }
            break;
            
        case 'ring':
            // 环形
            for (let i = 0; i < particleCount; i++) {
                const angle = Math.random() * Math.PI * 2;
                let radius;
                if (useInnerParticles) {
                    // 内部和外部都有粒子
                    radius = (Math.random() * 12);
                } else {
                    // 只有外部环的粒子
                    radius = 10 + (Math.random() - 0.5) * 2;
                }
                const x = radius * Math.cos(angle);
                const y = (Math.random() - 0.5) * 2;
                const z = radius * Math.sin(angle);
                
                positions[i * 3] = x;
                positions[i * 3 + 1] = y;
                positions[i * 3 + 2] = z;
            }
            break;
            
        case 'cube':
            // 立方体
            for (let i = 0; i < particleCount; i++) {
                let x, y, z;
                if (useInnerParticles) {
                    // 内部和外部都有粒子
                    x = (Math.random() - 0.5) * 20;
                    y = (Math.random() - 0.5) * 20;
                    z = (Math.random() - 0.5) * 20;
                } else {
                    // 只有立方体表面的粒子
                    x = (Math.random() - 0.5) * 20;
                    y = (Math.random() - 0.5) * 20;
                    z = (Math.random() - 0.5) * 20;
                    
                    // 随机选择立方体的一个面
                    const face = Math.floor(Math.random() * 6);
                    if (face === 0) x = 10; // 右
                    else if (face === 1) x = -10; // 左
                    else if (face === 2) y = 10; // 上
                    else if (face === 3) y = -10; // 下
                    else if (face === 4) z = 10; // 前
                    else z = -10; // 后
                }
                
                positions[i * 3] = x;
                positions[i * 3 + 1] = y;
                positions[i * 3 + 2] = z;
            }
            break;
            
        case 'spiral':
            // 螺旋形
            for (let i = 0; i < particleCount; i++) {
                const t = (i / particleCount) * 10 * Math.PI;
                let radius;
                if (useInnerParticles) {
                    // 内部和外部都有粒子
                    radius = (2 + t * 0.8) * Math.random();
                } else {
                    // 只有外部轮廓的粒子
                    radius = 2 + t * 0.8;
                }
                const x = radius * Math.cos(t);
                const y = radius * Math.sin(t);
                const z = (i / particleCount - 0.5) * 20;
                
                positions[i * 3] = x;
                positions[i * 3 + 1] = y;
                positions[i * 3 + 2] = z;
            }
            break;
            
        case 'snowflake':
            // 雪花形
            for (let i = 0; i < particleCount; i++) {
                let t, r;
                if (useInnerParticles) {
                    // 内部和外部都有粒子
                    t = (i / particleCount) * Math.PI * 2;
                    r = 10 * (Math.abs(Math.sin(3 * t)) + Math.abs(Math.cos(3 * t))) * Math.random();
                } else {
                    // 只有外部轮廓的粒子
                    t = (i / particleCount) * Math.PI * 2;
                    r = 10 * (Math.abs(Math.sin(3 * t)) + Math.abs(Math.cos(3 * t)));
                }
                const x = r * Math.cos(t);
                const y = r * Math.sin(t);
                const z = (Math.random() - 0.5) * 3;
                
                positions[i * 3] = x;
                positions[i * 3 + 1] = y;
                positions[i * 3 + 2] = z;
            }
            break;
            
        case 'torus':
            // 环形（甜甜圈形状）
            for (let i = 0; i < particleCount; i++) {
                const u = Math.random() * Math.PI * 2;
                const v = Math.random() * Math.PI * 2;
                const R = 10; // 大半径
                let r;
                if (useInnerParticles) {
                    // 内部和外部都有粒子
                    r = 3 * Math.random(); // 小半径随机，内部也有粒子
                } else {
                    // 只有表面的粒子
                    r = 3; // 固定小半径
                }
                
                const x = (R + r * Math.cos(v)) * Math.cos(u);
                const y = (R + r * Math.cos(v)) * Math.sin(u);
                const z = r * Math.sin(v);
                
                positions[i * 3] = x;
                positions[i * 3 + 1] = y;
                positions[i * 3 + 2] = z;
            }
            break;
            
        case 'sphere':
        default:
            // 球体形状
            for (let i = 0; i < particleCount; i++) {
                const phi = Math.random() * Math.PI * 2;
                const theta = Math.random() * Math.PI;
                let radius;
                if (useInnerParticles) {
                    // 内部和外部都有粒子
                    radius = 10 * Math.random();
                } else {
                    // 只有表面的粒子
                    radius = 10;
                }
                
                positions[i * 3] = radius * Math.sin(theta) * Math.cos(phi);
                positions[i * 3 + 1] = radius * Math.cos(theta);
                positions[i * 3 + 2] = radius * Math.sin(theta) * Math.sin(phi);
            }
            break;
    }
}

// 更新粒子颜色
function updateParticleColors(colors) {
    // 如果未传入colors数组，则从粒子系统中获取
    if (!colors) {
        colors = particleSystem.geometry.attributes.color.array;
    }
    
    // 如果是自定义图像且有颜色数据，使用图像的原始颜色
    if (currentShape === 'custom-image' && customImageData && customImageData.colors.length > 0) {
        for (let i = 0; i < particleCount; i++) {
            // 从图像颜色数据中选择颜色，如果颜色不够则循环使用
            const colorIndex = i % customImageData.colors.length;
            const color = customImageData.colors[colorIndex];
            
            colors[i * 3] = color.r;
            colors[i * 3 + 1] = color.g;
            colors[i * 3 + 2] = color.b;
        }
    } else {
        // 常规颜色处理逻辑
        const color1Obj = new THREE.Color(color1);
        const color2Obj = new THREE.Color(color2);
        
        for (let i = 0; i < particleCount; i++) {
            let r, g, b;
            
            if (useGradient) {
                // 计算渐变颜色
                const factor = i / particleCount;
                r = color1Obj.r + (color2Obj.r - color1Obj.r) * factor;
                g = color1Obj.g + (color2Obj.g - color1Obj.g) * factor;
                b = color1Obj.b + (color2Obj.b - color1Obj.b) * factor;
            } else {
                // 使用单一颜色
                r = color1Obj.r;
                g = color1Obj.g;
                b = color1Obj.b;
            }
            
            colors[i * 3] = r;
            colors[i * 3 + 1] = g;
            colors[i * 3 + 2] = b;
        }
    }
    
    if (particleSystem) {
        particleSystem.geometry.attributes.color.needsUpdate = true;
    }
}

// 识别手势（拳头或布）
function recognizeGesture(hand) {
    const keypoints = hand.keypoints;
    if (!keypoints || keypoints.length < 21) return 'unknown';
    
    // 关键点索引：0-手腕, 1-拇指根, 2-拇指中, 3-拇指近, 4-拇指尖
    // 5-食指根, 6-食指中, 7-食指近, 8-食指尖
    // 9-中指根, 10-中指中, 11-中指近, 12-中指尖
    // 13-无名指根, 14-无名指中, 15-无名指近, 16-无名指尖
    // 17-小指根, 18-小指中, 19-小指近, 20-小指尖
    
    // 计算每个手指的弯曲程度
    const fingers = [
        { name: 'thumb', tip: 4, mcp: 1 },    // 拇指
        { name: 'index', tip: 8, mcp: 5 },    // 食指
        { name: 'middle', tip: 12, mcp: 9 },  // 中指
        { name: 'ring', tip: 16, mcp: 13 },   // 无名指
        { name: 'pinky', tip: 20, mcp: 17 }   // 小指
    ];
    
    // 计算手掌中心（手腕和中指根的中点）
    const palmCenter = {
        x: (keypoints[0].x + keypoints[9].x) / 2,
        y: (keypoints[0].y + keypoints[9].y) / 2
    };
    
    // 计算每个手指指尖到手掌中心的距离
    const fingerDistances = fingers.map(finger => {
        const tip = keypoints[finger.tip];
        const mcp = keypoints[finger.mcp];
        
        // 计算指尖到手掌中心的距离
        const distanceToPalm = Math.sqrt(
            Math.pow(tip.x - palmCenter.x, 2) + 
            Math.pow(tip.y - palmCenter.y, 2)
        );
        
        // 计算MCP关节到手掌中心的距离
        const mcpToPalm = Math.sqrt(
            Math.pow(mcp.x - palmCenter.x, 2) + 
            Math.pow(mcp.y - palmCenter.y, 2)
        );
        
        // 返回指尖到手掌中心的相对距离
        return distanceToPalm - mcpToPalm;
    });
    
    // 计算平均距离
    const avgDistance = fingerDistances.reduce((sum, dist) => sum + dist, 0) / fingerDistances.length;
    
    // 判断手势：拳头时距离较小，布时距离较大
    if (avgDistance < 0.15) {
        return 'fist';  // 拳头
    } else if (avgDistance > 0.25) {
        return 'open';  // 布
    } else {
        return 'unknown';  // 未知手势
    }
}

// 处理手势控制
function handleHandGesture(hands) {
    if (hands.length >= 1) {
        // 获取第一个检测到的手
        const hand = hands[0];
        
        // 识别手势
        const gesture = recognizeGesture(hand);
        
        // 更新手势指示器
        updateGestureIndicator(gesture);
        
        // 根据手势控制粒子缩放
        if (particleSystem) {
            
            // 根据手势调整粒子大小和位置
            if (gesture === 'fist') {
                // 拳头：缩小粒子
                const scaleFactor = Math.max(0.5, 1 - particleSpeed * 0.1); // 限制缩小比例，避免粒子过小
                
                // 设置目标缩放值，用于平滑过渡
                targetScale = Math.max(0.2, targetScale * scaleFactor);
            } else if (gesture === 'open') {
                // 布：放大粒子
                const scaleFactor = Math.min(1.5, 1 + particleSpeed * 0.1); // 限制放大比例，避免速度过快
                
                // 设置目标缩放值，用于平滑过渡
                targetScale = Math.min(5.0, targetScale * scaleFactor);
            }
            
            particleSystem.geometry.attributes.position.needsUpdate = true;
        }
        
        // 如果检测到两只手，也可以保留原有的距离检测功能
        if (hands.length >= 2) {
            // 这里可以保留原有的双手距离检测逻辑（可选）
            const hand1 = hands[0].keypoints[9]; // 手掌中心
            const hand2 = hands[1].keypoints[9]; // 手掌中心
            
            const distance = Math.sqrt(
                Math.pow(hand1.x - hand2.x, 2) + 
                Math.pow(hand1.y - hand2.y, 2)
            );
            
            // 可以使用双手距离来控制其他参数（如旋转速度等）
        }
    } else {
        // 无手势检测
        document.querySelector('.gesture-icon').className = 'fas fa-hand-spock gesture-icon';
        document.querySelector('.gesture-text').textContent = '等待手势';
    }
}

// 更新手势指示器
function updateGestureIndicator(gesture) {
    const gestureIcon = document.querySelector('.gesture-icon');
    const gestureText = document.querySelector('.gesture-text');
    
    if (gesture === 'fist') {
        // 拳头
        gestureIcon.className = 'fas fa-fist-raised gesture-icon';
        gestureText.textContent = '拳头 - 粒子缩小';
    } else if (gesture === 'open') {
        // 布（手掌张开）
        gestureIcon.className = 'fas fa-hand-paper gesture-icon';
        gestureText.textContent = '布 - 粒子放大';
    } else if (typeof gesture === 'number') {
        // 保留原有的距离检测显示（兼容两只手的情况）
        if (gesture > lastHandDistance && lastHandDistance > 0) {
            gestureIcon.className = 'fas fa-hand-spock gesture-icon';
            gestureText.textContent = '双手张开 - 粒子扩散';
        } else if (gesture < lastHandDistance && lastHandDistance > 0) {
            gestureIcon.className = 'fas fa-praying-hands gesture-icon';
            gestureText.textContent = '双手闭合 - 粒子聚集';
        } else {
            gestureIcon.className = 'fas fa-hands gesture-icon';
            gestureText.textContent = '双手检测中';
        }
    } else {
        // 未知手势
        gestureIcon.className = 'fas fa-hand-sparkles gesture-icon';
        gestureText.textContent = '检测手势...';
    }
}

// 初始化摄像头和手势检测
async function initCamera() {
    try {
        const stream = await navigator.mediaDevices.getUserMedia({ 
            video: { 
                width: { ideal: 640 }, 
                height: { ideal: 480 },
                facingMode: 'user'
            } 
        });
        
        const video = document.getElementById('camera-feed');
        video.srcObject = stream;
        
        // 显示摄像头容器
        document.getElementById('camera-container').classList.remove('hidden');
        
        // 初始化手势检测模型
        await initHandDetection(video);
        
        return true;
    } catch (error) {
        console.error('摄像头访问失败:', error);
        // 模拟手势检测用于演示
        simulateHandDetection();
        return false;
    }
}

// 模拟手势检测（当摄像头不可用时）
function simulateHandDetection() {
    let simulatedDistance = 200;
    let increasing = true;
    
    setInterval(() => {
        if (!isDetecting) return;
        
        // 模拟距离变化
        if (increasing) {
            simulatedDistance += 10;
            if (simulatedDistance > 400) increasing = false;
        } else {
            simulatedDistance -= 10;
            if (simulatedDistance < 100) increasing = true;
        }
        
        // 创建模拟手势数据
        const mockHands = [
            { keypoints: [{x: 100, y: 100}, {}, {}, {}, {}, {}, {}, {}, {}, {x: 100, y: 100}] },
            { keypoints: [{x: 100 + simulatedDistance, y: 100}, {}, {}, {}, {}, {}, {}, {}, {}, {x: 100 + simulatedDistance, y: 100}] }
        ];
        
        handleHandGesture(mockHands);
    }, 300);
}

// 初始化手势检测
async function initHandDetection(video) {
    try {
        // 使用MediaPipe Hands进行手势检测
        const model = handPoseDetection.SupportedModels.MediaPipeHands;
        const detectorConfig = {
            runtime: 'mediapipe',
            modelType: 'full',
            maxHands: 2,
            solutionPath: 'https://cdn.jsdelivr.net/npm/@mediapipe/hands@0.4.1646424915'
        };
        
        handDetector = await handPoseDetection.createDetector(model, detectorConfig);
        
        // 开始检测循环
        async function detectHands() {
            if (!handDetector || !isDetecting) return;
            
            try {
                const hands = await handDetector.estimateHands(video);
                handleHandGesture(hands);
            } catch (error) {
                console.error('手势检测失败:', error);
            }
            
            // 继续下一帧检测
            requestAnimationFrame(detectHands);
        }
        
        // 开始检测
        isDetecting = true;
        detectHands();
        
    } catch (error) {
        console.error('手势检测初始化失败:', error);
        // 模拟手势检测作为后备
        simulateHandDetection();
    }
}

// 添加鼠标拖动旋转和滚轮缩放功能
function addMouseRotationControls() {
    const canvas = renderer.domElement;
    
    // 鼠标按下事件
    canvas.addEventListener('mousedown', (e) => {
        isRotating = true;
        previousMousePosition = { x: e.clientX, y: e.clientY };
        canvas.style.cursor = 'grabbing';
    });
    
    // 鼠标移动事件
    canvas.addEventListener('mousemove', (e) => {
        if (!isRotating || !particleSystem) return;
        
        // 计算鼠标移动的距离
        const deltaMove = {
            x: e.clientX - previousMousePosition.x,
            y: e.clientY - previousMousePosition.y
        };
        
        // 根据鼠标移动的距离旋转粒子系统
        const rotationSpeed = 0.005;
        particleSystem.rotation.x += deltaMove.y * rotationSpeed;
        particleSystem.rotation.y += deltaMove.x * rotationSpeed;
        
        // 更新前一鼠标位置
        previousMousePosition = { x: e.clientX, y: e.clientY };
    });
    
    // 鼠标释放事件
    window.addEventListener('mouseup', () => {
        isRotating = false;
        renderer.domElement.style.cursor = 'grab';
    });
    
    // 鼠标离开画布事件
    canvas.addEventListener('mouseleave', () => {
        isRotating = false;
        canvas.style.cursor = 'grab';
    });
    
    // 滚轮缩放事件
    canvas.addEventListener('wheel', (e) => {
        e.preventDefault();
        if (!particleSystem) return;
        
        // 计算缩放比例，确保缩放因子始终为正数
        const scaleFactor = e.deltaY > 0 ? 
            Math.max(0.5, 1 - zoomSpeed * 0.1) : // 缩小，限制最小缩放因子
            Math.min(1.5, 1 + zoomSpeed * 0.1);   // 放大，限制最大缩放因子
        
        // 更新目标缩放值（使用与手势控制相同的机制）
        targetScale *= scaleFactor;
        
        // 设置缩放范围限制
        const minScale = 0.2;
        const maxScale = 5.0;
        targetScale = Math.max(minScale, Math.min(maxScale, targetScale));
    });
    
    // 设置初始光标样式
    canvas.style.cursor = 'grab';
}

// 动画循环
function animate() {
    animationId = requestAnimationFrame(animate);
    
    // 如果没有拖动鼠标，则继续自动旋转
    if (particleSystem && !isRotating) {
        particleSystem.rotation.x += 0.005; // 增加旋转速度，更易观察拖尾效果
        particleSystem.rotation.y += 0.008; // 增加旋转速度，更易观察拖尾效果
    }
    
    // 应用平滑过渡效果，每个粒子独立缩放
    if (particleSystem) {
        // 获取粒子的基础位置和缩放属性
        const basePositions = particleSystem.userData.basePositions;
        const particleScales = particleSystem.userData.particleScales;
        const particleVelocities = particleSystem.userData.particleVelocities;
        const particleInertias = particleSystem.userData.particleInertias;
        
        // 获取位置属性
        const positions = particleSystem.geometry.attributes.position.array;
        
        // 为每个粒子应用独立的缩放和惯性
        for (let i = 0; i < particleCount; i++) {
            // 计算带惯性的平滑缩放过渡
            particleScales[i] += (targetScale - particleScales[i]) * particleVelocities[i] * (1.0 - particleInertias[i]) * particleSpeed;
            
            // 应用缩放后的位置
            positions[i * 3] = basePositions[i * 3] * particleScales[i];
            positions[i * 3 + 1] = basePositions[i * 3 + 1] * particleScales[i];
            positions[i * 3 + 2] = basePositions[i * 3 + 2] * particleScales[i];
        }
        
        // 更新粒子位置属性
        particleSystem.geometry.attributes.position.needsUpdate = true;
        
        // 添加轻微的脉动效果到整个系统
        const time = Date.now() * 0.001;
        const pulse = Math.sin(time) * 0.05 + 1;
        
        // 应用系统级别的脉动效果
        particleSystem.scale.x = pulse;
        particleSystem.scale.y = pulse;
        particleSystem.scale.z = pulse;
    }
    
    // 设置渲染器的清除方式和清除颜色
    if (useTrailEffect) {
        // 禁用自动清除
        renderer.autoClear = false;
        
        // 根据拖尾强度计算清除透明度
        // 拖尾强度越大，清除透明度越低，拖尾效果越明显
        const clearOpacity = 1.0 - trailStrength * 0.9;
        
        // 设置清除颜色为半透明黑色，透明度决定拖尾效果
        renderer.setClearColor(0x000000, clearOpacity);
        
        // 手动清除所有缓冲区
        renderer.clear();
    } else {
        // 恢复正常清除
        renderer.autoClear = true;
        renderer.setClearColor(0x000000, 1.0);
    }
    
    // 渲染场景
    renderer.render(scene, camera);
}

// 窗口大小调整处理
function onWindowResize() {
    camera.aspect = window.innerWidth / window.innerHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(window.innerWidth, window.innerHeight);
}

// 切换全屏
function toggleFullscreen() {
    const container = document.getElementById('container');
    
    if (!isFullscreen) {
        if (container.requestFullscreen) {
            container.requestFullscreen();
        } else if (container.webkitRequestFullscreen) {
            container.webkitRequestFullscreen();
        } else if (container.msRequestFullscreen) {
            container.msRequestFullscreen();
        }
        isFullscreen = true;
        document.getElementById('fullscreen-btn').innerHTML = '<i class="fas fa-compress"></i>';
    } else {
        if (document.exitFullscreen) {
            document.exitFullscreen();
        } else if (document.webkitExitFullscreen) {
            document.webkitExitFullscreen();
        } else if (document.msExitFullscreen) {
            document.msExitFullscreen();
        }
        isFullscreen = false;
        document.getElementById('fullscreen-btn').innerHTML = '<i class="fas fa-expand"></i>';
    }
}

// 处理图像上传
function handleImageUpload(event) {
    const file = event.target.files[0];
    if (!file) return;
    
    const reader = new FileReader();
    reader.onload = function(e) {
        // 创建临时图像元素
        const img = new Image();
        img.onload = function() {
            // 处理图像，提取轮廓和颜色
            customImageData = processImage(img);
            customImageData.img = img; // 保存原始图像对象
            
            // 提取所有像素点和颜色信息
            extractImagePixels(customImageData);
            
            // 更新UI - 显示自定义形状
            document.querySelectorAll('.shape-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            
            // 更新粒子形状
            currentShape = 'custom-image';
            createParticleSystem();
            
            // 显示提示
            alert(`已从图片中生成彩色粒子效果！`);
        };
        img.src = e.target.result;
    };
    reader.readAsDataURL(file);
}

// 处理图像，提取轮廓点和颜色信息
function processImage(img) {
    // 创建画布进行图像处理
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    
    // 调整图像大小以提高处理速度
    const maxSize = 200;
    let width = img.width;
    let height = img.height;
    
    if (width > height) {
        if (width > maxSize) {
            height = Math.round(height * (maxSize / width));
            width = maxSize;
        }
    } else {
        if (height > maxSize) {
            width = Math.round(width * (maxSize / height));
            height = maxSize;
        }
    }
    
    canvas.width = width;
    canvas.height = height;
    
    // 绘制原始图像
    ctx.drawImage(img, 0, 0, width, height);
    
    // 获取图像数据
    const imageData = ctx.getImageData(0, 0, width, height);
    const data = imageData.data;
    
    // 存储完整的图像信息
    return {
        points: [],
        colors: [],
        width: width,
        height: height
    };
}

// 从图像中提取所有像素点（包括颜色信息）
function extractImagePixels(imageInfo) {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    
    canvas.width = imageInfo.width;
    canvas.height = imageInfo.height;
    
    // 重绘图像
    ctx.drawImage(imageInfo.img, 0, 0, imageInfo.width, imageInfo.height);
    
    // 获取图像数据
    const imageData = ctx.getImageData(0, 0, imageInfo.width, imageInfo.height);
    const data = imageData.data;
    
    // 遍历图像，提取所有像素点
    const step = 2; // 采样步长，控制粒子密度
    for (let y = 0; y < imageInfo.height; y += step) {
        for (let x = 0; x < imageInfo.width; x += step) {
            const index = (y * imageInfo.width + x) * 4;
            
            // 获取像素颜色
            const r = data[index];
            const g = data[index + 1];
            const b = data[index + 2];
            const a = data[index + 3];
            
            // 只保留不透明的像素
            if (a > 128) {
                // 计算归一化坐标
                const normalizedX = (x - imageInfo.width / 2) / (imageInfo.width / 20);
                const normalizedY = -(y - imageInfo.height / 2) / (imageInfo.height / 20);
                
                imageInfo.points.push({
                    x: normalizedX,
                    y: normalizedY,
                    z: 0
                });
                
                // 存储颜色信息（0-1范围）
                imageInfo.colors.push({
                    r: r / 255,
                    g: g / 255,
                    b: b / 255
                });
            }
        }
    }
    
    return imageInfo;
}

// 初始化音频元素
function initAudio() {
    audioElement = new Audio();
    audioElement.loop = true;
    
    // 音乐进度条
    const musicProgress = document.getElementById('music-progress');
    
    // 音频时间更新事件
    audioElement.addEventListener('timeupdate', updateProgress);
    
    // 音频加载完成事件（获取总时长）
    audioElement.addEventListener('loadedmetadata', function() {
        document.getElementById('duration').textContent = formatTime(audioElement.duration);
        musicProgress.max = 100;
    });
    
    // 进度条点击/拖拽事件
    musicProgress.addEventListener('input', function() {
        setProgress(this.value);
    });
    
    // 进度条拖拽开始（暂停更新）
    musicProgress.addEventListener('mousedown', function() {
        audioElement.removeEventListener('timeupdate', updateProgress);
    });
    
    // 进度条拖拽结束（恢复更新）
    musicProgress.addEventListener('mouseup', function() {
        setProgress(this.value);
        audioElement.addEventListener('timeupdate', updateProgress);
    });
}

// 播放音乐
function playMusic() {
    if (audioElement && currentMusic) {
        audioElement.play().catch(error => {
            console.error('播放音乐失败:', error);
        });
        // 更新按钮状态
        const playPauseBtn = document.getElementById('play-pause-btn');
        playPauseBtn.innerHTML = '<i class="fas fa-pause"></i> 暂停';
        playPauseBtn.style.background = 'linear-gradient(135deg, #ff6ec7, #e84194)';
    }
}

// 暂停音乐
function pauseMusic() {
    if (audioElement) {
        audioElement.pause();
        // 更新按钮状态
        const playPauseBtn = document.getElementById('play-pause-btn');
        playPauseBtn.innerHTML = '<i class="fas fa-play"></i> 播放';
        playPauseBtn.style.background = 'linear-gradient(135deg, #7873f5, #4a44c8)';
    }
}

// 格式化时间（秒 -> mm:ss）
function formatTime(seconds) {
    const mins = Math.floor(seconds / 60);
    const secs = Math.floor(seconds % 60);
    return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
}

// 更新进度条
function updateProgress() {
    if (audioElement && audioElement.duration) {
        const progress = (audioElement.currentTime / audioElement.duration) * 100;
        document.getElementById('music-progress').value = progress;
        document.getElementById('current-time').textContent = formatTime(audioElement.currentTime);
    }
}

// 设置音乐进度
function setProgress(progress) {
    if (audioElement && audioElement.duration) {
        const time = (progress / 100) * audioElement.duration;
        audioElement.currentTime = time;
    }
}

// 重置音乐
function resetMusic() {
    if (audioElement && currentMusic) {
        audioElement.currentTime = 0;
        // 如果音乐之前是播放状态，重置后继续播放
        if (!audioElement.paused) {
            audioElement.play().catch(error => {
                console.error('播放音乐失败:', error);
            });
        }
    }
}

// 本地文件方式加载音乐列表
function loadMusicList() {
    const musicSelect = document.getElementById('music-select');
    
    // 清空现有选项
    musicSelect.innerHTML = '';
    
    // 使用全局的音乐文件列表
    let hasMusic = false;
    
    // 遍历所有音乐文件，创建选项
    musicFiles.forEach(fileName => {
        // 创建新的选项
        const option = document.createElement('option');
        option.value = 'music/' + fileName;
        option.textContent = fileName.replace('.mp3', '');
        musicSelect.appendChild(option);
        hasMusic = true;
    });
    
    // 如果没有找到音乐文件，添加提示选项
    if (!hasMusic) {
        const option = document.createElement('option');
        option.value = '';
        option.textContent = '未找到音乐文件';
        option.disabled = true;
        musicSelect.appendChild(option);
    } else {
        // 设置默认选中的音乐
        currentMusic = musicSelect.value;
    }
}

// 初始化UI事件
function initUIEvents() {
    // 加载音乐列表
    loadMusicList();
    // 形状选择按钮
    document.querySelectorAll('.shape-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            document.querySelectorAll('.shape-btn').forEach(b => b.classList.remove('active'));
            this.classList.add('active');
            
            currentShape = this.dataset.shape;
            createParticleSystem();
        });
    });
    
    // 颜色选择器
    document.getElementById('color1').addEventListener('input', function() {
        color1 = this.value;
        updateParticleColors();
    });
    
    document.getElementById('color2').addEventListener('input', function() {
        color2 = this.value;
        updateParticleColors();
    });
    
    // 渐变切换
    document.getElementById('gradient-toggle').addEventListener('change', function() {
        useGradient = this.checked;
        updateParticleColors();
    });
    
    // 粒子大小滑块
    const sizeSlider = document.getElementById('size-slider');
    const sizeValue = document.getElementById('size-value');
    
    sizeSlider.addEventListener('input', function() {
        particleSize = parseFloat(this.value);
        sizeValue.textContent = particleSize.toFixed(2);
        
        if (particleSystem) {
            particleSystem.material.size = particleSize;
        }
    });
    
    // 粒子数量滑块
    const countSlider = document.getElementById('count-slider');
    const countValue = document.getElementById('count-value');
    const particleCountDisplay = document.getElementById('particle-count');
    
    countSlider.addEventListener('input', function() {
        particleCount = parseInt(this.value);
        countValue.textContent = particleCount;
        particleCountDisplay.textContent = `粒子数: ${particleCount}`;
        
        createParticleSystem();
    });
    
    // 拖尾效果控制
    const trailToggle = document.getElementById('trail-toggle');
    const trailSlider = document.getElementById('trail-slider');
    const trailValue = document.getElementById('trail-value');
    
    trailToggle.addEventListener('change', function() {
        useTrailEffect = this.checked;
    });
    
    trailSlider.addEventListener('input', function() {
        trailStrength = parseFloat(this.value);
        trailValue.textContent = trailStrength.toFixed(2);
    });
    
    // 缩放速度控制
    const speedSlider = document.getElementById('speed-slider');
    const speedValue = document.getElementById('speed-value');
    
    speedSlider.addEventListener('input', function() {
        particleSpeed = parseFloat(this.value);
        speedValue.textContent = particleSpeed.toFixed(2);
    });
    
    // 鼠标滚轮速度控制
    const zoomSpeedSlider = document.getElementById('zoom-speed-slider');
    const zoomSpeedValue = document.getElementById('zoom-speed-value');
    
    zoomSpeedSlider.addEventListener('input', function() {
        zoomSpeed = parseFloat(this.value);
        zoomSpeedValue.textContent = zoomSpeed.toFixed(2);
    });
    
    // 内部粒子控制
    const innerParticlesToggle = document.getElementById('inner-particles-toggle');
    
    innerParticlesToggle.addEventListener('change', function() {
        useInnerParticles = this.checked;
        createParticleSystem(); // 重新创建粒子系统以应用新设置
    });
    
    // 图片上传
    document.getElementById('upload-trigger').addEventListener('click', function() {
        document.getElementById('image-upload').click();
    });
    
    document.getElementById('image-upload').addEventListener('change', handleImageUpload);
    
    // 全屏按钮
    document.getElementById('fullscreen-btn').addEventListener('click', toggleFullscreen);
    
    // 切换UI面板
    document.getElementById('toggle-panel').addEventListener('click', function() {
        const panel = document.getElementById('ui-panel');
        const icon = this.querySelector('i');
        
        if (isUIVisible) {
            panel.classList.add('collapsed');
            icon.className = 'fas fa-chevron-right';
        } else {
            panel.classList.remove('collapsed');
            icon.className = 'fas fa-chevron-left';
        }
        
        isUIVisible = !isUIVisible;
    });
    
    // 音乐选择
    const musicSelect = document.getElementById('music-select');
    musicSelect.addEventListener('change', function() {
        currentMusic = this.value;
        if (audioElement) {
            audioElement.src = currentMusic;
            audioElement.load();
            playMusic();
        }
    });
    
    // 播放/暂停切换按钮
    const playPauseBtn = document.getElementById('play-pause-btn');
    playPauseBtn.addEventListener('click', function() {
        if (audioElement.paused) {
            playMusic();
        } else {
            pauseMusic();
        }
    });
    
    // 启动按钮
    document.getElementById('start-btn').addEventListener('click', async function() {
        document.getElementById('status').classList.add('hidden');
        const success = await initCamera();
        
        if (!success) {
            alert('摄像头访问失败，将使用模拟手势控制。');
        }
        
        // 初始化音频
        initAudio();
        
        // 设置默认音乐
        currentMusic = musicSelect.value;
        audioElement.src = currentMusic;
        audioElement.load();
        playMusic();
        
        // 开始动画
        animate();
    });
}

// 键盘事件监听
document.addEventListener('keydown', function(event) {
    switch(event.key.toLowerCase()) {
        case 'q':
            resetMusic();
            break;
        case 'w':
            const playPauseBtn = document.getElementById('play-pause-btn');
            if (audioElement.paused) {
                playMusic();
            } else {
                pauseMusic();
            }
            break;
    }
});

// 页面加载完成时初始化
document.addEventListener('DOMContentLoaded', function() {
    initThreeJS();
    initUIEvents();
});