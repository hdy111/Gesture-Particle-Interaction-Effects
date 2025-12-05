#!/usr/bin/env python3
"""
3D粒子系统Web服务器（适配映射/内网穿透）
默认80端口，支持并发访问，优化外部网络请求兼容性
支持HTTPS协议，确保摄像头等敏感功能正常工作
"""

import http.server
import socketserver
import os
import argparse
import logging
from pathlib import Path
from datetime import datetime
import ssl
import socket

# ====================== 可编辑配置变量 ======================
# 服务器端口（默认80）
DEFAULT_PORT = 80

# 是否默认使用HTTPS（默认True）
DEFAULT_USE_HTTPS = True

# 服务器绑定地址（0.0.0.0表示绑定所有网络接口）
SERVER_HOST = "0.0.0.0"

# 请求队列大小（增大可处理更多并发请求）
REQUEST_QUEUE_SIZE = 50

# 日志级别（DEBUG, INFO, WARNING, ERROR）
LOG_LEVEL = logging.INFO

# 默认HTML文件（当访问根目录时使用）
# DEFAULT_HTML_FILE = "index1.html"
DEFAULT_HTML_FILE = "index2.html"
# ===========================================================

# 配置日志（方便排查映射后的请求是否到达服务器）
logging.basicConfig(
    level=LOG_LEVEL,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

class CustomRequestHandler(http.server.SimpleHTTPRequestHandler):
    """自定义请求处理器，优化映射场景兼容性"""
    
    # 支持HTTP/1.1（默认的SimpleHTTPRequestHandler可能强制HTTP/1.0，导致映射服务不兼容）
    protocol_version = "HTTP/1.1"
    
    def do_GET(self):
        """重写GET方法，支持自定义默认HTML文件和日志记录"""
        # 如果请求的是根目录，重定向到默认HTML文件
        if self.path == "/":
            self.path = f"/{DEFAULT_HTML_FILE}"
        
        # 记录请求信息（方便排查映射是否生效）
        client_ip = self.client_address[0]
        request_path = self.path
        logging.info(f"收到请求 - 客户端IP: {client_ip}, 路径: {request_path}, 协议: {self.request_version}")
        
        # 调用父类方法处理请求
        try:
            super().do_GET()
        except Exception as e:
            logging.error(f"处理请求失败: {e}")
            self.send_error(500, "服务器内部错误")
    
    def send_response(self, code, message=None):
        """重写send_response方法，在发送响应状态码后添加跨域响应头"""
        super().send_response(code, message)
        # 添加跨域支持（部分映射服务可能需要）
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
    
    def do_OPTIONS(self):
        """处理预检请求（映射/跨域场景必备）"""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", "0")
        self.end_headers()

def generate_self_signed_cert():
    """
    生成自签名SSL证书（用于HTTPS）
    :return: (cert_file, key_file) 证书文件路径
    """
    import tempfile
    import subprocess
    import platform
    
    # 创建临时文件存储证书和密钥
    cert_file = tempfile.NamedTemporaryFile(suffix='.pem', delete=False)
    key_file = tempfile.NamedTemporaryFile(suffix='.pem', delete=False)
    cert_path = cert_file.name
    key_path = key_file.name
    cert_file.close()
    key_file.close()
    
    try:
        if platform.system() == 'Windows':
            # Windows系统使用PowerShell生成自签名证书
            powershell_cmd = f"""
            $cert = New-SelfSignedCertificate -Type SSLServerAuthentication -Subject \"CN=localhost\" -FriendlyName \"3D Particle System\" -KeyAlgorithm RSA -KeyLength 2048 -CertStoreLocation \"Cert:\\CurrentUser\\My\" -NotAfter (Get-Date).AddYears(1)
            $certPath = \"cert:\\CurrentUser\\My\\$($cert.Thumbprint)\"
            Export-Certificate -Cert $certPath -FilePath \"{cert_path}\" -Type CERT
            $keyContainer = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
            $keyBytes = $keyContainer.Export([System.Security.Cryptography.RSAPrivateKeyFormat]::Pkcs1)
            [System.IO.File]::WriteAllBytes(\"{key_path}\", $keyBytes)
            """
            
            subprocess.run(['powershell', '-Command', powershell_cmd], check=True, capture_output=True, text=True)
        else:
            # Linux/macOS使用openssl生成自签名证书
            subprocess.run([
                'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
                '-keyout', key_path, '-out', cert_path,
                '-days', '365', '-nodes',
                '-subj', '/CN=localhost/O=3D Particle System/C=CN'
            ], check=True, capture_output=True, text=True)
        
        return cert_path, key_path
    except Exception as e:
        logging.error(f"生成自签名证书失败: {e}")
        return None, None

def run_server(port=DEFAULT_PORT, host=SERVER_HOST, use_https=DEFAULT_USE_HTTPS):
    """
    启动优化后的Web服务器（支持并发、映射兼容、HTTPS）
    :param port: 服务器端口，默认80
    :param host: 绑定所有网络接口（0.0.0.0），确保映射能访问
    :param use_https: 是否使用HTTPS协议，默认False
    """
    # 切换到脚本所在目录（确保能找到3D粒子系统的网页文件）
    current_dir = Path(__file__).parent.absolute()
    os.chdir(current_dir)
    logging.info(f"服务器根目录: {current_dir}")
    
    # 扫描music文件夹并生成musicList.js文件
    music_dir = Path(current_dir) / "music"
    if music_dir.exists() and music_dir.is_dir():
        # 获取所有MP3文件
        music_files = [file.name for file in music_dir.iterdir() if file.is_file() and file.suffix.lower() == '.mp3']
        
        # 按文件名排序
        music_files.sort()
        
        # 生成musicList.js内容
        music_list_content = "// 音乐文件列表配置（自动生成）\n"
        music_list_content += "const musicFiles = [\n"
        for file in music_files:
            music_list_content += f"    '{file}',\n"
        music_list_content = music_list_content.rstrip(',\n') + "\n"  # 移除最后一个逗号
        music_list_content += "];\n\n"
        music_list_content += "// 导出音乐列表（用于模块化导入）\n"
        music_list_content += "if (typeof module !== 'undefined' && module.exports) {\n"
        music_list_content += "    module.exports = { musicFiles };\n"
        music_list_content += "}\n"
        
        # 写入musicList.js文件
        music_list_path = Path(current_dir) / "musicList.js"
        try:
            with open(music_list_path, 'w', encoding='utf-8') as f:
                f.write(music_list_content)
            logging.info(f"成功生成musicList.js文件，包含{len(music_files)}首音乐")
        except Exception as e:
            logging.error(f"生成musicList.js文件失败: {e}")
    else:
        logging.warning("music文件夹不存在，跳过生成musicList.js")
    
    # 关键优化：使用多线程服务器，支持并发请求（原单线程会阻塞外部映射请求）
    # ThreadingTCPServer 为每个请求创建独立线程，避免映射后的并发请求被阻塞
    server_class = socketserver.ThreadingTCPServer
    server_class.allow_reuse_address = True  # 允许端口复用
    server_class.request_queue_size = REQUEST_QUEUE_SIZE  # 增大请求队列，应对映射后的多请求场景
    
    # 处理HTTPS配置
    cert_path = None
    key_path = None
    if use_https:
        cert_path, key_path = generate_self_signed_cert()
        if not cert_path or not key_path:
            logging.error("HTTPS证书生成失败，将回退到HTTP协议")
            use_https = False
    
    try:
        # 创建服务器实例（使用自定义请求处理器）
        with server_class((host, port), CustomRequestHandler) as httpd:
            if use_https:
                # 包装服务器以支持HTTPS
                httpd.socket = ssl.wrap_socket(
                    httpd.socket, 
                    certfile=cert_path, 
                    keyfile=key_path, 
                    server_side=True,
                    ssl_version=ssl.PROTOCOL_TLS_SERVER,
                    cert_reqs=ssl.CERT_NONE
                )
            
            local_ip = get_local_ip()
            protocol = "https" if use_https else "http"
            print("============================================")
            print(f"3D粒子系统Web服务器已启动（映射兼容版）")
            print(f"本地访问: {protocol}://localhost:{port}")
            print(f"局域网访问: {protocol}://{local_ip}:{port}")
            print(f"映射访问: 请使用你的内网穿透地址（{port}端口）")
            if use_https:
                print(f"HTTPS已启用，摄像头功能可用")
            else:
                print(f"HTTP模式，注意：某些浏览器可能限制摄像头访问")
            print("============================================")
            print("日志输出（可查看映射请求是否到达）：")
            print("============================================")
            
            # 启动服务器（持续运行）
            httpd.serve_forever()
    
    except KeyboardInterrupt:
        logging.info("\n服务器正在停止...")
        httpd.shutdown()
        print("服务器已停止")
    except OSError as e:
        if e.errno == 48 or "address already in use" in str(e).lower():
            logging.error(f"错误：80端口已被占用！")
            logging.error("请关闭占用80端口的程序（如IIS、Apache、Nginx等）")
        elif e.errno == 13 or "permission denied" in str(e).lower():
            logging.error(f"错误：无权限使用80端口！")
            logging.error("Windows：以管理员身份运行终端；Linux/macOS：使用 sudo 执行脚本")
        else:
            logging.error(f"服务器启动失败: {e}")

def get_local_ip():
    """获取本地局域网IP（用于验证局域网访问）"""
    import socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        return local_ip
    except Exception:
        return "127.0.0.1"

def main():
    parser = argparse.ArgumentParser(description="3D粒子系统Web服务器（适配映射/穿透）")
    parser.add_argument("-p", "--port", type=int, default=DEFAULT_PORT, help=f"服务器端口号，默认{DEFAULT_PORT}")
    parser.add_argument("--no-https", action="store_true", help=f"不使用HTTPS协议（默认使用{'HTTPS' if DEFAULT_USE_HTTPS else 'HTTP'})")
    args = parser.parse_args()
    # 默认使用HTTPS，除非明确指定--no-https
    use_https = not args.no_https
    run_server(port=args.port, use_https=use_https)

if __name__ == "__main__":
    main()