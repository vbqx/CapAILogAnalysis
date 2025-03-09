import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename
import pandas as pd
import requests
from pathlib import Path
from collections import defaultdict
import numpy as np
from datetime import datetime
import logging
from openai import OpenAI  # 添加 OpenAI 客户端
import importlib
import sys
import subprocess
import asyncio  # 添加asyncio支持

# 加载环境变量
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
CORS(app)

# 从环境变量获取配置
UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', 'uploads')
MAX_CONTENT_LENGTH = int(os.getenv('MAX_CONTENT_LENGTH', 5368709120))  # 5GB
ALLOWED_EXTENSIONS = {'pcap', 'pcapng', 'cap'}

# 从环境变量获取API配置
DEEPSEEK_API_KEY = os.getenv('DEEPSEEK_API_KEY')
DEEPSEEK_BASE_URL = os.getenv('DEEPSEEK_BASE_URL')

if not DEEPSEEK_API_KEY or not DEEPSEEK_BASE_URL:
    raise ValueError("请在.env文件中设置 DEEPSEEK_API_KEY 和 DEEPSEEK_BASE_URL")

# 初始化 OpenAI 客户端
client = OpenAI(
    base_url=DEEPSEEK_BASE_URL,
    api_key=DEEPSEEK_API_KEY,
    default_headers={
        "Authorization": f"Bearer {DEEPSEEK_API_KEY}"
    }
)

# 启用详细日志记录
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 确保上传目录存在
Path(UPLOAD_FOLDER).mkdir(parents=True, exist_ok=True)

# 设置tshark路径
TSHARK_PATH = "D:\\Wireshark\\tshark.exe"
os.environ['PATH'] = os.environ['PATH'] + os.pathsep + "D:\\Wireshark"

# 检查是否有pyshark
try:
    import pyshark
    # 直接设置pyshark使用的tshark路径
    if hasattr(pyshark, 'config'):
        pyshark.config.TSHARK_PATH = TSHARK_PATH
    HAS_PYSHARK = True
except ImportError:
    logger.warning("pyshark库未安装，无法分析pcap文件")
    HAS_PYSHARK = False

# 检查tshark是否可用
def is_tshark_available():
    import subprocess
    try:
        # 直接使用绝对路径运行tshark
        process = subprocess.Popen([TSHARK_PATH, '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if process.returncode == 0:
            logger.info(f"找到并成功运行tshark: {TSHARK_PATH}")
            return True
        else:
            logger.warning(f"尝试运行tshark失败: {stderr.decode()}")
            return False
    except Exception as e:
        logger.warning(f"检查tshark时发生错误: {str(e)}")
        return False

HAS_TSHARK = is_tshark_available()
if not HAS_TSHARK:
    logger.warning("tshark未安装或不在PATH中，无法使用pyshark分析pcap文件")

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

class NetworkAnalyzer:
    def __init__(self, filters=None):
        self.protocol_stats = defaultdict(int)
        self.src_ips = defaultdict(int)
        self.dst_ips = defaultdict(int)
        self.connections = defaultdict(int)
        self.port_stats = defaultdict(int)
        self.packet_sizes = []
        self.timestamps = []
        self.total_packets = 0
        self.sample_connections = []  # 存储样本连接用于展示
        self.max_sample_connections = 1000
        # 添加过滤器
        self.filters = filters or {}
        
        # 添加连接状态跟踪
        self.connection_states = defaultdict(lambda: {
            'last_seen': None,
            'first_seen': None,
            'status': 'active',
            'protocol': None,
            'packets': [],
            'gaps': []
        })
        
        # 协议特定的超时时间（秒）
        self.protocol_timeouts = {
            'TCP': 300,    # 5分钟
            'HTTP': 120,   # 2分钟
            'DNS': 10,     # 10秒
            'UDP': 30,     # 30秒
            'default': 60  # 默认1分钟
        }

    def should_process_packet(self, packet):
        """检查数据包是否满足过滤条件"""
        if not hasattr(packet, 'ip'):
            return False

        # 检查源IP过滤器
        if self.filters.get('src_ip') and packet.ip.src != self.filters['src_ip']:
            return False

        # 检查目标IP过滤器
        if self.filters.get('dst_ip') and packet.ip.dst != self.filters['dst_ip']:
            return False

        # 检查协议过滤器
        if self.filters.get('protocols'):
            protocols = [p.strip().upper() for p in self.filters['protocols']]
            if packet.highest_layer not in protocols:
                return False

        return True

    def get_connection_key(self, packet):
        """生成连接唯一标识"""
        try:
            if hasattr(packet, 'ip'):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                protocol = packet.highest_layer
                
                # 对于TCP/UDP连接，包含端口信息
                if hasattr(packet, 'tcp'):
                    tcp_layer = packet.tcp
                    if isinstance(tcp_layer, dict):
                        src_port = tcp_layer.get('tcp.srcport')
                        dst_port = tcp_layer.get('tcp.dstport')
                    elif hasattr(tcp_layer, 'srcport') and hasattr(tcp_layer, 'dstport'):
                        src_port = getattr(tcp_layer, 'srcport')
                        dst_port = getattr(tcp_layer, 'dstport')
                elif hasattr(packet, 'udp'):
                    udp_layer = packet.udp
                    if isinstance(udp_layer, dict):
                        src_port = udp_layer.get('udp.srcport')
                        dst_port = udp_layer.get('udp.dstport')
                    elif hasattr(udp_layer, 'srcport') and hasattr(udp_layer, 'dstport'):
                        src_port = getattr(udp_layer, 'srcport')
                        dst_port = getattr(udp_layer, 'dstport')
                
                # 构建连接键
                if src_ip and dst_ip:
                    if src_port and dst_port:
                        return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                    else:
                        return f"{src_ip}-{dst_ip}"
                
                return None
        except Exception as e:
            logger.error(f"获取连接键时出错: {str(e)}")
            return None

    def detect_connection_gaps(self, connection_data):
        """检测连接中的异常间隔"""
        if len(connection_data['packets']) < 2:
            return []

        gaps = []
        protocol = connection_data['protocol']
        timeout = self.protocol_timeouts.get(protocol, self.protocol_timeouts['default'])
        
        # 按时间排序数据包
        sorted_packets = sorted(connection_data['packets'])
        
        for i in range(1, len(sorted_packets)):
            current_time = sorted_packets[i]
            prev_time = sorted_packets[i-1]
            gap = (current_time - prev_time).total_seconds()
            
            # 如果间隔超过协议超时时间，记录为异常断联
            if gap > timeout:
                gaps.append({
                    'start_time': prev_time,
                    'end_time': current_time,
                    'duration': gap,
                    'protocol': protocol
                })
        
        return gaps

    def update_stats(self, packet):
        """更新统计信息"""
        # 如果不满足过滤条件，跳过此数据包
        if not self.should_process_packet(packet):
            return
        
        # 更新基本计数
        self.total_packets += 1
        
        try:
            # 提取时间戳
            if hasattr(packet, 'sniff_timestamp') and packet.sniff_timestamp is not None:
                try:
                    # 时间戳可能是浮点数字符串，需要转换
                    timestamp = float(packet.sniff_timestamp)
                    self.timestamps.append(timestamp)
                except (ValueError, TypeError):
                    logger.warning(f"无法转换时间戳: {packet.sniff_timestamp}")
            
            # 记录数据包大小
            if hasattr(packet, 'length'):
                try:
                    length = int(packet.length)
                    self.packet_sizes.append(length)
                except (ValueError, TypeError):
                    logger.warning(f"无法转换数据包长度: {packet.length}")
            
            # 协议统计
            if hasattr(packet, 'highest_layer') and packet.highest_layer:
                self.protocol_stats[packet.highest_layer] += 1
            
            # 提取IP地址
            src_ip = None
            dst_ip = None
            
            # 检查IPv4
            if hasattr(packet, 'ip'):
                ip_layer = packet.ip
                if isinstance(ip_layer, dict):
                    src_ip = ip_layer.get('ip.src')
                    dst_ip = ip_layer.get('ip.dst')
                elif hasattr(ip_layer, 'src') and hasattr(ip_layer, 'dst'):
                    src_ip = getattr(ip_layer, 'src')
                    dst_ip = getattr(ip_layer, 'dst')
            
            # 检查IPv6
            if not src_ip and hasattr(packet, 'ipv6'):
                ipv6_layer = packet.ipv6
                if isinstance(ipv6_layer, dict):
                    src_ip = ipv6_layer.get('ipv6.src')
                    dst_ip = ipv6_layer.get('ipv6.dst')
                elif hasattr(ipv6_layer, 'src') and hasattr(ipv6_layer, 'dst'):
                    src_ip = getattr(ipv6_layer, 'src')
                    dst_ip = getattr(ipv6_layer, 'dst')
            
            # 如果找到IP地址，更新统计
            if src_ip:
                self.src_ips[src_ip] += 1
            
            if dst_ip:
                self.dst_ips[dst_ip] += 1
            
            # 端口统计
            src_port = None
            dst_port = None
            
            # TCP
            if hasattr(packet, 'tcp'):
                tcp_layer = packet.tcp
                if isinstance(tcp_layer, dict):
                    src_port = tcp_layer.get('tcp.srcport')
                    dst_port = tcp_layer.get('tcp.dstport')
                elif hasattr(tcp_layer, 'srcport') and hasattr(tcp_layer, 'dstport'):
                    src_port = getattr(tcp_layer, 'srcport')
                    dst_port = getattr(tcp_layer, 'dstport')
            
            # UDP
            elif hasattr(packet, 'udp'):
                udp_layer = packet.udp
                if isinstance(udp_layer, dict):
                    src_port = udp_layer.get('udp.srcport')
                    dst_port = udp_layer.get('udp.dstport')
                elif hasattr(udp_layer, 'srcport') and hasattr(udp_layer, 'dstport'):
                    src_port = getattr(udp_layer, 'srcport')
                    dst_port = getattr(udp_layer, 'dstport')
            
            # 更新端口统计
            if src_port:
                self.port_stats[int(src_port)] += 1
            
            if dst_port:
                self.port_stats[int(dst_port)] += 1
            
            # 更新连接统计
            if src_ip and dst_ip:
                conn_key = self.get_connection_key(packet)
                if conn_key:
                    self.connections[conn_key] += 1
                    
                    # 更新连接状态
                    if conn_key not in self.connection_states:
                        self.connection_states[conn_key] = {
                            'first_seen': None,
                            'last_seen': None,
                            'status': 'active',
                            'protocol': packet.highest_layer if hasattr(packet, 'highest_layer') else None,
                            'packets': [],
                            'gaps': []
                        }
                    
                    conn_state = self.connection_states[conn_key]
                    
                    # 记录时间戳
                    if hasattr(packet, 'sniff_timestamp') and packet.sniff_timestamp:
                        timestamp = float(packet.sniff_timestamp)
                        
                        if not conn_state['first_seen'] or timestamp < conn_state['first_seen']:
                            conn_state['first_seen'] = timestamp
                        
                        if not conn_state['last_seen'] or timestamp > conn_state['last_seen']:
                            conn_state['last_seen'] = timestamp
                        
                        conn_state['packets'].append(timestamp)
                    
                    # 保存样本连接数据
                    if len(self.sample_connections) < self.max_sample_connections:
                        self.sample_connections.append({
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'src_port': src_port,
                            'dst_port': dst_port,
                            'protocol': packet.highest_layer if hasattr(packet, 'highest_layer') else None,
                            'timestamp': float(packet.sniff_timestamp) if hasattr(packet, 'sniff_timestamp') and packet.sniff_timestamp else None,
                            'length': int(packet.length) if hasattr(packet, 'length') else 0
                        })
        
        except Exception as e:
            logger.error(f"更新统计信息时出错: {str(e)}", exc_info=True)

    def get_summary_stats(self):
        """获取汇总统计信息"""
        # 分析所有连接的断联情况
        connection_gaps = []
        for conn_key, conn_data in self.connection_states.items():
            gaps = self.detect_connection_gaps(conn_data)
            if gaps:
                for gap in gaps:
                    connection_gaps.append({
                        'connection': conn_key,
                        'start_time': gap['start_time'].isoformat(),
                        'end_time': gap['end_time'].isoformat(),
                        'duration': gap['duration'],
                        'protocol': gap['protocol']
                    })

        # 计算时间范围
        if self.timestamps:
            start_time = min(self.timestamps)
            end_time = max(self.timestamps)
            duration = (end_time - start_time).total_seconds()
        else:
            duration = 0
        
        # 计算包大小统计
        packet_sizes = np.array(self.packet_sizes) if self.packet_sizes else np.array([0])
        
        # 获取最常见的端口
        top_ports = sorted(self.port_stats.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # 获取最活跃的IP
        top_src_ips = sorted(self.src_ips.items(), key=lambda x: x[1], reverse=True)[:10]
        top_dst_ips = sorted(self.dst_ips.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            'total_packets': self.total_packets,
            'unique_src_ips': len(self.src_ips),
            'unique_dst_ips': len(self.dst_ips),
            'unique_connections': len(self.connections),
            'protocols': dict(self.protocol_stats),
            'duration_seconds': duration,
            'avg_packet_size': float(np.mean(packet_sizes)),
            'max_packet_size': float(np.max(packet_sizes)),
            'min_packet_size': float(np.min(packet_sizes)),
            'top_ports': dict(top_ports),
            'top_src_ips': dict(top_src_ips),
            'top_dst_ips': dict(top_dst_ips),
            'packets_per_second': self.total_packets / duration if duration > 0 else 0,
            'connection_gaps': connection_gaps  # 添加断联信息
        }

def analyze_pcap(filepath, filters=None):
    """分批分析PCAP文件"""
    analyzer = NetworkAnalyzer(filters)
    
    try:
        # 使用同步方式处理捕获文件，避免事件循环冲突
        logger.info(f"开始分析文件: {filepath}")
        
        # 使用tshark直接读取和解析packet，避免异步冲突
        import subprocess
        import json
        
        # 使用tshark命令行工具直接解析为json格式
        cmd = [
            TSHARK_PATH, 
            '-r', filepath,  # 读取指定的捕获文件
            '-T', 'ek',      # 输出为Elasticsearch JSON格式 (更简单的JSON格式)
            '-x'             # 包含十六进制和ASCII输出
        ]
        
        logger.info(f"执行命令: {' '.join(cmd)}")
        
        try:
            # 执行命令并获取输出，使用二进制模式避免编码问题
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                universal_newlines=False  # 使用二进制模式
            )
            
            stdout_data, stderr_data = process.communicate()
            
            # 处理可能的错误
            if process.returncode != 0:
                stderr_text = stderr_data.decode('utf-8', errors='ignore')
                logger.error(f"tshark命令执行失败: {stderr_text}")
                return analyzer.get_summary_stats(), analyzer.sample_connections
            
            # 将二进制输出解码为文本
            stdout_text = stdout_data.decode('utf-8', errors='ignore')
            
            if not stdout_text or not stdout_text.strip():
                logger.warning("tshark未返回任何数据，可能是空的捕获文件")
                return analyzer.get_summary_stats(), analyzer.sample_connections
            
            # 解析JSON输出，每行是一个独立的JSON对象
            packet_count = 0
            for line in stdout_text.splitlines():
                if not line.strip():
                    continue
                    
                try:
                    packet_json = json.loads(line)
                    packet_count += 1
                    
                    # 提取数据包信息
                    layers = packet_json.get('layers', {})
                    
                    # 创建一个简单的数据包对象，包含必要的属性
                    class SimplePacket:
                        def __init__(self):
                            self.sniff_timestamp = None
                            self.highest_layer = None
                            self.transport_layer = None
                            self.ip = None
                            self.ipv6 = None
                            self.tcp = None
                            self.udp = None
                            self.length = 0
                            self.layers = []
                    
                    packet = SimplePacket()
                    
                    # 提取基本信息
                    if 'frame' in layers:
                        frame = layers['frame']
                        packet.sniff_timestamp = frame.get('frame.time_epoch')
                        packet.length = int(frame.get('frame.len', 0))
                    
                    # 提取协议信息
                    for layer_name, layer_data in layers.items():
                        if layer_name != 'frame':
                            packet.layers.append(layer_name)
                            setattr(packet, layer_name, layer_data)
                    
                    # 设置最高层协议
                    if packet.layers:
                        packet.highest_layer = packet.layers[-1]
                    
                    # 设置传输层
                    if 'tcp' in packet.layers:
                        packet.transport_layer = 'tcp'
                    elif 'udp' in packet.layers:
                        packet.transport_layer = 'udp'
                    
                    # 更新统计信息
                    analyzer.update_stats(packet)
                    
                    # 打印进度
                    if packet_count % 100 == 0:
                        logger.info(f"已处理 {packet_count} 个数据包")
                    
                except json.JSONDecodeError:
                    logger.warning(f"无法解析JSON行: {line[:100]}...")
                    continue
                except Exception as e:
                    logger.error(f"处理数据包 {packet_count} 时出错: {str(e)}", exc_info=True)
                    continue
            
            logger.info(f"文件分析完成，共处理 {packet_count} 个数据包")
            
        except Exception as e:
            logger.error(f"执行tshark命令时出错: {str(e)}", exc_info=True)
    
    except Exception as e:
        logger.error(f"读取捕获文件时出错: {str(e)}", exc_info=True)
    
    return analyzer.get_summary_stats(), analyzer.sample_connections

def get_ai_summary(stats, sample_connections):
    """使用DeepSeek API基于汇总数据生成分析报告"""
    # 准备提示词
    prompt = f"""分析以下网络流量数据并提供详细的网络安全分析报告：

基本统计信息：
- 总数据包数：{stats['total_packets']}
- 唯一源IP数：{stats['unique_src_ips']}
- 唯一目标IP数：{stats['unique_dst_ips']}
- 唯一连接数：{stats['unique_connections']}
- 捕获持续时间：{stats['duration_seconds']:.2f}秒
- 平均每秒数据包：{stats['packets_per_second']:.2f}

数据包大小统计：
- 平均大小：{stats['avg_packet_size']:.2f}字节
- 最大大小：{stats['max_packet_size']}字节
- 最小大小：{stats['min_packet_size']}字节

协议分布：
{stats['protocols']}

最活跃的源IP（前10个）：
{stats['top_src_ips']}

最活跃的目标IP（前10个）：
{stats['top_dst_ips']}

最常用端口（前10个）：
{stats['top_ports']}

请提供以下方面的专业分析：
1. 网络流量模式和特征
2. 潜在的安全威胁和异常行为
3. 可疑的网络活动
4. 具体的安全建议和防护措施
"""
    
    try:
        logger.debug("准备发送请求到 DeepSeek API")
        response = client.chat.completions.create(
            model="deepseek-ai/DeepSeek-R1",
            messages=[
                {"role": "system", "content": "你是一个专业的网络安全分析师，擅长分析网络流量并提供专业的安全建议。"},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=2000
        )
        
        logger.debug(f"收到 API 响应: {response}")
        logger.debug(f"响应类型: {type(response)}")
        logger.debug(f"响应属性: {dir(response)}")
        
        if hasattr(response, 'choices') and len(response.choices) > 0:
            logger.debug(f"第一个选择: {response.choices[0]}")
            logger.debug(f"选择属性: {dir(response.choices[0])}")
            if hasattr(response.choices[0], 'message'):
                logger.debug(f"消息内容: {response.choices[0].message}")
                return response.choices[0].message.content
            else:
                logger.error("响应中没有找到 message 属性")
                return "API 响应格式错误：没有找到消息内容"
        else:
            logger.error("响应中没有找到 choices")
            return "API 响应格式错误：没有找到选择项"
            
    except Exception as e:
        logger.error(f"调用AI API时发生错误：{str(e)}", exc_info=True)
        return f"调用AI API时发生错误：{str(e)}"

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': '没有文件被上传'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': '没有选择文件'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': '不支持的文件类型'}), 400
    
    # 检查是否可以分析PCAP文件
    if not HAS_PYSHARK or not HAS_TSHARK:
        return jsonify({
            'error': '服务器缺少分析PCAP文件所需的组件。请安装Wireshark和pyshark库。'
        }), 500
    
    try:
        # 获取过滤参数
        filters = {
            'src_ip': request.form.get('src_ip'),
            'dst_ip': request.form.get('dst_ip'),
            'protocols': request.form.get('protocols', '').split(',') if request.form.get('protocols') else None
        }
        
        # 移除空值
        filters = {k: v for k, v in filters.items() if v}
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)
        
        # 分析PCAP文件
        stats, sample_connections = analyze_pcap(filepath, filters)
        
        # 获取AI分析总结
        summary = get_ai_summary(stats, sample_connections)
        
        # 删除临时文件
        os.remove(filepath)
        
        return jsonify({
            'success': True,
            'stats': stats,
            'connections': sample_connections,
            'summary': summary,
            'total_connections': len(sample_connections),
            'filters': filters  # 返回使用的过滤器
        })
    
    except Exception as e:
        logger.error(f"处理文件时发生错误: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/chat', methods=['POST'])
def chat():
    """处理与DeepSeek的对话"""
    try:
        data = request.json
        if not data:
            logger.error("没有收到JSON数据")
            return jsonify({'success': False, 'error': '没有收到JSON数据'}), 400
            
        message = data.get('message')
        if not message:
            logger.error("消息内容为空")
            return jsonify({'success': False, 'error': '消息内容不能为空'}), 400
            
        context = data.get('context', {})
        
        logger.info(f"收到请求 - 消息: {message}")
        logger.info(f"上下文数据: {context}")
        
        # 构建提示词
        system_prompt = """你是一个专业的网络安全分析师，正在分析一个PCAP文件的网络流量。
基于以下网络分析数据回答用户的问题：

基本统计信息：
- 总数据包数：{total_packets}
- 唯一源IP数：{unique_src_ips}
- 唯一目标IP数：{unique_dst_ips}
- 唯一连接数：{unique_connections}
- 捕获持续时间：{duration_seconds:.2f}秒

协议分布：
{protocols}

请基于这些信息，专业且详细地回答用户的问题。""".format(
            total_packets=context.get('total_packets', 'N/A'),
            unique_src_ips=context.get('unique_src_ips', 'N/A'),
            unique_dst_ips=context.get('unique_dst_ips', 'N/A'),
            unique_connections=context.get('unique_connections', 'N/A'),
            duration_seconds=context.get('duration_seconds', 0),
            protocols=context.get('protocols', {})
        )

        logger.debug(f"系统提示词: {system_prompt}")
        
        try:
            # 发送请求
            response = client.chat.completions.create(
                model="deepseek-ai/DeepSeek-V2.5",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": message}
                ],
                temperature=0.7,
                max_tokens=2000
            )
            
            logger.debug(f"API响应: {response}")
            
            if hasattr(response, 'choices') and len(response.choices) > 0:
                content = response.choices[0].message.content
                logger.info(f"API响应内容: {content}")
                return jsonify({
                    'success': True,
                    'response': content
                })
            else:
                error_msg = "响应中没有找到有效内容"
                logger.error(error_msg)
                return jsonify({'success': False, 'error': error_msg}), 500
                
        except Exception as e:
            error_message = f"调用AI API时发生错误：{str(e)}"
            logger.error(error_message, exc_info=True)
            return jsonify({
                'success': False,
                'error': error_message
            }), 500
            
    except Exception as e:
        error_message = f"处理请求时发生错误：{str(e)}"
        logger.error(error_message, exc_info=True)
        return jsonify({
            'success': False,
            'error': error_message
        }), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000) 