import os
import sys
import logging
import json
from pathlib import Path

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 导入本地模块
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend.app import analyze_pcap, TSHARK_PATH

def main():
    """测试PCAP文件分析功能"""
    # 指定测试文件路径
    test_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'uploads', 'mqtt_packets_Windows.cap')
    
    if not os.path.exists(test_file):
        logger.error(f"测试文件不存在: {test_file}")
        return
    
    logger.info(f"开始分析测试文件: {test_file}")
    logger.info(f"使用tshark路径: {TSHARK_PATH}")
    
    try:
        # 分析PCAP文件
        stats, connections = analyze_pcap(test_file)
        
        # 打印结果
        logger.info("分析结果:")
        logger.info(f"总数据包数: {stats.get('total_packets', 0)}")
        logger.info(f"唯一源IP数: {stats.get('unique_src_ips', 0)}")
        logger.info(f"唯一目标IP数: {stats.get('unique_dst_ips', 0)}")
        logger.info(f"唯一连接数: {stats.get('unique_connections', 0)}")
        logger.info(f"协议分布: {stats.get('protocols', {})}")
        logger.info(f"捕获持续时间: {stats.get('duration_seconds', 0)}秒")
        
        # 保存详细结果到文件
        with open('analysis_result.json', 'w', encoding='utf-8') as f:
            json.dump({
                'stats': stats,
                'connections': connections
            }, f, ensure_ascii=False, indent=2)
        
        logger.info(f"详细结果已保存到: analysis_result.json")
        
    except Exception as e:
        logger.error(f"分析过程中出错: {str(e)}", exc_info=True)

if __name__ == "__main__":
    # 运行主函数
    main() 