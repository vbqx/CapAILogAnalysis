from openai import OpenAI
import logging
import os
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

# 配置日志
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# 从环境变量获取API配置
API_KEY = os.getenv('DEEPSEEK_API_KEY')
BASE_URL = os.getenv('DEEPSEEK_BASE_URL')

if not API_KEY or not BASE_URL:
    raise ValueError("请在.env文件中设置 DEEPSEEK_API_KEY 和 DEEPSEEK_BASE_URL")

# 打印配置信息（注意不要显示完整的API密钥）
logger.info(f"BASE_URL: {BASE_URL}")
logger.info(f"API_KEY 前10个字符: {API_KEY[:10] if API_KEY else 'None'}")
logger.info(f"API_KEY 长度: {len(API_KEY) if API_KEY else 0}")

def test_api():
    try:
        # 初始化客户端
        logger.info("初始化 OpenAI 客户端...")
        client = OpenAI(
            base_url=BASE_URL,
            api_key=API_KEY,
            default_headers={
                "Authorization": f"Bearer {API_KEY}"
            }
        )
        
        # 打印客户端配置
        logger.info(f"客户端配置:")
        logger.info(f"- base_url: {client.base_url}")
        logger.info(f"- default_headers: {client.default_headers}")
        
        # 准备请求数据
        messages = [
            {
                "role": "user",
                "content": "分析一下这个网络流量的特点：TCP占80%，UDP占20%，总共100个数据包。"
            }
        ]
        
        logger.info("发送请求到 API...")
        logger.debug(f"请求消息: {messages}")
        logger.debug(f"完整请求配置:")
        logger.debug(f"- URL: {BASE_URL}/chat/completions")
        logger.debug(f"- Headers: {client.default_headers}")
        logger.debug(f"- Model: deepseek-ai/DeepSeek-V2.5")
        logger.debug(f"- Temperature: 0.7")
        logger.debug(f"- Max tokens: 2000")
        
        # 发送请求
        response = client.chat.completions.create(
            model="deepseek-ai/DeepSeek-V2.5",
            messages=messages,
            temperature=0.7,
            max_tokens=2000
        )
        
        logger.info("收到响应...")
        logger.debug(f"完整响应: {response}")
        
        if hasattr(response, 'choices') and len(response.choices) > 0:
            content = response.choices[0].message.content
            logger.info("API 响应内容:")
            print(content)
        else:
            logger.error("响应中没有找到有效内容")
            
    except Exception as e:
        logger.error(f"测试过程中发生错误: {str(e)}", exc_info=True)
        # 打印更多错误信息
        if hasattr(e, 'response'):
            logger.error(f"错误响应状态码: {e.response.status_code}")
            logger.error(f"错误响应头: {e.response.headers}")
            logger.error(f"错误响应内容: {e.response.text}")

if __name__ == "__main__":
    test_api()
    input("按回车键继续...") 