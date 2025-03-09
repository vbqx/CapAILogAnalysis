import requests
import json
import logging

# 配置日志
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def send_test_request():
    url = "http://localhost:5000/chat"
    headers = {
        "Content-Type": "application/json"
    }
    
    data = {
        "message": "分析一下这个网络流量的特点",
        "context": {
            "total_packets": 100,
            "unique_src_ips": 5,
            "unique_dst_ips": 3,
            "unique_connections": 10,
            "duration_seconds": 60,
            "protocols": {
                "TCP": 80,
                "UDP": 20
            }
        }
    }

    try:
        logger.info(f"Sending request to {url}")
        logger.debug(f"Request headers: {headers}")
        logger.debug(f"Request data: {json.dumps(data, indent=2)}")
        
        response = requests.post(url, headers=headers, json=data)
        
        logger.info(f"Response status code: {response.status_code}")
        logger.info(f"Response headers: {response.headers}")
        
        if response.status_code == 200:
            logger.info("Request successful")
            logger.info(f"Response content: {json.dumps(response.json(), indent=2, ensure_ascii=False)}")
        else:
            logger.error(f"Request failed with status code {response.status_code}")
            logger.error(f"Error response: {json.dumps(response.json(), indent=2, ensure_ascii=False)}")
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed with error: {str(e)}")
    except json.JSONDecodeError:
        logger.error("Failed to decode JSON response")
        logger.error(f"Raw response: {response.text}")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")

if __name__ == "__main__":
    send_test_request()
    input("按回车键继续...") 