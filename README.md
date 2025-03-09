# 网络包分析平台 (Network Packet Analysis Platform)

这是一个基于Web的网络包分析平台，使用DeepSeek大模型来分析和总结网络连接信息。用户可以通过拖拽方式上传PCAP文件（最大5GB），系统会自动分析并展示网络连接的详细信息和总结。

## 功能特点

- 拖拽上传PCAP文件
- 自动提取网络连接信息
- 使用DeepSeek大模型进行智能分析
- 可视化展示分析结果
- 支持大文件处理（最大5GB）

## 技术栈

- 前端：HTML, CSS, JavaScript, Vue.js
- 后端：Python, Flask
- 网络包分析：pyshark, scapy
- AI模型：DeepSeek

## 安装与运行

### 环境要求

- Python 3.8+
- Node.js 14+

### 安装步骤

1. 克隆仓库
```
git clone https://github.com/yourusername/CapAILogAnalysis.git
cd CapAILogAnalysis
```

2. 安装后端依赖
```
pip install -r requirements.txt
```

3. 安装前端依赖
```
cd frontend
npm install
```

4. 配置环境变量
创建`.env`文件并添加DeepSeek API密钥：
```
DEEPSEEK_API_KEY=your_api_key_here
```

5. 运行应用
```
# 启动后端服务
cd backend
python app.py

# 在另一个终端启动前端服务
cd frontend
npm run serve
```

6. 访问应用
打开浏览器，访问 `http://localhost:8080`

## 使用方法

1. 打开应用首页
2. 将PCAP文件拖拽到指定区域或点击选择文件
3. 等待文件上传和分析完成
4. 查看分析结果和网络连接总结

## 注意事项

- 处理大文件可能需要较长时间，请耐心等待
- 确保您的DeepSeek API密钥有效且有足够的配额
- 分析结果的准确性取决于DeepSeek模型的能力
