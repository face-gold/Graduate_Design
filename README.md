# Graduate_Design
## 说明
本项目是：基于机器学习的加密恶意流量检测<br>参考项目：https://github.com/Timeless-zfqi/AS-DMF-framework
## 简介
本项目是本科毕设题目，依托参考项目课题组完成，首先向课题组表示感谢；其次，项目是关于机器学习的加密恶意流量检测，本人首次接触这个方向，是纯小白，内容不是很饱满，但是本项目针对自己的论文结构进行了web页面展示，方便熟悉论文结构框架的同时，呈现了一个基本的加密恶意流量检测的流程。最后，希望有不足之处可以得到谅解、有问题之处可以提出并相互学习！
## 环境
所需环境：Python 3.8(ubuntu20.04)、zeek version 7.0.0-dev.102，Zeek flowmeter<br>
安装所需要的包——requirements.txt中罗列主要的包，如遇到相关包未安装的报错问题，自行安装即可。
## web界面
本项目是基于Flask和bootstrap进行开发，是一个简单的可视化任务。<br>
运行项目：终端中进入项目的文件夹，执行指令“python app.py”。
### 基础功能展示
#### 主页
![image](https://github.com/face-gold/Graduate_Design/blob/main/images/image-20240530140503115.png)
#### 上传文件
![image](https://github.com/face-gold/Graduate_Design/blob/main/images/image-20240530140532240.png)
#### 解析文件
![image](https://github.com/face-gold/Graduate_Design/blob/main/images/image-20240530140602240.png)
#### 解析结果
![image](https://github.com/face-gold/Graduate_Design/blob/main/images/image-20240530140622546.png)
#### 实验数据展示
![image](https://github.com/face-gold/Graduate_Design/blob/main/images/image-20240530141656822.png)
### 注意
本项目的可视化任务目的是为了毕业答辩时更好地展示本人的论文实现框架。<br>
运行指令后进入web页面，在进入CTU-13或者是DOH模块时，其执行的顺序应该是：<br>
1. 数据展示
2. 相关性分析
3. Boruta特征选择
4. 特征轻量化

为了更好演示，本项目在代码中设置了缓存，其缓存时限设置了永久，可按需修改。<br>
注意整个web项目的实现逻辑是：上传的pcap流量包保存在uploads文件夹下，在页面上选择要解析的pcap文件，所得到的解析结果保存在logs文件夹下，所以在读取数据时，需要根据logs文件夹下的文件路径来读取数据。<br>
本项目由于时间原因，直接把解析后的数据保存在data文件夹下，所以在读取数据时，使用的是data文件夹下的文件路径来读取数据。
