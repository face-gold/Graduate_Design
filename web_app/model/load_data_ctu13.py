# 导入所需要的包
import numpy as np
import pandas as pd
import zat
import os
from zat.log_to_dataframe import LogToDataFrame
from zat.dataframe_to_matrix import DataFrameToMatrix
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import learning_curve
import warnings
warnings.filterwarnings("ignore")

# 将zeek提取到的日志数据读入python中
def data_select(path1,path2,path3):
    log_to_df = LogToDataFrame()
    df_conn = log_to_df.create_dataframe(path1)
    df_ssl = log_to_df.create_dataframe(path2)
    df_flow = log_to_df.create_dataframe(path3)
    print('Read in conn {:d} Rows...'.format(len(df_conn)))
    print('Read in ssl {:d} Rows...'.format(len(df_ssl)))
    print('Read in flowmeter {:d} Rows...'.format(len(df_flow)))
    
    # Feature selection
    df_conn['uid_length'] =df_conn['uid'].str.len()
    features_conn = ['uid','orig_bytes','service', 'resp_bytes','conn_state',
                      'missed_bytes','orig_pkts','orig_ip_bytes','resp_pkts','resp_ip_bytes']
    feature_df_conn = df_conn[features_conn]

    df_ssl['uid_length'] = df_ssl['uid'].str.len()
    features_ssl = ['uid','curve','resumed','established','version',
                     'cipher','subject','issuer']
    feature_df_ssl= df_ssl[features_ssl]

    df_flow['uid_length'] = df_flow['uid'].str.len()
    features_flow = ['uid','flow_duration','fwd_pkts_tot','bwd_pkts_tot','fwd_data_pkts_tot','bwd_data_pkts_tot','fwd_pkts_per_sec','bwd_pkts_per_sec','flow_pkts_per_sec',
             'down_up_ratio','fwd_header_size_tot','fwd_header_size_min','fwd_header_size_max','bwd_header_size_tot','bwd_header_size_min','bwd_header_size_max',
             'flow_FIN_flag_count','flow_SYN_flag_count','flow_RST_flag_count','fwd_PSH_flag_count','bwd_PSH_flag_count','flow_ACK_flag_count',
             'fwd_URG_flag_count','bwd_URG_flag_count','flow_CWR_flag_count','flow_ECE_flag_count',
             'fwd_pkts_payload.max','fwd_pkts_payload.min','fwd_pkts_payload.tot','fwd_pkts_payload.avg','fwd_pkts_payload.std',
             'bwd_pkts_payload.max','bwd_pkts_payload.min','bwd_pkts_payload.tot','bwd_pkts_payload.avg','bwd_pkts_payload.std',
             'flow_pkts_payload.min','flow_pkts_payload.max','flow_pkts_payload.tot','flow_pkts_payload.avg','flow_pkts_payload.std',
             'fwd_iat.min','fwd_iat.max', 'fwd_iat.tot','fwd_iat.avg','fwd_iat.std','bwd_iat.max','bwd_iat.min','bwd_iat.tot','bwd_iat.avg','bwd_iat.std',
             'flow_iat.min','flow_iat.max','flow_iat.tot','flow_iat.avg','flow_iat.std','payload_bytes_per_second','fwd_subflow_pkts','bwd_subflow_pkts','fwd_subflow_bytes','bwd_subflow_bytes',
             'fwd_bulk_bytes','bwd_bulk_bytes','fwd_bulk_packets','bwd_bulk_packets','fwd_bulk_rate','bwd_bulk_rate','active.min','active.max','active.tot','active.avg','active.std',
             'idle.min','idle.max','idle.tot','idle.avg','idle.std','fwd_init_window_size','bwd_init_window_size','fwd_last_window_size','bwd_last_window_size']
    feature_df_flow = df_flow[features_flow]
    # merge features with uid
    df_f1 =  pd.merge(feature_df_flow,feature_df_conn,how='outer',on='uid')
    df_fsm=  pd.merge(df_f1,feature_df_ssl,how='outer',on='uid')
    # only TLS flows
    df_onlytls = df_fsm.dropna(subset=['version'])
    # make sure a complete TLS connection
    df_onlytls1 = df_onlytls.query("established == 'T'")
    print(df_onlytls.shape,df_onlytls1.shape)
    return df_onlytls1

# 注意整个web项目的实现逻辑是：上传的pcap流量包保存在uploads文件夹下，在页面上选择要解析的pcap文件，
# 所得到的解析结果保存在logs文件夹下，所以在读取数据时，需要根据logs文件夹下的文件路径来读取数据
# 本项目由于时间原因，直接把解析后的数据保存在data文件夹下，所以在读取数据时，使用的是data文件夹下的文件路径来读取数据

# Benign
    #normal1
# 获取当前脚本的绝对路径
script_dir = os.path.dirname(os.path.abspath(__file__))
# 计算文件的绝对路径
path1 = os.path.join(script_dir, "../data/CTU13/Normal/capture1/conn.log")
path2 = os.path.join(script_dir, "../data/CTU13/Normal/capture1/ssl.log")
path3 = os.path.join(script_dir, "../data/CTU13/Normal/capture1/flowmeter.log")
'''
path1 =r"../data/CTU13/Normal/capture1/conn.log"
path2 = r"../data/CTU13/Normal/capture1/ssl.log"
path3 =r"../data/CTU13/Normal/capture1/flowmeter.log"
'''
#进行数据选择
normal1 = data_select(path1,path2,path3)
print("缺失值判断：",normal1.isnull().any())
print("含缺失值的行统计：",normal1.isnull().sum())
print(normal1.shape)

    #normal2
path1 = os.path.join(script_dir, "../data/CTU13/Normal/capture2/conn.log")
path2 = os.path.join(script_dir, "../data/CTU13/Normal/capture2/ssl.log")
path3 = os.path.join(script_dir, "../data/CTU13/Normal/capture2/flowmeter.log")
'''
path1 =r"../data/CTU13/Normal/capture2/conn.log"
path2 = r"../data/CTU13/Normal/capture2/ssl.log"
path3 =r"../data/CTU13/Normal/capture2/flowmeter.log"
'''

#进行数据选择
normal2 = data_select(path1,path2,path3)
print("缺失值判断：",normal2.isnull().any())
print("含缺失值的行统计：",normal2.isnull().sum())
print(normal2.shape)

    #normal3
path1 = os.path.join(script_dir, "../data/CTU13/Normal/capture3/conn.log")
path2 = os.path.join(script_dir, "../data/CTU13/Normal/capture3/ssl.log")
path3 = os.path.join(script_dir, "../data/CTU13/Normal/capture3/flowmeter.log")
'''
path1 =r"../data/CTU13/Normal/capture3/conn.log"
path2 = r"../data/CTU13/Normal/capture3/ssl.log"
path3 =r"../data/CTU13/Normal/capture3/flowmeter.log"
'''
#进行数据选择
normal3 = data_select(path1,path2,path3)
print("缺失值判断：",normal3.isnull().any())
print("含缺失值的行统计：",normal3.isnull().sum())
print(normal3.shape)

# Malicious
    #Bunitu
path1 = os.path.join(script_dir, "../data/CTU13/Bunitu/conn.log")
path2 = os.path.join(script_dir, "../data/CTU13/Bunitu/ssl.log")
path3 = os.path.join(script_dir, "../data/CTU13/Bunitu/flowmeter.log")
'''
path1 =r"../data/CTU13/Bunitu/conn.log"
path2 = r"../data/CTU13/Bunitu/ssl.log"
path3 =r"../data/CTU13/Bunitu/flowmeter.log"
'''

#进行数据选择
Bunitu = data_select(path1,path2,path3)
print("缺失值判断：",Bunitu.isnull().any())
print("含缺失值的行统计：",Bunitu.isnull().sum())
print(Bunitu.shape)

    #Cobalt
path1 = os.path.join(script_dir, "../data/CTU13/Cobalt/conn.log")
path2 = os.path.join(script_dir, "../data/CTU13/Cobalt/ssl.log")
path3 = os.path.join(script_dir, "../data/CTU13/Cobalt/flowmeter.log")
'''
path1 =r"../data/CTU13/Cobalt/conn.log"
path2 = r"../data/CTU13/Cobalt/ssl.log"
path3 =r"../data/CTU13/Cobalt/flowmeter.log"
'''

#进行数据选择
Cobalt = data_select(path1,path2,path3)
print("缺失值判断：",Cobalt.isnull().any())
print("含缺失值的行统计：",Cobalt.isnull().sum())
print(Cobalt.shape) 

    #Dridex
path1 = os.path.join(script_dir, "../data/CTU13/Dridex_/conn.log")
path2 = os.path.join(script_dir, "../data/CTU13/Dridex_/ssl.log")
path3 = os.path.join(script_dir, "../data/CTU13/Dridex_/flowmeter.log")
'''
path1 =r"../data/CTU13/Dridex_/conn.log"
path2 = r"../data/CTU13/Dridex_/ssl.log"
path3 =r"../data/CTU13/Dridex_/flowmeter.log"
'''

#进行数据选择
Dridex = data_select(path1,path2,path3)
Dridex = Dridex.iloc[:6630,:]
print("缺失值判断：",Dridex.isnull().any())
print("含缺失值的行统计：",Dridex.isnull().sum())
print(Dridex.shape)

    #Tickbot
path1 = os.path.join(script_dir, "../data/CTU13/Tickbot/conn.log")
path2 = os.path.join(script_dir, "../data/CTU13/Tickbot/ssl.log")
path3 = os.path.join(script_dir, "../data/CTU13/Tickbot/flowmeter.log")
'''
path1 =r"../data/CTU13/Tickbot/conn.log"
path2 = r"../data/CTU13/Tickbot/ssl.log"
path3 =r"../data/CTU13/Tickbot/flowmeter.log"
'''

#进行数据选择
Tickbot = data_select(path1,path2,path3)
Tickbot = Tickbot.iloc[:6630,:]
print("缺失值判断：",Tickbot.isnull().any())
print("含缺失值的行判断：",Tickbot.isnull().sum())
print(Tickbot.shape)

    #TRasftuby
path1 = os.path.join(script_dir, "../data/CTU13/TRasftuby/conn.log")
path2 = os.path.join(script_dir, "../data/CTU13/TRasftuby/ssl.log")
path3 = os.path.join(script_dir, "../data/CTU13/TRasftuby/flowmeter.log")
'''
path1 =r"../data/CTU13/TRasftuby/conn.log"
path2 = r"../data/CTU13/TRasftuby/ssl.log"
path3 =r"../data/CTU13/TRasftuby/flowmeter.log"
'''

#进行数据选择
TRasftuby = data_select(path1,path2,path3)
print("缺失值判断：",TRasftuby.isnull().any())
print("含缺失值的行判断：",TRasftuby.isnull().sum())
print(TRasftuby.shape)

    #Trojan_Yakes
path1 = os.path.join(script_dir, "../data/CTU13/Trojan_Yakes/conn.log")
path2 = os.path.join(script_dir, "../data/CTU13/Trojan_Yakes/ssl.log")
path3 = os.path.join(script_dir, "../data/CTU13/Trojan_Yakes/flowmeter.log")
'''
path1 =r"../data/CTU13/Trojan_Yakes/conn.log"
path2 = r"../data/CTU13/Trojan_Yakes/ssl.log"
path3 =r"../data/CTU13/Trojan_Yakes/flowmeter.log"
'''

#进行数据选择
Trojan_Yakes = data_select(path1,path2,path3)
print("缺失值判断：",Trojan_Yakes.isnull().any())
print("含缺失值的行判断：",Trojan_Yakes.isnull().sum())
print(Trojan_Yakes.shape)

    #Vawtrak
path1 = os.path.join(script_dir, "../data/CTU13/Vawtrak/conn.log")
path2 = os.path.join(script_dir, "../data/CTU13/Vawtrak/ssl.log")
path3 = os.path.join(script_dir, "../data/CTU13/Vawtrak/flowmeter.log")
'''
path1 =r"../data/CTU13/Vawtrak/conn.log"
path2 = r"../data/CTU13/Vawtrak/ssl.log"
path3 =r"../data/CTU13/Vawtrak/flowmeter.log"
'''

#进行数据选择
Vawtrak = data_select(path1,path2,path3)
Vawtrak = Vawtrak.iloc[:6630,:]
print("缺失值判断：",Vawtrak.isnull().any())
print("含缺失值的行判断：",Vawtrak.isnull().sum())
print(Vawtrak.shape)


# 数据合并
Benign = pd.concat([normal1,normal2,normal3],axis=0) 
Malicious = pd.concat([Bunitu,Cobalt,Dridex,Tickbot,TRasftuby,Trojan_Yakes,Vawtrak],axis = 0)
df = pd.concat([Malicious,Benign],axis=0) 
print('Malware size: {:d}'.format(len(Malicious))) 
print('Benign size: {:d}'.format(len(Benign))) 
all_zero_columns = df.apply(lambda x: all(x == 0))
# 删除包含零值的所有列
df = df.drop(df.columns[all_zero_columns], axis=1)
# 将timedelta64[ns]类型的数据转换为int类型
df['flow_duration'] = df['flow_duration'].dt.total_seconds()
df = df.drop('service',axis=1)
df = df.drop('established',axis = 1)
print(df.shape)
#ob_feature = df.select_dtypes(include='object')
#print(ob_feature.shape)
new_df = df.select_dtypes(exclude='object')
print(new_df.shape)

# 创建标签
y = np.hstack((np.full((1,len(Malicious)),0),np.full((1,len(Benign)),1))).T 
y = y.ravel()
print(y.shape)


#相关性分析，阈值选择0.4
corr_matrix = new_df.corr()

redundant_features = []
for i in range(len(corr_matrix.columns)):
    for j in range(i+1, len(corr_matrix.columns)):
        if abs(corr_matrix.iloc[i, j]) >= 0.4:
            redundant_features.append(corr_matrix.columns[j])

corr_features = new_df.drop(redundant_features, axis=1)

# 保存corr_features到csv文件
corr_features.to_csv('ctu13_corr_features.csv', index=False)

print("Remaining features after removing redundancy:")
print(corr_features.columns)
print(corr_features.shape)

# 绘制热力图
plt.figure(figsize=(20, 20))
sns.heatmap(corr_features.corr(), annot=True, fmt=".2f")
plt.show()


# 标准化数据
to_matrix = zat.dataframe_to_matrix.DataFrameToMatrix()
corr_X = to_matrix.fit_transform(corr_features)
print(corr_X.shape)

# 保存数据
np.save('ctu13_corr_X.npy', corr_X)
np.save('ctu13_y.npy', y)
