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
    #Google
# 获取当前脚本的绝对路径
script_dir = os.path.dirname(os.path.abspath(__file__))
# 计算文件的绝对路径
path1 = os.path.join(script_dir, "../data/CIC-IDS/Benign_log/Google/conn.log")
path2 = os.path.join(script_dir, "../data/CIC-IDS/Benign_log/Google/ssl.log")
path3 = os.path.join(script_dir, "../data/CIC-IDS/Benign_log/Google/flowmeter.log")

#进行数据选择
Google = data_select(path1,path2,path3)
print(Google.shape)

    #Cloudflare
path1 = os.path.join(script_dir, "../data/CIC-IDS/Benign_log/Cloudflare/conn.log")
path2 = os.path.join(script_dir, "../data/CIC-IDS/Benign_log/Cloudflare/ssl.log")
path3 = os.path.join(script_dir, "../data/CIC-IDS/Benign_log/Cloudflare/flowmeter.log")


#进行数据选择
Cloudflare = data_select(path1,path2,path3)
print(Cloudflare.shape)

# Malicious
    #dns2tcp1
path1 = os.path.join(script_dir, "../data/CIC-IDS/Malicious_log/dns2tcp/merge/conn.log")
path2 = os.path.join(script_dir, "../data/CIC-IDS/Malicious_log/dns2tcp/merge/ssl.log")
path3 = os.path.join(script_dir, "../data/CIC-IDS/Malicious_log/dns2tcp/merge/flowmeter.log")

#进行数据选择
dns2tcp1 = data_select(path1,path2,path3)
print(dns2tcp1.shape)


    #dns2tcp2
path1 = os.path.join(script_dir, "../data/CIC-IDS/Malicious_log/dns2tcp/merge1201/conn.log")
path2 = os.path.join(script_dir, "../data/CIC-IDS/Malicious_log/dns2tcp/merge1201/ssl.log")
path3 = os.path.join(script_dir, "../data/CIC-IDS/Malicious_log/dns2tcp/merge1201/flowmeter.log")

#进行数据选择
dns2tcp2 = data_select(path1,path2,path3)
dns2tcp2 = dns2tcp2.iloc[:47596,:]
print(dns2tcp2.shape)

    #dns2tcp3
path1 = os.path.join(script_dir, "../data/CIC-IDS/Malicious_log/dns2tcp/merge1802/conn.log")
path2 = os.path.join(script_dir, "../data/CIC-IDS/Malicious_log/dns2tcp/merge1802/ssl.log")
path3 = os.path.join(script_dir, "../data/CIC-IDS/Malicious_log/dns2tcp/merge1802/flowmeter.log")

#进行数据选择
dns2tcp3 = data_select(path1,path2,path3)
print(dns2tcp3.shape)

    #dns2tcp4
path1 = os.path.join(script_dir, "../data/CIC-IDS/Malicious_log/dns2tcp/merge2402/conn.log")
path2 = os.path.join(script_dir, "../data/CIC-IDS/Malicious_log/dns2tcp/merge2402/ssl.log")
path3 = os.path.join(script_dir, "../data/CIC-IDS/Malicious_log/dns2tcp/merge2402/flowmeter.log")
#进行数据选择
dns2tcp4 = data_select(path1,path2,path3)
print(dns2tcp4.shape)

    #dnscat2_1
path1 = os.path.join(script_dir, "../data/CIC-IDS/Malicious_log/dnscat2/dnscat2_1201/conn.log")
path2 = os.path.join(script_dir, "../data/CIC-IDS/Malicious_log/dnscat2/dnscat2_1201/ssl.log")
path3 = os.path.join(script_dir, "../data/CIC-IDS/Malicious_log/dnscat2/dnscat2_1201/flowmeter.log")


#进行数据选择
dnscat2_1 = data_select(path1,path2,path3)
print(dnscat2_1.shape)

    #dnscat2_2
path1 = os.path.join(script_dir, "../data/CIC-IDS/Malicious_log/dnscat2/dnscat2_1802/conn.log")
path2 = os.path.join(script_dir, "../data/CIC-IDS/Malicious_log/dnscat2/dnscat2_1802/ssl.log")
path3 = os.path.join(script_dir, "../data/CIC-IDS/Malicious_log/dnscat2/dnscat2_1802/flowmeter.log")

#进行数据选择
dnscat2_2 = data_select(path1,path2,path3)
print(dnscat2_2.shape)

    #iodine1
path1 = os.path.join(script_dir, "../data/CIC-IDS/Malicious_log/iodine/iodine_1201/conn.log")
path2 = os.path.join(script_dir, "../data/CIC-IDS/Malicious_log/iodine/iodine_1201/ssl.log")
path3 = os.path.join(script_dir, "../data/CIC-IDS/Malicious_log/iodine/iodine_1201/flowmeter.log")

#进行数据选择
iodine1 = data_select(path1,path2,path3)
print(iodine1.shape)

    #iodine2
path1 = os.path.join(script_dir, "../data/CIC-IDS/Malicious_log/iodine/iodine_1802/conn.log")
path2 = os.path.join(script_dir, "../data/CIC-IDS/Malicious_log/iodine/iodine_1802/ssl.log")
path3 = os.path.join(script_dir, "../data/CIC-IDS/Malicious_log/iodine/iodine_1802/flowmeter.log")
#进行数据选择
iodine2 = data_select(path1,path2,path3)
print(iodine2.shape)



# 数据合并
Benign = pd.concat([Google,Cloudflare],axis=0) # 合并所有正常样本
Malicious = pd.concat([dns2tcp1,dns2tcp2,dns2tcp3,dns2tcp4,dnscat2_1,dnscat2_2,iodine1,iodine2],axis = 0)
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
corr_features.to_csv('doh_corr_features.csv', index=False)

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
np.save('doh_corr_X.npy', corr_X)
np.save('doh_y.npy', y)
