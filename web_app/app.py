import numpy as np
import pandas as pd
from flask import Flask, request, render_template,redirect,url_for,flash
from flask_caching import Cache
from werkzeug.utils import secure_filename
import pickle
import os
import subprocess
import shutil
from flask import jsonify 
from flask_bootstrap import Bootstrap 
import zat
import sys
import seaborn as sns
import matplotlib.pyplot as plt
from boruta import BorutaPy
from sklearn.feature_selection import SelectKBest
from sklearn.feature_selection import chi2
from sklearn.feature_selection import mutual_info_classif
from sklearn.ensemble import RandomForestClassifier
from zat.log_to_dataframe import LogToDataFrame
from zat.dataframe_to_matrix import DataFrameToMatrix
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.metrics import precision_score
from sklearn.metrics import f1_score
from sklearn.metrics import roc_auc_score
from sklearn.metrics import roc_curve
from sklearn.metrics import confusion_matrix
from sklearn import metrics
from xgboost import XGBClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.svm import SVC
import time
import json
app = Flask(__name__)#初始化APP
app.secret_key = 'LRC_iu'
cache = Cache(app, config={'CACHE_TYPE': 'simple'})
bootstrap = Bootstrap(app)
 
#创建文件夹，保存上传的文件
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
#创建文件夹，保存解析后的日志文件
SAVE_FOLDER = 'logs'
if not os.path.exists(SAVE_FOLDER):
    os.makedirs(SAVE_FOLDER)
app.config['SAVE_FOLDER'] = SAVE_FOLDER
#限制上传文件大小为40GB
app.config['MAX_CONTENT_LENGTH'] = 40 * 1024 * 1024 * 1024
app.config['UPLOAD_EXTENSIONS'] = ['pcap', 'pcapng','log'] 


@app.route("/")
def home():
    files = os.listdir(app.config['UPLOAD_FOLDER']) #获取文件夹下的文件列表
    return render_template("index.html")

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        # 判断文件是否符合要求
        if f.filename == '':
            flash('No selected file')
            return redirect(request.url)
            #return render_template('upload_index.html')
        if f.filename.split('.')[-1] not in app.config['UPLOAD_EXTENSIONS']: 
            flash('Invalid file type')
            return redirect(request.url)
            #return render_template('upload_index.html')
        # 保存文件
        filename = secure_filename(f.filename)
        if os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], filename)):
            flash('File already exists')
            return redirect(request.url)
            #return render_template('upload_index.html')
        else:
            f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            flash('file uploaded successfully')
    return render_template('upload.html')

@app.route('/Parse', methods=['GET', 'POST'])
def parse_file():
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    if request.method == 'POST':
        file_name = request.form.get('file_name') #获取文件名
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_name) #获取文件路径

        #获取文件名
        base_name = os.path.splitext(file_name)[0]
        #创建子目录
        output_dir = os.path.join(app.config['SAVE_FOLDER'], base_name)
        os.makedirs(output_dir, exist_ok=True)

        if not os.path.exists(file_path):
            return 'File does not exist'
        # 在Ubuntu终端使用命令“zeek flowmeter -C -r target pcap path -p save log path”解析上传文件夹里的pcap流量包
        process=subprocess.Popen("zeek flowmeter -C -r "+file_path, shell=True)
        
        #等待子进程完成
        process.wait()

        # 获取app.py所在的目录
        app_dir = os.path.dirname(os.path.abspath(__file__))
        #移动生成的日志文件到output_dir
        for log_file in os.listdir(app_dir):
            if log_file.endswith('.log'):
                if os.path.exists(os.path.join(output_dir, log_file)):
                    os.remove(os.path.join(output_dir, log_file))
                shutil.move(os.path.join(app_dir, log_file), output_dir)
        
    return render_template("parse.html",files=files)

@app.route('/api/files/', defaults={'path': ''})
@app.route('/api/files/<path:path>') 
def list_files_api(path):
    full_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'logs', path)  
    subdirs = [d for d in os.listdir(full_path) if os.path.isdir(os.path.join(full_path, d))]
    files = [f for f in os.listdir(full_path) if os.path.isfile(os.path.join(full_path, f))]
    return jsonify({'path': path, 'directories': subdirs, 'files': files})

@app.route('/files_list')
def files_list():
    return render_template('files.html')


@app.route('/show_data_CTU-13', methods=['GET', 'POST'])
@cache.cached(timeout=0)
def data_ctu13_show():
    sys.path.append('./model')  
    from model.load_data_ctu13 import normal1,normal2,normal3,Bunitu,Cobalt
    from model.load_data_ctu13 import Dridex,Tickbot,TRasftuby,Trojan_Yakes,Vawtrak
    #计算数据集的大小
    normal1_size = normal1.shape[0]
    normal2_size = normal2.shape[0]
    normal3_size = normal3.shape[0]
    benign_size = normal1_size + normal2_size + normal3_size
    Bunitu_size = Bunitu.shape[0]
    Cobalt_size = Cobalt.shape[0]
    Dridex_size = Dridex.shape[0]
    Tickbot_size = Tickbot.shape[0]
    TRasftuby_size = TRasftuby.shape[0]
    Trojan_Yakes_size = Trojan_Yakes.shape[0]
    Vawtrak_size = Vawtrak.shape[0]
    Data = {
        "Benign": benign_size,
        "Bunitu": Bunitu_size,
        "Cobalt": Cobalt_size,
        "Dridex": Dridex_size,
        "Tickbot": Tickbot_size,
        "TRasftuby": TRasftuby_size,
        "Trojan_Yakes": Trojan_Yakes_size,
        "Vawtrak": Vawtrak_size,
    }
    return render_template('show_data_ctu-13.html', data=Data)


@app.route('/corr_analysis_CTU-13', methods=['GET', 'POST'])
@cache.cached(timeout=0)
def corr_analysis_ctu13():
    #读取文件
    corr_features = pd.read_csv('./ctu13_corr_features.csv')
    corr_X = np.load('ctu13_corr_X.npy')
    y = np.load('ctu13_y.npy')
    #绘制热力图
    plt.figure(figsize=(20, 20))
    sns.heatmap(corr_features.corr(), annot=True, cmap='coolwarm', fmt=".2f")
    plt.savefig('./static/imgs/ctu13_corr_heatmap.png')
    features = corr_features.columns
    return render_template('corr_analyze_ctu-13.html', features=features)

to_matrix = zat.dataframe_to_matrix.DataFrameToMatrix()
rf = RandomForestClassifier(n_estimators=100, oob_score=True)
xgb = XGBClassifier(eval_metric=['logloss','auc','error'],max_depth=12,n_jobs=-1)
gnb = GaussianNB()
svc = SVC()
models = [rf, xgb, gnb,svc]
accuracies1 = [0, 0, 0,0] # 准确率
precision_score1 = [0, 0, 0,0] # 精确率
f1_score1 = [0, 0, 0,0] # F1值
auc_score1 = [0, 0, 0,0] # AUC值
TPR1 = [0, 0, 0,0] # 真正率
FPR1 = [0, 0, 0,0] # 假正率
run_time1 = [0,0,0,0]
best_model_index = -1 # 保存Topsis最佳模型的索引

@app.route('/Boruta_ML_CTU-13', methods=['GET', 'POST'])
@cache.cached(timeout=0)
def boruta_ctu13():
    #读取文件
    corr_features = pd.read_csv('./ctu13_corr_features.csv')
    corr_X = np.load('ctu13_corr_X.npy')
    y = np.load('ctu13_y.npy')
    # Boruta算法
    model_rf = RandomForestClassifier(n_jobs=-1, class_weight='balanced', max_depth=5)
    boruta_selector = BorutaPy(model_rf, n_estimators= 'auto', verbose=2,random_state=1, max_iter = 100)
    boruta_selector.fit(corr_X, y)
    boruta_selected_features = corr_features.columns[boruta_selector.support_].tolist()
    # 依据Boruta算法选择的特征，重新构建数据集
    boruta_features = corr_features.loc[:, boruta_selected_features]
    boruta_features.to_csv('./ctu13_boruta_features.csv',index=False)
    boruta_X = to_matrix.fit_transform(boruta_features)
    np.save('ctu13_boruta_X.npy', boruta_X)
    # 进行模型训练,使用准确率、精确率、F1值、auc_score、TPR、FPR进行评估
    for i, model in enumerate(models):
        start = time.time()
        model.fit(boruta_X, y)
        y_pred = model.predict(boruta_X)
        end = time.time()
        run_time1[i] = end - start
        accuracies1[i] = accuracy_score(y, y_pred)
        precision_score1[i] = metrics.precision_score(y, y_pred)
        f1_score1[i] = metrics.f1_score(y, y_pred)
        auc_score1[i] = metrics.roc_auc_score(y, y_pred)
        fpr, tpr, thresholds = metrics.roc_curve(y, y_pred)
        TPR1[i] = tpr[1]
        FPR1[i] = fpr[1]
    # 保存模型评估结果
    data = [accuracies1, precision_score1, f1_score1, auc_score1, TPR1, FPR1,run_time1]
    data = np.array(data).T
    model_result = pd.DataFrame(data, columns=['accuracy', 'precision', 'f1', 'auc', 'TPR', 'FPR','run_time'], 
                                index=['RF', 'XGB', 'GNB', 'SVC'])

    # 保存model_result
    model_result.to_csv('./ctu13_boruta_model_result.csv')

    model_performance = [
        {"model": "RF", "accuracy": accuracies1[0], "precision": precision_score1[0], "f1": f1_score1[0], "auc": auc_score1[0], "TPR": TPR1[0], "FPR": FPR1[0], "run_time": run_time1[0]},
        {"model": "XGB", "accuracy": accuracies1[1], "precision": precision_score1[1], "f1": f1_score1[1], "auc": auc_score1[1], "TPR": TPR1[1], "FPR": FPR1[1], "run_time": run_time1[1]},
        {"model": "GNB", "accuracy": accuracies1[2], "precision": precision_score1[2], "f1": f1_score1[2], "auc": auc_score1[2], "TPR": TPR1[2], "FPR": FPR1[2], "run_time": run_time1[2]},
        {"model": "SVC", "accuracy": accuracies1[3], "precision": precision_score1[3], "f1": f1_score1[3], "auc": auc_score1[3], "TPR": TPR1[3], "FPR": FPR1[3], "run_time": run_time1[3]}
    ]

    top_two = model_result['precision'].nlargest(2)
    best_two_model = top_two.index.tolist()
    model_result_json = json.dumps(model_performance)
    return render_template('boruta_ML_ctu-13.html', model_result=model_result_json, features=boruta_selected_features,best_two_model=best_two_model)


@app.route('/feature_lighting_CTU-13', methods=['GET', 'POST'])
@cache.cached(timeout=0)
def feature_lighting_ctu13():
    model_result = pd.read_csv('./ctu13_boruta_model_result.csv')
    boruta_features = pd.read_csv('./ctu13_boruta_features.csv')
    boruta_X = np.load('ctu13_boruta_X.npy')
    y = np.load('ctu13_y.npy')
    #从model_result中的precision列中找到最大值和第二大值对应的索引
    #保存索引值到first_model_select中
    top_two = model_result['precision'].nlargest(2)
    first_model_select = top_two.index
    top1_precision = top_two.values[0]
    top2_precision = top_two.values[1]
    # 保存MI所选出来的特征在boruta_features中的数字索引
    mi_select = []
    # 保存Chi2所选出来的特征在boruta_features中的数字索引
    chi2_select = []
    stl_accuracy = accuracies1.copy()
    stl_precision = precision_score1.copy()
    stl_f1 = f1_score1.copy()
    stl_auc = auc_score1.copy()
    stl_TPR = TPR1.copy()
    stl_FPR = FPR1.copy()
    stl_run_time = run_time1.copy()
    def mi_feature_select(num):
        selector = SelectKBest(mutual_info_classif, k=num).fit(boruta_X, y)

        # 获取所选择的特征的索引
        mi_index = selector.get_support(indices=True)
        mi_select.append(mi_index)
        print(mi_index)
        mi_feature_name = boruta_features.columns[mi_index]
        print(mi_feature_name)
        X_mi = selector.transform(boruta_X)
        return X_mi
    
    def chi2_feature_select(num):
        selector = SelectKBest(chi2, k=num).fit(boruta_X, y)

        # 获取所选择的特征的索引
        chi2_index = selector.get_support(indices = True)
        chi2_select.append(chi2_index)
        print(chi2_index)
        chi2_feature_name = boruta_features.columns[chi2_index]
        print(chi2_feature_name)
        X_chi2 = selector.transform(boruta_X)
        return X_chi2

    # 获取boruta_features的特征数
    feature_num = boruta_features.shape[1]
    NUM = feature_num
    # 从feature_num-1开始循环，使用MI和Chi2特征选择器进行特征选择并堆叠，
    #训练模型，计算准确率、精确率、F1值、AUC值、TPR、FPR
    #使用top1_precision和top2_precision作为参考值，当其对应的模型的precision分别小于这两个值的95%时，停止循环；或者当feature_num小于1时，停止循环
    #使用top1_precision和top2_precision作为参考值，若其对应的模型的precision分别大于等于这两个值的95%时，更新model_result
    feature_num = feature_num - 1
    X_union = boruta_features
    while feature_num > 0:
        mi_X = mi_feature_select(feature_num)
        chi2_X = chi2_feature_select(feature_num)
        # 特征堆叠融合
        mi_select_x = boruta_features.iloc[:, np.concatenate(mi_select)] 
        print(mi_select_x)
        chi2_select_x = boruta_features.iloc[:, np.concatenate(chi2_select)]
        print(chi2_select_x)
        # 取两个特征选择器的并集
        union_select = np.union1d(mi_select_x.columns, chi2_select_x.columns)
        # 使用并集特征选择器进行特征选择
        X_union = boruta_features[union_select]
        print(X_union.shape)
        print(X_union)
        # 计算X_union的特征数
        if X_union.shape[1] == NUM:
            continue
        # 将mi_select和chi2_select的值清零
        mi_select = []
        chi2_select = []
        # 融合后的数据进行标准化
        merged_features = to_matrix.fit_transform(X_union)
        for i, model in enumerate(models):
            start = time.time()
            model.fit(merged_features, y)
            y_pred = model.predict(merged_features)
            end = time.time()
            run_time1[i] = end - start
            accuracies1[i] = accuracy_score(y, y_pred)
            precision_score1[i] = metrics.precision_score(y, y_pred)
            f1_score1[i] = metrics.f1_score(y, y_pred)
            auc_score1[i] = metrics.roc_auc_score(y, y_pred)
            fpr, tpr, thresholds = metrics.roc_curve(y, y_pred)
            TPR1[i] = tpr[1]
            FPR1[i] = fpr[1]
        # 与top1_precision和top2_precision进行比较
        # 若其对应的模型的precision分别大于等于这两个值的95%时，更新model_result
        if precision_score1[first_model_select[0]] >= top1_precision * 0.95 and precision_score1[first_model_select[1]] >= top2_precision * 0.95:
            data = [accuracies1, precision_score1, f1_score1, auc_score1, TPR1, FPR1,run_time1]
            data = np.array(data).T
            model_result = pd.DataFrame(data, columns=['accuracy', 'precision', 'f1', 'auc', 'TPR', 'FPR','run_time'], 
                                        index=['RF', 'XGB', 'GNB', 'SVC'])
            feature_num = feature_num - 1
            # 更新stl_accuracy, stl_precision, stl_f1, stl_auc, stl_TPR, stl_FPR, stl_run_time
            stl_accuracy = accuracies1.copy()
            stl_precision = precision_score1.copy()
            stl_f1 = f1_score1.copy()
            stl_auc = auc_score1.copy()
            stl_TPR = TPR1.copy()
            stl_FPR = FPR1.copy()
            stl_run_time = run_time1.copy()
        
        else:
            break
        
    
    model_performance = [
        {"model": "RF", "accuracy": stl_accuracy[0], "precision": stl_precision[0], "f1": stl_f1[0], "auc": stl_auc[0], "TPR": stl_TPR[0], "FPR": stl_FPR[0], "run_time": stl_run_time[0]},
        {"model": "XGB", "accuracy": stl_accuracy[1], "precision": stl_precision[1], "f1": stl_f1[1], "auc": stl_auc[1], "TPR": stl_TPR[1], "FPR": stl_FPR[1], "run_time": stl_run_time[1]},
        {"model": "GNB", "accuracy": stl_accuracy[2], "precision": stl_precision[2], "f1": stl_f1[2], "auc": stl_auc[2], "TPR": stl_TPR[2], "FPR": stl_FPR[2], "run_time": stl_run_time[2]},
        {"model": "SVC", "accuracy": stl_accuracy[3], "precision": stl_precision[3], "f1": stl_f1[3], "auc": stl_auc[3], "TPR": stl_TPR[3], "FPR": stl_FPR[3], "run_time": stl_run_time[3]}

    ]
    model_result_json = json.dumps(model_performance)
    # 获取X_union的特征名以及特征数
    features = X_union.columns.tolist()
    return render_template('feature_LT_ctu-13.html', model_result=model_result_json,
                           features=features)


#-----------------------------DOH数据集分析(逻辑同CTU-13，只是数据集发生了变化)--------------------------------
@app.route('/show_data_DOH', methods=['GET', 'POST'])
@cache.cached(timeout=0)
def data_doh_show():
    sys.path.append('./model')  
    from model.load_data_doh import Google,Cloudflare,dns2tcp1,dns2tcp2,dns2tcp3,dns2tcp4,dnscat2_1,dnscat2_2,iodine1,iodine2
    #计算数据集的大小
    Google_size = Google.shape[0]
    Cloudflare_size = Cloudflare.shape[0]
    dns2tcp1_size = dns2tcp1.shape[0]
    dns2tcp2_size = dns2tcp2.shape[0]
    dns2tcp3_size = dns2tcp3.shape[0]
    dns2tcp4_size = dns2tcp4.shape[0]
    dnscat2_1_size = dnscat2_1.shape[0]
    dnscat2_2_size = dnscat2_2.shape[0]
    iodine1_size = iodine1.shape[0]
    iodine2_size = iodine2.shape[0]
    benign_size = Google_size + Cloudflare_size
    dns2tcp_size = dns2tcp1_size + dns2tcp2_size + dns2tcp3_size + dns2tcp4_size
    dnscat2_size = dnscat2_1_size + dnscat2_2_size
    iodine_size = iodine1_size + iodine2_size
    Data = {
        "Benign": benign_size,
        "dns2tcp": dns2tcp_size,
        "dnscat2": dnscat2_size,
        "iodine": iodine_size,
    }
    return render_template('show_data_doh.html', data=Data)

@app.route('/corr_analysis_DOH', methods=['GET', 'POST'])
@cache.cached(timeout=0)
def corr_analysis_doh():
    corr_features = pd.read_csv('./doh_corr_features.csv')
    corr_X = np.load('doh_corr_X.npy')
    y = np.load('doh_y.npy')
    #绘制热力图
    plt.figure(figsize=(20, 20))
    sns.heatmap(corr_features.corr(), annot=True, cmap='coolwarm', fmt=".2f")
    plt.savefig('./static/imgs/doh_corr_heatmap.png')
    features = corr_features.columns
    return render_template('corr_analyze_doh.html', features=features)

accuracies2 = [0, 0, 0,0] # 准确率
precision_score2 = [0, 0, 0,0] # 精确率
f1_score2 = [0, 0, 0,0] # F1值
auc_score2 = [0, 0, 0,0] # AUC值
TPR2 = [0, 0, 0,0] # 真正率
FPR2 = [0, 0, 0,0] # 假正率
run_time2 = [0,0,0,0]

@app.route('/Boruta_ML_DOH', methods=['GET', 'POST'])
@cache.cached(timeout=0)
def boruta_doh():
    corr_features = pd.read_csv('./doh_corr_features.csv')
    corr_X = np.load('doh_corr_X.npy')
    y = np.load('doh_y.npy')
    # Boruta算法
    model_rf = RandomForestClassifier(n_jobs=-1, class_weight='balanced', max_depth=5)
    boruta_selector = BorutaPy(model_rf, n_estimators= 'auto', verbose=2,random_state=1, max_iter = 100)
    boruta_selector.fit(corr_X, y)
    boruta_selected_features = corr_features.columns[boruta_selector.support_].tolist()
    # 依据Boruta算法选择的特征，重新构建数据集
    boruta_features = corr_features.loc[:, boruta_selected_features]
    boruta_features.to_csv('./doh_boruta_features.csv',index=False)
    boruta_X = to_matrix.fit_transform(boruta_features)
    np.save('doh_boruta_X.npy', boruta_X)
    # 进行模型训练,使用准确率、精确率、F1值、auc_score、TPR、FPR进行评估
    for i, model in enumerate(models):
        start = time.time()
        model.fit(boruta_X, y)
        y_pred = model.predict(boruta_X)
        end = time.time()
        run_time2[i] = end - start
        accuracies2[i] = accuracy_score(y, y_pred)
        precision_score2[i] = metrics.precision_score(y, y_pred)
        f1_score2[i] = metrics.f1_score(y, y_pred)
        auc_score2[i] = metrics.roc_auc_score(y, y_pred)
        fpr, tpr, thresholds = metrics.roc_curve(y, y_pred)
        TPR2[i] = tpr[1]
        FPR2[i] = fpr[1]
    # 保存模型评估结果
    data = [accuracies2, precision_score2, f1_score2, auc_score2, TPR2, FPR2,run_time2]
    data = np.array(data).T
    model_result = pd.DataFrame(data, columns=['accuracy', 'precision', 'f1', 'auc', 'TPR', 'FPR','run_time'], 
                                index=['RF', 'XGB', 'GNB', 'SVC'])

    # 保存model_result
    model_result.to_csv('./doh_boruta_model_result.csv')

    model_performance = [
        {"model": "RF", "accuracy": accuracies2[0], "precision": precision_score2[0], "f1": f1_score2[0], "auc": auc_score2[0], "TPR": TPR2[0], "FPR": FPR2[0], "run_time": run_time2[0]},
        {"model": "XGB", "accuracy": accuracies2[1], "precision": precision_score2[1], "f1": f1_score2[1], "auc": auc_score2[1], "TPR": TPR2[1], "FPR": FPR2[1], "run_time": run_time2[1]},
        {"model": "GNB", "accuracy": accuracies2[2], "precision": precision_score2[2], "f1": f1_score2[2], "auc": auc_score2[2], "TPR": TPR2[2], "FPR": FPR2[2], "run_time": run_time2[2]},
        {"model": "SVC", "accuracy": accuracies2[3], "precision": precision_score2[3], "f1": f1_score2[3], "auc": auc_score2[3], "TPR": TPR2[3], "FPR": FPR2[3], "run_time": run_time2[3]}
    ]

    top_two = model_result['precision'].nlargest(2)
    best_two_model = top_two.index.tolist()
    model_result_json = json.dumps(model_performance)
    return render_template('boruta_ML_doh.html', model_result=model_result_json, features=boruta_selected_features,best_two_model=best_two_model)

@app.route('/feature_lighting_DOH', methods=['GET', 'POST'])
@cache.cached(timeout=0)
def feature_lighting_doh():
    #读取数据
    model_result = pd.read_csv('./doh_boruta_model_result.csv')
    boruta_features = pd.read_csv('./doh_boruta_features.csv')
    boruta_X = np.load('doh_boruta_X.npy')
    y = np.load('doh_y.npy')
    top_two = model_result['precision'].nlargest(2)
    first_model_select = top_two.index
    top1_precision = top_two.values[0]
    top2_precision = top_two.values[1]
    mi_select = []
    chi2_select = []
    stl_accuracy = accuracies2.copy()
    stl_precision = precision_score2.copy()
    stl_f1 = f1_score2.copy()
    stl_auc = auc_score2.copy()
    stl_TPR = TPR2.copy()
    stl_FPR = FPR2.copy()
    stl_run_time = run_time2.copy()
    def mi_feature_select(num):
        selector = SelectKBest(mutual_info_classif, k=num).fit(boruta_X, y)

        # 获取所选择的特征的索引
        mi_index = selector.get_support(indices=True)
        mi_select.append(mi_index)
        print(mi_index)
        mi_feature_name = boruta_features.columns[mi_index]
        print(mi_feature_name)
        X_mi = selector.transform(boruta_X)
        return X_mi
    
    def chi2_feature_select(num):
        selector = SelectKBest(chi2, k=num).fit(boruta_X, y)

        # 获取所选择的特征的索引
        chi2_index = selector.get_support(indices = True)
        chi2_select.append(chi2_index)
        print(chi2_index)
        chi2_feature_name = boruta_features.columns[chi2_index]
        print(chi2_feature_name)
        X_chi2 = selector.transform(boruta_X)
        return X_chi2

    # 获取boruta_features的特征数
    feature_num = boruta_features.shape[1]
    NUM = feature_num
    feature_num = feature_num - 1
    X_union = boruta_features
    while feature_num > 0:
        mi_X = mi_feature_select(feature_num)
        chi2_X = chi2_feature_select(feature_num)
        mi_select_x = boruta_features.iloc[:, np.concatenate(mi_select)] 
        print(mi_select_x)
        chi2_select_x = boruta_features.iloc[:, np.concatenate(chi2_select)]
        print(chi2_select_x)
        union_select = np.union1d(mi_select_x.columns, chi2_select_x.columns)
        X_union = boruta_features[union_select]
        print(X_union.shape)
        print(X_union)
        if X_union.shape[1] == NUM:
            continue
        mi_select = []
        chi2_select = []
        # 融合后的数据进行标准化
        merged_features = to_matrix.fit_transform(X_union)
        for i, model in enumerate(models):
            start = time.time()
            model.fit(merged_features, y)
            y_pred = model.predict(merged_features)
            end = time.time()
            run_time2[i] = end - start
            accuracies2[i] = accuracy_score(y, y_pred)
            precision_score2[i] = metrics.precision_score(y, y_pred)
            f1_score2[i] = metrics.f1_score(y, y_pred)
            auc_score2[i] = metrics.roc_auc_score(y, y_pred)
            fpr, tpr, thresholds = metrics.roc_curve(y, y_pred)
            TPR2[i] = tpr[1]
            FPR2[i] = fpr[1]
        if precision_score2[first_model_select[0]] >= top1_precision * 0.95 and precision_score2[first_model_select[1]] >= top2_precision * 0.95:
            data = [accuracies2, precision_score2, f1_score2, auc_score2, TPR2, FPR2,run_time2]
            data = np.array(data).T
            model_result = pd.DataFrame(data, columns=['accuracy', 'precision', 'f1', 'auc', 'TPR', 'FPR','run_time'], 
                                        index=['RF', 'XGB', 'GNB', 'SVC'])
            feature_num = feature_num - 1
            stl_accuracy = accuracies2.copy()
            stl_precision = precision_score2.copy()
            stl_f1 = f1_score2.copy()
            stl_auc = auc_score2.copy()
            stl_TPR = TPR2.copy()
            stl_FPR = FPR2.copy()
            stl_run_time = run_time2.copy()
        
        else:
            break
        
    model_performance = [
        {"model": "RF", "accuracy": stl_accuracy[0], "precision": stl_precision[0], "f1": stl_f1[0], "auc": stl_auc[0], "TPR": stl_TPR[0], "FPR": stl_FPR[0], "run_time": stl_run_time[0]},
        {"model": "XGB", "accuracy": stl_accuracy[1], "precision": stl_precision[1], "f1": stl_f1[1], "auc": stl_auc[1], "TPR": stl_TPR[1], "FPR": stl_FPR[1], "run_time": stl_run_time[1]},
        {"model": "GNB", "accuracy": stl_accuracy[2], "precision": stl_precision[2], "f1": stl_f1[2], "auc": stl_auc[2], "TPR": stl_TPR[2], "FPR": stl_FPR[2], "run_time": stl_run_time[2]},
        {"model": "SVC", "accuracy": stl_accuracy[3], "precision": stl_precision[3], "f1": stl_f1[3], "auc": stl_auc[3], "TPR": stl_TPR[3], "FPR": stl_FPR[3], "run_time": stl_run_time[3]}

    ]
    model_result_json = json.dumps(model_performance)
    features = X_union.columns.tolist()
    return render_template('feature_LT_doh.html', model_result=model_result_json,
                           features=features)


#-------------------祝语part-------------------
@app.route("/teacher", methods=['GET', 'POST'])
def teacher():
    return render_template('teacher.html')

@app.route("/student", methods=['GET', 'POST'])
def student():
    return render_template('student.html')


@app.route("/predict", methods=["POST"])
def predict():
    pass
    
 
if __name__ == "__main__":
    app.run(debug=True)#调试模式下运行文件，实时反应结果。仅限测试使用，生产模式下不要使用
    #app.run() #默认运行在5000端口——http://127.0.0.1:5000 app.run(port=自定义端口)
