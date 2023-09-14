import tensorflow as tf
from tensorflow import keras 
import numpy as np 
from tensorflow.keras import layers
import pandas as pd 
from sklearn.model_selection import train_test_split
from tensorflow.keras.callbacks import EarlyStopping
from tensorflow.keras.models import Sequential
from tensorflow.keras.losses import categorical_crossentropy
from sklearn.preprocessing import MinMaxScaler
from kafka import KafkaProducer
from kafka import KafkaConsumer
from matplotlib import pyplot as plt
import sklearn.metrics 
from sklearn.metrics import accuracy_score

df1=pd.read_csv('C:/Users/.spyder-py3/ddos.csv')
df2=pd.read_csv('C:/Users/.spyder-py3/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv')
df3=pd.read_csv('C:/Users/.spyder-py3/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv')
concatened=pd.concat([df1,df2,df3])

concatened_1=pd.get_dummies(concatened)


#inversion de la base selon le besoin 
X=concatened_1[[' Destination Port', ' Flow Duration', 'Flow Bytes/s',
       ' Flow Packets/s', 'Fwd Packets/s', ' Bwd Packets/s',
       ' Total Fwd Packets', ' Total Backward Packets',
       'Total Length of Fwd Packets', ' Total Length of Bwd Packets',
       ' Fwd Packet Length Max', ' Fwd Packet Length Min',
       ' Fwd Packet Length Mean', ' Bwd Packet Length Std',
       ' Bwd Packet Length Mean', ' Bwd Packet Length Min',
       'Bwd Packet Length Max', ' Fwd Packet Length Std', ' Max Packet Length',
       ' Min Packet Length', ' Packet Length Mean', ' Packet Length Std',
       ' Packet Length Variance', ' Fwd Header Length', 'Bwd IAT Total',
       ' min_seg_size_forward', ' act_data_pkt_fwd', ' Flow IAT Mean',
       ' Flow IAT Max', ' Flow IAT Min', 'Fwd PSH Flags', ' Bwd PSH Flags',
       ' Fwd URG Flags', ' Bwd URG Flags', ' Bwd Header Length',
       ' Bwd IAT Std', ' Flow IAT Std', ' Bwd IAT Min', ' Bwd IAT Max',
       'Fwd IAT Total', ' Fwd IAT Mean', ' Fwd IAT Std', 'FIN Flag Count',
       ' SYN Flag Count', ' RST Flag Count', ' PSH Flag Count',
       ' ACK Flag Count', ' URG Flag Count', ' CWE Flag Count',
       ' ECE Flag Count', ' Down/Up Ratio', ' Average Packet Size',
       ' Avg Fwd Segment Size', ' Avg Bwd Segment Size', ' Fwd IAT Max',
       'Fwd Avg Bytes/Bulk', ' Fwd Avg Packets/Bulk', ' Fwd Avg Bulk Rate',
       ' Bwd Avg Bytes/Bulk', ' Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
       'Subflow Fwd Packets', ' Subflow Fwd Bytes', ' Subflow Bwd Packets',
       ' Subflow Bwd Bytes', 'Init_Win_bytes_forward',
       ' Init_Win_bytes_backward', ' Bwd IAT Mean', ' Fwd IAT Min',
       'Active Mean', ' Active Std', ' Active Max', ' Active Min', 'Idle Mean',
       ' Idle Std', ' Idle Max', ' Idle Min']] 

#choix de la cible(target)
y=concatened_1[[' Label_BENIGN', ' Label_DDoS' ,' Label_PortScan' ,' Label_Web Attack � Brute Force', ' Label_Web Attack � XSS',
 ' Label_Web Attack � Sql Injection']]

#check if there is infinity values in dataset
dx= X.isin([np.inf, -np.inf])
#check if there is NaN values in dataset 
missing_values_count = concatened.isna()
#replace infinity values
X.replace([np.inf,-np.inf],inplace=True)
#drop NaN values
concatened=concatened.dropna()
from sklearn.preprocessing import MinMaxScaler
scaler = MinMaxScaler()
scaled = scaler.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(X,y,train_size=0.8,test_size=0.2, random_state=1)


model = keras.Sequential([
    layers.Dense(units=128, input_shape=[77],activation='relu'),
    layers.Dense(16, activation='relu'),
    layers.Dropout(0.4),
    layers.BatchNormalization(),
    layers.Dense(units=128,activation='relu'),
    layers.Dense(16, activation='relu'),
    layers.Dropout(0.4),
    layers.BatchNormalization(),
    layers.Dense(units=6,activation='softmax'),
])

early= EarlyStopping(
    min_delta=0.001,
    patience=20,
    restore_best_weights=True,
)


model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])

history= model.fit(
    X_train, y_train,
    validation_data=(X_test, y_test),
    batch_size=200,
    epochs=80,
    callbacks=[early],
)

# convert the training history to a dataframe
history_df = pd.DataFrame(history.history)

# use Pandas native plot method
history_df.loc[:, ['loss', 'val_loss']].plot()

y_pred=model.predict(X_test)
y_true=y_test
print('Test Accuracy = ',accuracy_score(y_test,y_pred.round()))

consumer = KafkaConsumer('cicflow',
                         group_id=None,
                         bootstrap_servers=['192.168.1.13:9092'])
#Data processing 

for message in consumer:
     a= message.value.decode("utf-8") 
     r=a.split("\r\n")   
     for l in r: 
           d=l.split(",")
           if d==['src_ip', 'dst_ip', 'src_port', 'dst_port', 'src_mac', 'dst_mac', 'protocol', 'timestamp', 'flow_duration', 'flow_byts_s', 'flow_pkts_s', 'fwd_pkts_s', 'bwd_pkts_s', 'tot_fwd_pkts', 'tot_bwd_pkts', 'totlen_fwd_pkts', 'totlen_bwd_pkts', 'fwd_pkt_len_max', 'fwd_pkt_len_min', 'fwd_pkt_len_mean', 'fwd_pkt_len_std', 'bwd_pkt_len_max', 'bwd_pkt_len_min', 'bwd_pkt_len_mean', 'bwd_pkt_len_std', 'pkt_len_max', 'pkt_len_min', 'pkt_len_mean', 'pkt_len_std', 'pkt_len_var', 'fwd_header_len', 'bwd_header_len', 'fwd_seg_size_min', 'fwd_act_data_pkts', 'flow_iat_mean', 'flow_iat_max', 'flow_iat_min', 'flow_iat_std', 'fwd_iat_tot', 'fwd_iat_max', 'fwd_iat_min', 'fwd_iat_mean', 'fwd_iat_std', 'bwd_iat_tot', 'bwd_iat_max', 'bwd_iat_min', 'bwd_iat_mean', 'bwd_iat_std', 'fwd_psh_flags', 'bwd_psh_flags', 'fwd_urg_flags', 'bwd_urg_flags', 'fin_flag_cnt', 'syn_flag_cnt', 'rst_flag_cnt', 'psh_flag_cnt', 'ack_flag_cnt', 'urg_flag_cnt', 'ece_flag_cnt', 'down_up_ratio', 'pkt_size_avg', 'init_fwd_win_byts', 'init_bwd_win_byts', 'active_max', 'active_min', 'active_mean', 'active_std', 'idle_max', 'idle_min', 'idle_mean', 'idle_std', 'fwd_byts_b_avg', 'fwd_pkts_b_avg', 'bwd_byts_b_avg', 'bwd_pkts_b_avg', 'fwd_blk_rate_avg', 'bwd_blk_rate_avg', 'fwd_seg_size_avg', 'bwd_seg_size_avg', 'cwe_flag_count', 'subflow_fwd_pkts', 'subflow_bwd_pkts', 'subflow_fwd_byts', 'subflow_bwd_byts']:
              d.pop()
           elif d==['\x00\x00\x00\x00\x00\x00']:
             d.pop()
           else:
            df=pd.DataFrame(d)
            df=df.T
            df=df.drop([0,1,2,4,5,6,7],axis=1)
            df = df.astype('float64')
            prediction=model.predict(df)
            prediction=np.argmax(prediction)
            attack={0:'benin',1:'DDos',2:'PORTSCAN',3:'BrutForce',4:'XSS',5:'SQlInjection'}
            print("alert:",attack[prediction])


