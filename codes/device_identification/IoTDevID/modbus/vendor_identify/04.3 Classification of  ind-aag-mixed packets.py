import warnings
warnings.filterwarnings("ignore")

from sklearn import metrics
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.metrics import balanced_accuracy_score
from sklearn.metrics import classification_report
from sklearn.metrics import confusion_matrix
from sklearn.naive_bayes import CategoricalNB

from sklearn.tree import DecisionTreeClassifier
from sklearn.utils import shuffle
from collections import Counter
import matplotlib.pyplot as plt
import numpy as np
import os
import pandas as pd
import seaborn as sns
import sklearn
import time


# Discovering Labels
def target_name(name):
    df = pd.read_csv(name,usecols=["label_code"])
    target_names=sorted(list(df["label_code"].unique()))
    return target_names


def find_the_way(path,file_format):
    files_add = []
    # r=root, d=directories, f = files
    for r, d, f in os.walk(path):
        for file in f:
            if file_format in file:
                files_add.append(os.path.join(r, file))  
    return files_add


# Hyperparameters of machine learning algorithm.
ml_list={"NB":CategoricalNB(alpha=1e-09),
         "DT":DecisionTreeClassifier(criterion='entropy', max_depth=28, max_features=16,min_samples_split= 7),
         "RF":RandomForestClassifier(bootstrap= False, criterion= "entropy", max_depth= 29, max_features= 7, min_samples_split= 9, n_estimators= 80)}


# Aggregation Algorithm notmal
altime=0

 
def most_frequent(List):
    occurence_count = Counter(List)
    occurence_count={k: v for k, v in sorted(occurence_count.items(), key=lambda item: item[1],reverse=True)}
    big=list(occurence_count.values())
    big=big.count(big[0])
    return list(occurence_count.keys())[np.random.randint(big)]


def create_exception(df): 
    exception_list=[]
    dominant_mac=[]
    for i in df['aggregated'].unique():
        k=df[df['aggregated']==i]
        for ii in ['MAC']:
            hist = {}
            for x in k[ii].values:
                hist[x] = hist.get(x, 0) + 1
            hist=dict(sorted(hist.items(), key=lambda item: item[1],reverse=True))
            temp=next(iter(hist))
            if temp not in dominant_mac:
                dominant_mac.append(temp)
            else:
                exception_list.append(temp)
    return exception_list


def merged(m_test, predict, step, mixed):
    second=time.time()
    mac_test=[]
    for q in m_test.index:
        mac_test.append(m_test[q])

    d_list=sorted(list(m_test.unique()))
    devices={}
    for q in d_list:
        devices[q]=[]    

    new_y=[0]*len(m_test)

    for q,qq in enumerate (mac_test):
        devices[qq].append(q)
    for q in devices:
        a = [devices[q][j:j + step] for j in range(0, len(devices[q]), step)]  
        for qq in a:
            step_list=[]
            for qqq in qq:
                step_list.append(predict[qqq])
            add=most_frequent(list(step_list))
            for qqq in qq:
                new_y[qqq]=add
    results=pd.DataFrame(m_test)
    results["aggregated"]=new_y # Only aggregated results
    results["normal"]=predict
    
    #MIXED METHOD
    if mixed:
        exception=create_exception(results)
        for q in exception:
            results.loc[results.MAC == q, 'aggregated'] = results['normal']

    return results["aggregated"].values,time.time()-second


# Calculation of evaluations
def score(altime,train_time,test_time,predict,y_test,class_based_results,i,cv,dname,ii):
    precision=[]
    recall=[]
    f1=[]
    accuracy=[]
    total_time=[]
    kappa=[]
    accuracy_b=[]
    
    rc=sklearn.metrics.recall_score(y_test, predict,average= "weighted")
    pr=sklearn.metrics.precision_score(y_test, predict,average= "weighted")
    f_1=sklearn.metrics.f1_score(y_test, predict,average= "weighted")

    predict_label_set = set()
    error_count = 0
    index = 0
    for item in predict:
        if predict[index] != y_test[index]:
            error_count += 1
        # print(f"{predict[index]} : {y_test[index]}")
        predict_label_set.add(item)
        index += 1

    # print(f"error_count: {error_count} / {len(predict)}, accuracy: {(len(predict) - error_count) / len(predict)}")

    y_test_label_set = set()
    for item in y_test:
        y_test_label_set.add(item)

    # print(predict_label_set)
    # print(y_test_label_set)
    # print(target_names)
    # Use labels to match the classes with target_names
    target_names = set(np.concatenate((predict, y_test), axis=0))# Including all labels in y_test and predict
    # report = classification_report(y_test, predict, labels=target_names, target_names=target_names, output_dict=True)
    report = classification_report(y_test, predict, target_names=target_names, output_dict=True)
    cr = pd.DataFrame(report).transpose()
    if class_based_results.empty:
        class_based_results =cr
    else:
        class_based_results = class_based_results.add(cr, fill_value=0)
    precision.append(float(pr))
    recall.append(float(rc))
    f1.append(float(f_1))
    accuracy_b.append(balanced_accuracy_score( y_test,predict))
    accuracy.append(accuracy_score(y_test, predict))

    kappa.append(round(float(sklearn.metrics.cohen_kappa_score(y_test, predict, 
    labels=None, weights=None, sample_weight=None)),15))
    print ('%-15s %-3s %-3s %-6s  %-5s %-5s %-5s %-5s %-8s %-5s %-8s %-8s%-8s%-8s' % (dname,i,cv,ii[0:6],str(round(np.mean(accuracy),2)),str(round(np.mean(accuracy_b),2)),
        str(round(np.mean(precision),2)), str(round(np.mean(recall),2)),str(round(np.mean(f1),4)), 
        str(round(np.mean(kappa),2)),str(round(np.mean(train_time),2)),str(round(np.mean(test_time),2)),str(round(np.mean(test_time)+np.mean(train_time),2)),str(round(np.mean(altime),2))))
    lines=(str(dname)+","+str(i)+","+str(cv)+","+str(ii)+","+str(round(np.mean(accuracy),15))+","+str(round(np.mean(accuracy_b),15))+","+str(round(np.mean(precision),15))+","+ str(round(np.mean(recall),15))+","+str(round(np.mean(f1),15))+","+str(round(np.mean(kappa),15))+","+str(round(np.mean(train_time),15))+","+str(round(np.mean(test_time),15))+","+str(altime)+"\n")
    return lines, class_based_results, target_names


def ML(loop1, loop2, output_csv, cols, step, mixed, dname):
    ths = open(output_csv, "w")
    ths.write("Dataset,T,CV,ML algorithm,Acc,b_Acc,Precision,Recall,F1-score,kappa,tra-Time,test-Time,Al-Time\n")

    for ii in ml_list:
        print ('%-15s %-3s %-3s %-6s  %-5s %-5s %-5s %-5s %-8s %-5s %-8s %-8s%-8s%-8s'%
               ("Dataset","T","CV","ML alg","Acc","b_Acc","Prec", "Rec" , "F1", "kap" ,"tra-T","test-T","total","al-time"))
        class_based_results=pd.DataFrame()#"" #pd.DataFrame(0, index=np.arange((len(target_names)+3)), columns=["f1-score","precision","recall","support"])
        cm=pd.DataFrame()
        cv=0
        if ii in ["GB","SVM"]: #for slow algorithms.
            repetition=10 
        else:
            repetition=10

        for i in range(repetition):
            #TRAIN
            train_df = pd.read_csv(loop1,usecols=cols)

            m_train=train_df["IP_addr"]
            del train_df["IP_addr"]
            """  Convert the 'label' column to categorical dtype
            train_df['label'] = pd.Categorical(train_df['label'])
            train_df['label_code'] = train_df['label'].cat.codes """

            #TEST
            test_df = pd.read_csv(loop2,usecols=cols)
            test_df = shuffle(test_df, random_state=42)
            m_test=test_df["IP_addr"]
            del test_df["IP_addr"]
            # Convert the 'label' column to categorical with the same categories as in training data
            # test_df['label'] = pd.Categorical(test_df['label'], categories=train_df['label'].cat.categories)
            # Assign codes to the testing data
            # test_df['label_code'] = test_df['label'].cat.codes

            """ Obtain all training and testing labels """
            train_category_code_dic = {}
            for idx, item in train_df.iterrows():
                train_category_code_dic[item["label"]] = item["label_code"]
            # print(train_category_code_dic)
            test_category_code_dic = {}
            for idx, item in test_df.iterrows():
                test_category_code_dic[item["label"]] = item["label_code"]
            # print(test_category_code_dic)

            del train_df["label"]
            y_train = train_df['label_code']
            del train_df['label_code']
            X_train = np.array(train_df)

            del test_df["label"]
            y_test = test_df['label_code']
            del test_df['label_code']
            X_test=np.array(test_df)


            results_y=[]
            cv+=1
            results_y.append(y_test)

            #machine learning algorithm is applied in this section
            clf = ml_list[ii]#choose algorithm from ml_list dictionary
            second=time.time()
            clf.fit(X_train, y_train)
            train_time=(float((time.time()-second)) )
            second=time.time()
            predict =clf.predict(X_test)
            test_time=(float((time.time()-second)) )
            """ Obtain all predicted labels """
            predict_label_set = set()

            """ RF
            rf = RandomForestClassifier(n_estimators=100, random_state=42)
            rf.fit(X_train, y_train)
            y_pred = rf.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred) """

            for item in predict:
                predict_label_set.add(item)
            # print(f"ML_predict_label_set: {predict_label_set}")

            if step==1:
                altime=0
                lines, class_based_results, target_names = score(altime,train_time,test_time,predict,y_test,class_based_results,i,cv,dname,ii)
            else:
                predict,altime=merged(m_test,predict,step,mixed)
                lines, class_based_results, target_names = score(altime,train_time,test_time,predict,y_test,class_based_results,i,cv,dname,ii)
            ths.write (lines)


            df_cm = pd.DataFrame(confusion_matrix(y_test, predict))
            if cm.empty:
                cm =df_cm
            else:
                cm = cm.add(df_cm, fill_value=0)
            
        class_based_results=class_based_results/repetition
        print(class_based_results)
        class_based_results.to_csv(f"class_based_results_{step}.csv")
        if True :
            cm=cm//repetition
            graph_name=output_csv+ii+"_confusion matrix.pdf"   
            plt.figure(figsize = (5,3))
            sns.heatmap(cm,xticklabels=target_names, yticklabels=target_names, annot=True, fmt='g')
            plt.savefig(graph_name,bbox_inches='tight')#, dpi=400)
            plt.show()
            #print(cm)
            print("\n\n\n")             

    ths.close()  


# Machine learning applications
# Aalto Dataset
ml_list={"DT" :DecisionTreeClassifier(criterion='entropy', max_depth=28.0, max_features=16,min_samples_split= 7)}

feature= ['pck_size', 'Ether_type', 'LLC_ctrl', 'EAPOL_version', 'EAPOL_type', 'IP_ihl', 'IP_tos', 'IP_len', 'IP_flags', 'IP_DF', 'IP_ttl', 'IP_options', 'ICMP_code', 'TCP_dataofs', 'TCP_FIN', 'TCP_ACK', 'TCP_window', 'UDP_len', 'DHCP_options', 'BOOTP_hlen', 'BOOTP_flags', 'BOOTP_sname', 'BOOTP_file', 'BOOTP_options', 'DNS_qr', 'DNS_rd', 'DNS_qdcount', 'dport_class', 'payload_bytes', 'entropy',
"IP_addr",
'label',
'label_code']


""" Normal Results
test='UNSW_test_IoTDevID.csv'
train='UNSW_BIG_train_IoTDevID.csv'

dataset="./UNSW/"
step=1

ml_list={"DT" :DecisionTreeClassifier(criterion='entropy', max_depth=27.0, max_features=19,min_samples_split= 8)}
mixed=False

step=1
sayac=1
output_csv=dataset+str(sayac)+"_"+str(step)+"_"+str(mixed)+".csv"
target_names=target_name(test)
ML(train,test,output_csv,feature,step,mixed,dataset[2:-1]+"_"+str(step)) """


""" Aggregated Results (Size 13) """
# test='UNSW_test_IoTDevID.csv'
# train='UNSW_BIG_train_IoTDevID.csv'
train = "ics_library_final_train_vendor.csv"
test = "ics_library_final_test_vendor.csv"

# dataset="./UNSW/"
dataset="result/"
step=1

ml_list={"RF":RandomForestClassifier(bootstrap= False, criterion= "entropy", max_depth= 29, max_features= 7, min_samples_split= 9, n_estimators= 80)}
mixed=False

step=1
sayac=1
output_csv=dataset+str(sayac)+"_"+str(step)+"_"+str(mixed)+".csv"
ML(train, test, output_csv, feature, step, mixed, dataset[2:-1]+"_"+str(step))


""" Mixed (Size 13)
test='UNSW_test_IoTDevID.csv'
train='UNSW_BIG_train_IoTDevID.csv'

dataset="./UNSW/"
step=1

mixed=True

step=13
sayac=1
output_csv=dataset+str(sayac)+"_"+str(step)+"_"+str(mixed)+".csv"
target_names=target_name(test)
ML(train,test,output_csv,feature,step,mixed,dataset[2:-1]+"_"+str(step)) """

