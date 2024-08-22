"""
Coding: UTF-8
Author: Chuan Sheng
Date: 13/7/24
Description:
"""
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import numpy as np

def score_packets(test_data, y_pred, test_label_list):
    packet_predict = []
    packet_label = []
    for index, row in test_data.iterrows():
        count = row["src_num_packet"] + row["dst_num_packet"]
        for a in range(count):
            packet_predict.append(y_pred[index])
            packet_label.append(test_label_list[index])

    accuracy = accuracy_score(packet_label, packet_predict)
    rc = sklearn.metrics.recall_score(packet_label, packet_predict,average= "weighted")
    pr = sklearn.metrics.precision_score(packet_label, packet_predict,average= "weighted")
    f1_score = sklearn.metrics.f1_score(packet_label, packet_predict,average= "weighted")
    # print(f'Packet_Accuracy: {accuracy:.6f}，Packet_F1_score: {f1_score:.6f}')

    target_names = set(np.concatenate((y_pred, test_label_list), axis=0))  # Including all labels in y_test and predict
    report = classification_report(packet_label, packet_predict, target_names=target_names, output_dict=True)
    cr = pd.DataFrame(report).transpose()
    return cr


def run():
    # load data
    train_filepath = "ics_library_final_train_vendor.csv"
    test_filepath = "ics_library_final_test_vendor.csv"

    header = ["src_addr", "dst_addr", "src_num_port", "dst_num_port", "src_num_packet", "dst_num_packet", "src_num_byte", "dst_num_byte", "src_size_min_packet", "src_size_max_packet", "src_size_mean_packet", "src_size_stddev_packet", "dst_size_min_packet", "dst_size_max_packet", "dst_size_mean_packet", "dst_size_stddev_packet", "src_time_min_packet", "src_time_max_packet", "src_time_mean_packet", "src_time_stddev_packet", "dst_time_min_packet", "dst_time_max_packet", "dst_time_mean_packet" ,"dst_time_stddev_packet", "read_times", "read_num_location", "read_length_location", "write_times", "write_num_location", "write_length_location", "ilrt", "IP_addr", "vendor", "model", "label", "label_code"]
    feature = ["src_num_port", "dst_num_port", "src_num_packet", "dst_num_packet", "src_num_byte", "dst_num_byte", "src_size_min_packet", "src_size_max_packet", "src_size_mean_packet", "src_size_stddev_packet", "dst_size_min_packet", "dst_size_max_packet", "dst_size_mean_packet", "dst_size_stddev_packet", "src_time_min_packet", "src_time_max_packet", "src_time_mean_packet", "src_time_stddev_packet", "dst_time_min_packet", "dst_time_max_packet", "dst_time_mean_packet" ,"dst_time_stddev_packet"]
    feature_ilrt = ["src_num_port", "dst_num_port", "src_num_packet", "dst_num_packet", "src_num_byte", "dst_num_byte", "src_size_min_packet", "src_size_max_packet", "src_size_mean_packet", "src_size_stddev_packet", "dst_size_min_packet", "dst_size_max_packet", "dst_size_mean_packet", "dst_size_stddev_packet", "src_time_min_packet", "src_time_max_packet", "src_time_mean_packet", "src_time_stddev_packet", "dst_time_min_packet", "dst_time_max_packet", "dst_time_mean_packet" ,"dst_time_stddev_packet", "ilrt"]

    bins = 50
    train_data = pd.read_csv(train_filepath)
    train_data["ilrt"] = pd.cut(train_data["ilrt"], bins=bins, labels=[i for i in range(0, bins)])
    train_feature_list = train_data[feature_ilrt]
    train_label_list = train_data["label_code"]

    test_data = pd.read_csv(test_filepath)
    test_data["ilrt"] = pd.cut(test_data["ilrt"], bins=bins, labels=[i for i in range(0, bins)])
    test_feature_list = test_data[feature_ilrt]
    test_label_list = test_data["label_code"]

    rf = RandomForestClassifier(n_estimators=100, random_state=42)

    rf.fit(train_feature_list, train_label_list)
    print("Feature_importance: ", rf.feature_importances_)

    y_pred = rf.predict(test_feature_list)

    accuracy = accuracy_score(test_label_list, y_pred)
    f1_score = sklearn.metrics.f1_score(test_label_list, y_pred, average="weighted")

    print(f'Training data size: {len(train_feature_list)}')
    print(f'Training label size: {len(set(train_label_list))}')
    print(f'Testing data size: {len(test_feature_list)}')
    print(f'Testing label size: {len(set(test_label_list))}')
    # print(f'Session_Accuracy: {accuracy:.6f}，Session_F1_score: {f1_score:.6f}')

    target_names = set(np.concatenate((y_pred, test_label_list), axis=0))  # Including all labels in y_test and predict
    report = classification_report(test_label_list, y_pred, target_names=target_names, output_dict=True)
    cr = pd.DataFrame(report).transpose()
    print("Flow-level results: ")
    print(cr)

    packet_cr = score_packets(test_data, y_pred, test_label_list)
    print("Packet-level results: ")
    print(packet_cr)

    conf = confusion_matrix(test_label_list, y_pred)
    # print(conf)

if __name__ == '__main__':
    run()