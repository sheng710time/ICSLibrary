"""
Coding: UTF-8
Author: Chuan Sheng
Date: 13/7/24
Description:
"""
import csv
import random
import pandas as pd
import os


"""
Generate training and testing data files
"""
def generate_train_test_data(df, train_filepath, test_filepath, ratio):
    train_list, test_list, header = fingerprint_preprocess(df, ratio)

    train_ip_set = set()
    train_label_dic = {}
    with open(train_filepath, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(header)
        # Write each row to the CSV file
        for row in train_list:
            writer.writerow(row)
            train_ip_set.add(row[31])
            if row[34] in train_label_dic:
                train_label_dic[row[34]] = train_label_dic[row[34]] +1
            else:
                train_label_dic[row[34]] = 1

    test_ip_set = set()
    test_label_dic = {}
    with open(test_filepath, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(header)
        # Write each row to the CSV file
        for row in test_list:
            writer.writerow(row)
            test_ip_set.add(row[31])
            if row[34] in test_label_dic:
                test_label_dic[row[34]] = test_label_dic[row[34]] + 1
            else:
                test_label_dic[row[34]] = 1

    # print(len(train_ip_dic), len(test_ip_dic))
    print(f"training_label: {len(train_label_dic)}, training_ip: {len(train_ip_set)}, testing_label: {len(test_label_dic)}, testing_ip: {len(test_ip_set)}")
    for label in train_label_dic:
        print(f"{label}: {train_label_dic[label]}, {test_label_dic[label] if label in test_label_dic else 0}")


"""
Convert raw fingerprint data to training and testing lists
"""
def fingerprint_preprocess(df, ratio = 0.8):
    # Combine and add label column to df
    header = df.columns.tolist()

    # Split data by "label"
    labeled_data_dict = {}  # {"label1":[ip1, ip2, ...], "label2":[ip3, ip4, ...], ...}
    for index, raw_data in df.iterrows():
        if raw_data["label"] in labeled_data_dict:
            labeled_data_dict[raw_data["label"]].add(raw_data["IP_addr"])
        else:
            labeled_data_dict[raw_data["label"]] = set()
            labeled_data_dict[raw_data["label"]].add(raw_data["IP_addr"])

    """ verify the total number
    count = 0
    for label, array in labeled_data_dict.items():
        count += len(array)
    print(count) """

    train_labeled_ip_set, test_labeled_ip_set = train_test_split_labeled_ip(labeled_data_dict, ratio)
    train_list = []
    test_list = []
    for index, raw_data in df.iterrows(): # keep the order of IPs in original pcap files
        if raw_data["IP_addr"] in train_labeled_ip_set:
            train_list.append(raw_data)
        elif raw_data["IP_addr"] in test_labeled_ip_set:
            test_list.append(raw_data)

    return train_list, test_list, header


def train_test_split_labeled_ip(labeled_ip_data_dict, ratio):
    """
    train_labeled_ip_set = set()  #[ip1, ip2, ...]
    test_labeled_ip_set = set()  #[ip3, ip4, ...]
    string_labels = []
    for label, labeled_ip in labeled_ip_data_dict.items():
        # Generate the index list
        labeled_ip_idxs = list(range(len(labeled_ip)))
        # Shuffle the array
        random.shuffle(labeled_ip_idxs)
        # Split the index list
        train_idx = labeled_ip_idxs[:int(round(ratio*len(labeled_ip_idxs)+0.1))]  # add a small value (0.1) to the float to ensure that 0.5 rounds up to 1
        test_idx = labeled_ip_idxs[int(ratio*len(labeled_ip_idxs)):]

        current_idx = 0
        for ip_addr in labeled_ip:
            if current_idx in train_idx:
                train_labeled_ip_set.add(ip_addr)
            else:
                test_labeled_ip_set.add(ip_addr)
            current_idx += 1 """

    """ Get training and testing IP sets from data directory """
    code_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    project_dir = os.path.dirname(os.path.dirname(os.path.dirname(code_dir)))
    data_path = os.path.join(project_dir, "data\\ip_list")

    train_labeled_ip_df = pd.read_csv(os.path.join(data_path, "enip_vendor_train_ip_list.csv"))
    train_labeled_ip_set = set(train_labeled_ip_df["train_ip"])

    test_labeled_ip_df = pd.read_csv(os.path.join(data_path, "enip_vendor_test_ip_list.csv"))
    test_labeled_ip_set = set(test_labeled_ip_df["test_ip"])
    return train_labeled_ip_set, test_labeled_ip_set


""" Load csv files """
code_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
project_dir = os.path.dirname(os.path.dirname(os.path.dirname(code_dir)))
data_path=os.path.join(project_dir, "data\\csv\\enip")
def find_the_way(path,file_format):
    files_add = []
    # r=root, d=directories, f = files
    for r, d, f in os.walk(path):
        for file in f:
            if file_format in file:
                files_add.append(os.path.join(r, file))
    return files_add
files_add=find_the_way(data_path,'.csv')
print(f"The number of pcap files: {len(files_add)}")
for file in files_add:
    print(file)

df = pd.DataFrame()
for numero,i in enumerate (files_add):
    df2 = pd.read_csv(i)
    df = pd.concat([df, df2], ignore_index=True)


# file_name = "../ics_library_final.csv"
train_filepath = "ics_library_final_train_vendor.csv"
test_filepath = "ics_library_final_test_vendor.csv"
ratio = 0.8
generate_train_test_data(df, train_filepath, test_filepath, ratio)