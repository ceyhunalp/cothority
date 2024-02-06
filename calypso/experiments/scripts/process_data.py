import csv
import sys
import re
import argparse
import os
import numpy as np

large_hdr = ['num_txns', 'avg', 'min', 'max', 'std']
lotto_hdr = ['num_txns', 'avg']

BASE_DIR = "data"

otsproto_hdr = ['cmt_sz', 'cl_wr', 'ac_wr', 'ac_r', 'decrypt', 'recover']
pqproto_hdr = ['cmt_sz', 'cl_wr', 'verify_wr', 'ac_wr', 'ac_r', 'decrypt', 'recover']

setup_pattern = "setup_(\w+)_wall_avg"

cwd = os.getcwd()

def read_data(fname):
    with open(fname, 'r') as f:
        reader = csv.reader(f, delimiter=',')
        labels = next(reader)
        data_read = []
        for row in reader:
            data_read.append(dict(zip(labels, row)))
    return data_read

def process_micro(data_read, proto):
    latency_vals = dict()
    if proto == "ots":
        sz = len(otsproto_hdr)
        hdr = otsproto_hdr
    else:
        sz = len(pqproto_hdr)
        hdr = pqproto_hdr
    wall_str = "wall_avg"
    for dr in data_read:
        vals = list()
        cmt_sz = int(dr['hosts'])
        for i in range(1,sz):
            val = float(dr[f'{hdr[i]}_{wall_str}'])
            vals.append(val)
        latency_vals[cmt_sz] = vals

    outpath = os.path.join(cwd, BASE_DIR, 'micro', f'{proto}.csv')
    with open(outpath, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(hdr)
        for k in latency_vals:
            data = [k] + latency_vals[k]
            writer.writerow(data)

def process_burst(data_read, proto):
    write_times = dict()
    read_times = dict()
    wall_str = "wall_avg"
    for dr in data_read:
        num_txns = int(dr['numtxns'])
        write_vals = list()
        read_vals = list()
        for i in range(num_txns):
            w_val = float(dr[f'wr_{i}_{wall_str}'])
            r_val = float(dr[f'r_{i}_{wall_str}'])
            write_vals.append(w_val)
            read_vals.append(r_val)
        write_times[num_txns] = write_vals
        read_times[num_txns] = read_vals

    wr_path = os.path.join(cwd, BASE_DIR, 'burst', f'{proto}_w.csv')
    with open(wr_path, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(large_hdr)
        for k in write_times:
            vals = np.array(write_times[k])
            min_val = np.min(vals)
            max_val = np.max(vals)
            mean_val = np.mean(vals)
            std_val = np.std(vals)
            data = [k, mean_val, min_val, max_val, std_val]
            writer.writerow(data)
    r_path = os.path.join(cwd, BASE_DIR, 'burst', f'{proto}_r.csv')
    with open(r_path, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(large_hdr)
        for k in read_times:
            vals = np.array(read_times[k])
            min_val = np.min(vals)
            max_val = np.max(vals)
            mean_val = np.mean(vals)
            std_val = np.std(vals)
            data = [k, mean_val, min_val, max_val, std_val]
            writer.writerow(data)

def process_burst_partial(data_read, proto):
    write_times = dict()
    read_times = dict()
    wall_str = "wall_avg"
    for dr in data_read:
        num_txns = int(dr['numtxns'])
        write_vals = list()
        read_vals = list()
        for i in range(num_txns):
            w_val = float(dr[f'wr_{i}_{wall_str}'])
            r_val = float(dr[f'r_{i}_{wall_str}'])
            write_vals.append(w_val)
            read_vals.append(r_val)
        wr_mean = np.mean(write_vals)
        r_mean = np.mean(read_vals)
        if num_txns not in write_times:
            write_times[num_txns] = [wr_mean]
            read_times[num_txns] = [r_mean]
        else:
            write_times[num_txns].append(wr_mean)
            read_times[num_txns].append(r_mean)

    print(write_times)
    print(read_times)
    wr_path = os.path.join(cwd, BASE_DIR, 'burst', f'{proto}_part_w.csv')
    with open(wr_path, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(large_hdr)
        for k in write_times:
            vals = np.array(write_times[k])
            min_val = np.min(vals)
            max_val = np.max(vals)
            mean_val = np.mean(vals)
            std_val = np.std(vals)
            data = [k, mean_val, min_val, max_val, std_val]
            writer.writerow(data)
    r_path = os.path.join(cwd, BASE_DIR, 'burst', f'{proto}_part_r.csv')
    with open(r_path, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(large_hdr)
        for k in read_times:
            vals = np.array(read_times[k])
            min_val = np.min(vals)
            max_val = np.max(vals)
            mean_val = np.mean(vals)
            std_val = np.std(vals)
            data = [k, mean_val, min_val, max_val, std_val]
            writer.writerow(data)

def process_lotto(data_read, proto, isBatch):
    txn_vals = list()
    latency_vals = list()
    avg_str = "wall_avg"
    sum_str = "wall_sum"

    for dr in data_read:
        num_txns = int(dr['numtxns'])
        if proto is not None:
            val = float(dr[f'read_{avg_str}']) + float(dr[f'dec_{avg_str}'])
        else:
            val = float(dr[f'open_{sum_str}']) / float(dr['rounds'])
        txn_vals.append(num_txns)
        latency_vals.append(val)

    sz = len(txn_vals)
    if proto is not None:
        if isBatch:
            fpath = os.path.join(cwd, BASE_DIR, 'lotto', f'{proto}_batch.csv')
        else:
            fpath = os.path.join(cwd, BASE_DIR, 'lotto', f'{proto}.csv')
    else:
        fpath = os.path.join(cwd, BASE_DIR, 'lotto', 'tournament.csv')
    with open(fpath, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(lotto_hdr)
        for i in range(sz):
            data = [txn_vals[i], latency_vals[i]]
            writer.writerow(data)

def process_byzgen(data_read, proto):
    write_vals = list()
    read_vals = list()
    for dr in data_read:
        num_wtxns = int(dr['numwritetxns'])
        num_rtxns = int(dr['numreadtxns'])
        for i in range(num_wtxns):
            val = float(dr[f'wr_{i}_wall_avg'])
            write_vals.append(val)
        for i in range(num_rtxns):
            val = float(dr[f'r_{i}_wall_avg'])
            read_vals.append(val)

    fpath = os.path.join(cwd, BASE_DIR, 'byzgen', f'{proto}_write.csv')
    with open(fpath, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(large_hdr)
        np_wvals = np.array(write_vals)
        min_val = np.min(np_wvals)
        max_val = np.max(np_wvals)
        mean_val = np.mean(np_wvals)
        std_val = np.std(np_wvals)
        data = [num_wtxns, mean_val, min_val, max_val, std_val]
        writer.writerow(data)

    fpath = os.path.join(cwd, BASE_DIR, 'byzgen', f'{proto}_read.csv')
    with open(fpath, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(large_hdr)
        np_rvals = np.array(read_vals)
        min_val = np.min(np_rvals)
        max_val = np.max(np_rvals)
        mean_val = np.mean(np_rvals)
        std_val = np.std(np_rvals)
        data = [num_rtxns, mean_val, min_val, max_val, std_val]
        writer.writerow(data)

def main():
    parser = argparse.ArgumentParser(description='Parsing csv files')
    parser.add_argument('fname', type=str)
    parser.add_argument('exp_type', choices=['micro', 'burst', 'lotto', 'byzgen'], type=str)
    parser.add_argument('-p', dest='proto', choices=['ots', 'pqots', 'sc'], type=str)
    parser.add_argument('-b', dest='batch', action='store_true')
    parser.add_argument('-pa', dest='partial', action='store_true')

    args = parser.parse_args()
    data_read = read_data(args.fname)
    if "burst" in args.exp_type:
        if args.partial:
            process_burst_partial(data_read, args.proto)
        else:
            process_burst(data_read, args.proto)
    elif "lotto" in args.exp_type:
        process_lotto(data_read, args.proto, args.batch)
    elif "byzgen" in args.exp_type:
        process_byzgen(data_read, args.proto)
    elif "micro" in args.exp_type:
        process_micro(data_read, args.proto)

if __name__ == '__main__':
    main()
