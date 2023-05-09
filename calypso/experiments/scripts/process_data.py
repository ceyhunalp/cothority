import csv
import sys
import re
import argparse
import os
import numpy as np

burst_hdr = ['num_txns', 'avg', 'min', 'max', 'std']
lotto_hdr = ['num_txns', 'avg']

BASE_DIR = "data"

spattern = 'sign_(\d+)_(\d+)_wall_avg'
setup_pattern = "setup_(\w+)_wall_avg"

# pattern_dict = {SETUP: setup_pattern, CLOSE: cpattern, LOCK: lpattern, SHUFFLE:
                # shuf_pattern, TALLY: tpattern, FINALIZE: fpattern}

cwd = os.getcwd()

def read_data(fname):
    with open(fname, 'r') as f:
        reader = csv.reader(f, delimiter=',')
        labels = next(reader)
        data_read = []
        for row in reader:
            data_read.append(dict(zip(labels, row)))
    return data_read

def process_kv(data_read, local):
    data = dict()
    for label, value in data_read[0].items():
        if local:
            match = re.search(vpattern_local, label)
        else:
            match = re.search(vpattern, label)
        if match is not None:
            input_num = int(match.group(1))
            blk_num = int(match.group(2))
            if blk_num > 5:
                if input_num not in data:
                    data[input_num] = {blk_num: value}
                else:
                    d = data[input_num]
                    d[blk_num] = value

    print("input_num,block_num,total")
    for input_num, val_dict in sorted(data.items()):
        for blk_num, val in sorted(val_dict.items()):
            print("%d,%d,%.6f" % (input_num, blk_num, float(val)))

def process_opc(data_read, local):
    data = dict()
    for label, value in data_read[0].items():
        if local:
            match = re.search(vpattern_local, label)
        else:
            match = re.search(vpattern, label)
        if match is not None:
            input_num = int(match.group(1))
            data_size = int(match.group(2))
            if data_size > 4096:
                if input_num not in data:
                    data[input_num] = {data_size: value}
                else:
                    d = data[input_num]
                    d[data_size] = value

    print("input_num,data_size,total")
    for input_num, val_dict in sorted(data.items()):
        for data_size, val in sorted(val_dict.items()):
            print("%d,%d,%.6f" % (input_num, data_size, float(val)))

def process_sign(data_read, local):
    data = dict()
    for label, value in data_read[0].items():
        if local:
            match = re.search(spattern_local, label)
        else:
            match = re.search(spattern, label)
        if match is not None:
            output_num = int(match.group(1))
            data_size = int(match.group(2))
            if data_size > 4096:
                if output_num not in data:
                    data[output_num] = {data_size: value}
                else:
                    d = data[output_num]
                    d[data_size] = value

    print("output_num,data_size,total")
    for output_num, val_dict in sorted(data.items()):
        for data_size, val in sorted(val_dict.items()):
            print("%d,%d,%.6f" % (output_num, data_size, float(val)))

def process_dfu_mb(data_read, prefix):
    data = dict()
    label = prefix + "_wall_avg"
    for dr in data_read:
        num_ctexts = int(dr['numciphertexts'])
        if num_ctexts > 5:
            data[num_ctexts] = float(dr[label])

    print("num_ctexts,total")
    for k in data:
        print("%d,%6f" % (k,data[k]))

def process_jv(data_read, app_type, txn_type, outfile):
    latency_vals = dict()
    for dr in data_read:
        num_participants = int(dr['numparticipants'])
        if num_participants > 5:
            vals = list()
            for i in range(num_participants):
                val = float(dr[f'p{i}_{txn_type}_wall_avg'])
                vals.append(val)
            latency_vals[num_participants] = vals

    if outfile:
        fpath = os.path.join(cwd, BASE_DIR, app_type, f'{outfile}_{txn_type}.csv')
    else:
        fpath = os.path.join(cwd, BASE_DIR, app_type, f'{txn_type}.csv')
    with open(fpath, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(jv_header)
        for k in latency_vals:
            vals = np.array(latency_vals[k])
            min_val = np.min(vals)
            max_val = np.max(vals)
            mean_val = np.mean(vals)
            std_val = np.std(vals)
            data = [k, mean_val, min_val, max_val, std_val]
            writer.writerow(data)
            # print("%d,%.6f,%.6f,%.6f" % (k, mean_val, min_val, max_val))

def process_jv_batch(data_read, app_type, txn_type, outfile):
    latency_vals = dict()
    for dr in data_read:
        num_participants = int(dr['numparticipants'])
        if num_participants > 5:
            vals = list()
            for i in range(num_batches):
                val = float(dr[f'batch_{txn_type}_{i}_wall_avg'])
                vals.append(val)
            latency_vals[num_participants] = vals
    if outfile:
        fpath = os.path.join(cwd, BASE_DIR, app_type, f'{outfile}_{txn_type}_batch.csv')
    else:
        fpath = os.path.join(cwd, BASE_DIR, app_type, f'{txn_type}_batch.csv')
    with open(fpath, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(jv_header)
        for k in latency_vals:
            vals = np.array(latency_vals[k])
            # min_val = vals.min()
            # max_val = vals.max()
            # mean_val = vals.mean()
            min_val = np.min(vals)
            max_val = np.max(vals)
            mean_val = np.mean(vals)
            std_val = np.std(vals)
            data = [k, mean_val, min_val, max_val, std_val]
            writer.writerow(data)
            # print("%d,%.6f,%.6f,%.6f" % (k, mean_val, min_val, max_val))

def process_txn(data_read, app_type, txn_type, outfile, batch):
    print(">>>", txn_type)
    pattern = pattern_dict[txn_type]
    if outfile:
        if batch:
            fpath = os.path.join(cwd, BASE_DIR, app_type, f'{outfile}_{txn_type}_batch.csv')
        else:
            fpath = os.path.join(cwd, BASE_DIR, app_type, f'{outfile}_{txn_type}.csv')
    else:
        if batch:
            fpath = os.path.join(cwd, BASE_DIR, app_type, f'{txn_type}_batch.csv')
        else:
            fpath = os.path.join(cwd, BASE_DIR, app_type, f'{txn_type}.csv')
    with open(fpath, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(txn_header)
        dedup = dict()
        for dr in data_read:
            num_participants = int(dr['numparticipants'])
            if num_participants > 5:
                total = 0.0
                for label, value in dr.items():
                    match = re.search(pattern, label)
                    # if match is not None and match.group(1) != "getstate":
                    if match is not None: 
                        total += float(value)
                data = [num_participants, total]
                dedup[num_participants] = data
                # writer.writerow(data)
                # print("%d,%.6f" % (num_participants, total))
        for nump in sorted(dedup):
            writer.writerow(dedup[nump])

def process_randlot(data_read, outfile, batch):
    if batch:
        process_jv_batch(data_read, RANDLOTTERY, JOIN, outfile)
    else:
        process_jv(data_read, RANDLOTTERY, JOIN, outfile)
    process_txn(data_read, RANDLOTTERY, CLOSE, outfile, batch)
    process_txn(data_read, RANDLOTTERY, FINALIZE, outfile, batch)

def process_dkglot(data_read, outfile, batch):
    if batch:
        process_jv_batch(data_read, DKGLOTTERY, JOIN, outfile)
    else:
        process_jv(data_read, DKGLOTTERY, JOIN, outfile)
    process_txn(data_read, DKGLOTTERY, SETUP, outfile, batch)
    process_txn(data_read, DKGLOTTERY, CLOSE, outfile, batch)
    process_txn(data_read, DKGLOTTERY, FINALIZE, outfile, batch)

def process_evote(data_read, outfile, batch):
    if batch:
        process_jv_batch(data_read, EVOTING, VOTE, outfile)
    else:
        process_jv(data_read, EVOTING, VOTE, outfile)
    process_txn(data_read, EVOTING, SETUP, outfile, batch)
    process_txn(data_read, EVOTING, LOCK, outfile, batch)
    process_txn(data_read, EVOTING, SHUFFLE, outfile, batch)
    process_txn(data_read, EVOTING, TALLY, outfile, batch)

def dump_kv(data_read):
    data = dict()
    for label, value in data_read[0].items():
        avg_match = re.search(vpattern, label)
        # max_match = re.search(vpattern_max, label)
        # if avg_match is not None and min_match is not None and max_match is not None:
        if avg_match is not None:
            input_num = int(avg_match.group(1))
            blk_num = int(avg_match.group(2))
            if blk_num > 5:
                if input_num not in data:
                    data[input_num] = {blk_num: [value]}
                else:
                    d = data[input_num]
                    d[blk_num] = [value]

    for label, value in data_read[0].items():
        min_match = re.search(vpattern_min, label)
        if min_match is not None:
            input_num = int(min_match.group(1))
            blk_num = int(min_match.group(2))
            if blk_num > 5:
                d = data[input_num]
                d[blk_num].append(value)

    for label, value in data_read[0].items():
        max_match = re.search(vpattern_max, label)
        if max_match is not None:
            input_num = int(max_match.group(1))
            blk_num = int(max_match.group(2))
            if blk_num > 5:
                d = data[input_num]
                d[blk_num].append(value)


    print("input_num,block_num,avg,min,max")
    for input_num, val_dict in sorted(data.items()):
        for blk_num, val in sorted(val_dict.items()):
            print("%d,\t%d,\t%.6f,\t%.6f,\t%.6f" % (input_num, blk_num,
                                            float(val[0]), float(val[1]),
                                            float(val[2])))

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

    wr_path = os.path.join(cwd, BASE_DIR, f'{proto}_write_burst.csv')
    with open(wr_path, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(burst_hdr)
        for k in write_times:
            vals = np.array(write_times[k])
            min_val = np.min(vals)
            max_val = np.max(vals)
            mean_val = np.mean(vals)
            std_val = np.std(vals)
            data = [k, mean_val, min_val, max_val, std_val]
            writer.writerow(data)
    r_path = os.path.join(cwd, BASE_DIR, f'{proto}_read_burst.csv')
    with open(r_path, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(burst_hdr)
        for k in read_times:
            vals = np.array(read_times[k])
            min_val = np.min(vals)
            max_val = np.max(vals)
            mean_val = np.mean(vals)
            std_val = np.std(vals)
            data = [k, mean_val, min_val, max_val, std_val]
            writer.writerow(data)

# def process_burst(data_read, proto):
    # write_times = dict()
    # read_times = dict()
    # wall_str = "wall_avg"
    # for dr in data_read:
        # num_txns = int(dr['numtxns'])
        # write_vals = list()
        # read_vals = list()
        # for i in range(num_txns):
            # if "pqots" in proto:
                # w_val = float(dr[f'wr_txn_{i}_{wall_str}']) + float(dr[f'wr_pr_{i}_{wall_str}']) + float(dr[f'wr_verify_{i}_{wall_str}'])
            # else:
                # w_val = float(dr[f'wr_txn_{i}_{wall_str}']) + float(dr[f'wr_pr_{i}_{wall_str}'])
            # r_val = float(dr[f'r_txn_{i}_{wall_str}']) + float(dr[f'r_pr_{i}_{wall_str}']) + float(dr[f'dec_{i}_{wall_str}'])
            # write_vals.append(w_val)
            # read_vals.append(r_val)
        # write_times[num_txns] = write_vals
        # read_times[num_txns] = read_vals

    # wr_path = os.path.join(cwd, BASE_DIR, f'{proto}_write_burst.csv')
    # with open(wr_path, 'w') as f:
        # writer = csv.writer(f)
        # writer.writerow(burst_hdr)
        # for k in write_times:
            # vals = np.array(write_times[k])
            # min_val = np.min(vals)
            # max_val = np.max(vals)
            # mean_val = np.mean(vals)
            # std_val = np.std(vals)
            # data = [k, mean_val, min_val, max_val, std_val]
            # writer.writerow(data)
    # r_path = os.path.join(cwd, BASE_DIR, f'{proto}_read_burst.csv')
    # with open(r_path, 'w') as f:
        # writer = csv.writer(f)
        # writer.writerow(burst_hdr)
        # for k in read_times:
            # vals = np.array(read_times[k])
            # min_val = np.min(vals)
            # max_val = np.max(vals)
            # mean_val = np.mean(vals)
            # std_val = np.std(vals)
            # data = [k, mean_val, min_val, max_val, std_val]
            # writer.writerow(data)

# def process_burst(data_read, proto):
    # write_times = dict()
    # read_times = dict()
    # wall_str = "wall_avg"
    # for dr in data_read:
        # num_txns = int(dr['numtxns'])
        # write_vals = list()
        # read_vals = list()
        # w_val = float(dr[f'wr_txn_{wall_str}']) + float(dr[f'wr_pr_{wall_str}'])
        # r_val = float(dr[f'r_txn_{wall_str}']) + float(dr[f'r_pr_{wall_str}'])
        # w_val = w_val / float(num_txns)
        # r_val = r_val / float(num_txns)
        # for i in range(num_txns):
            # dec_val = float(dr[f'dec_{i}_{wall_str}'])
            # total_val = r_val + dec_val
            # read_vals.append(total_val)
        # write_times[num_txns] = w_val
        # read_times[num_txns] = read_vals

    # wr_path = os.path.join(cwd, BASE_DIR, f'{proto}_write_burst.csv')
    # with open(wr_path, 'w') as f:
        # writer = csv.writer(f)
        # writer.writerow(burst_hdr)
        # for k in write_times:
            # vals = np.array(write_times[k])
            # min_val = np.min(vals)
            # max_val = np.max(vals)
            # mean_val = np.mean(vals)
            # std_val = np.std(vals)
            # data = [k, mean_val, min_val, max_val, std_val]
            # writer.writerow(data)
    # r_path = os.path.join(cwd, BASE_DIR, f'{proto}_read_burst.csv')
    # with open(r_path, 'w') as f:
        # writer = csv.writer(f)
        # writer.writerow(burst_hdr)
        # for k in read_times:
            # vals = np.array(read_times[k])
            # min_val = np.min(vals)
            # max_val = np.max(vals)
            # mean_val = np.mean(vals)
            # std_val = np.std(vals)
            # data = [k, mean_val, min_val, max_val, std_val]
            # writer.writerow(data)

def process_lotto(data_read, proto):
    txn_vals = list()
    latency_vals = list()
    wall_str = "wall_avg"
    if proto is not None:
        for dr in data_read:
            num_txns = int(dr['numtxns'])
            val = float(dr[f'r_txn_{wall_str}']) + float(dr[f'r_pr_{wall_str}']) + float(dr[f'dec_{wall_str}'])
            # val = float(dr[f'add_read_{wall_str}']) + float(dr[f'decrypt_{wall_str}'])
            txn_vals.append(num_txns)
            latency_vals.append(val)

        sz = len(txn_vals)
        fpath = os.path.join(cwd, BASE_DIR, f'{proto}_lotto.csv')
        with open(fpath, 'w') as f:
            writer = csv.writer(f)
            writer.writerow(lotto_hdr)
            for i in range(sz):
                data = [txn_vals[i], latency_vals[i]]
                writer.writerow(data)
            # for num_txn in txn_vals:
                # data = [num_txn, latency_vals[num_txn]]
                # writer.writerow(data)

def main():
    parser = argparse.ArgumentParser(description='Parsing csv files')
    parser.add_argument('fname', type=str)
    parser.add_argument('exp_type', choices=['burst', 'lotto'], type=str)
    parser.add_argument('-p', dest='proto', choices=['ots', 'pqots'], type=str)
    # parser.add_argument('-b', dest='batch', action='store_true')
    # parser.add_argument('-o', dest='outfile', type=str)
    # parser.add_argument('-d', dest='dump', action='store_true')
    args = parser.parse_args()
    data_read = read_data(args.fname)
    if "burst" in args.exp_type:
        process_burst(data_read, args.proto)
    elif "lotto" in args.exp_type:
        process_lotto(data_read, args.proto)
    # if "kv" in args.exp_type:
        # if args.dump:
            # dump_kv(data_read)
        # else:
            # process_kv(data_read, args.local)
    # elif "opc" in args.exp_type:
        # if args.dump:
            # dump_opc(data_read)
        # else:
            # process_opc(data_read, args.local)
    # elif "sign" in args.exp_type:
        # process_sign(data_read, args.local)
    # elif "shuf" in args.exp_type:
        # process_dfu_mb(data_read, "shuffle")
    # elif "dec" in args.exp_type:
        # process_dfu_mb(data_read, "decrypt")
    # elif "rlot" in args.exp_type:
        # process_randlot(data_read, args.outfile, args.batch)
    # elif "dlot" in args.exp_type:
        # process_dkglot(data_read, args.outfile, args.batch)
    # elif "evote" in args.exp_type:
        # process_evote(data_read, args.outfile, args.batch)

if __name__ == '__main__':
    main()
