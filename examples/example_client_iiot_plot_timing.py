
import itertools
import os
import pickle
import numpy as np
import matplotlib.pyplot as plt

# do scatter plot of delays over rounds on exit
# rounds = [*range(len(rtt_array))]
# plt.scatter(rounds, rtt_array)
# plt.ylabel("Round Trip Time [s]")
# plt.xlabel("Round Number")
# plt.show()

# check for timing data written by actuator/client and display it
print("checking for external statistic files...")
statistics = {}
for file in os.listdir("."):
    if file.endswith(".pckl"):
        print(f"loading {file}")
        with open(file, 'rb') as handle:
            dict = pickle.load(handle)
        statistics[file]=dict

marker = itertools.cycle((',', '+', '.', 'o', '*')) #markers to use for each kind of datapoint
for name in sorted(statistics,reverse=True):
    ref_name = '000_time_ref.pckl'
    if name == ref_name: # dont add reference timestamps plot
        continue
    dataset = statistics[name]
    block_nr_array=[]
    value_array =[]
    for meas_ref in dataset:
        timestamp = dataset[meas_ref]
        try:
            ref_timestamp = statistics[ref_name][meas_ref]
        except KeyError: # if there is no matching reference data
            print(f"error: no reference data, skipping datapoint {meas_ref} in {name}")
            continue
        time_offset = timestamp - ref_timestamp
        block_nr_array.append(int(meas_ref))
        value_array.append(time_offset)
    plt.scatter(block_nr_array,value_array,label=name, marker=next(marker))
plt.legend(loc="upper left")
plt.axhline(y=1000, color='r', linestyle='-') # add 1000 ms limit as line
plt.xlabel("block number")
plt.ylabel("time after data sensed [ms]")
plt.show()
