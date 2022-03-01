
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

averages = {} # dict to hold averages for each datapoint

plt.figure(0)

marker = itertools.cycle((',', '+', '.', 'o', '*')) #markers to use for each kind of datapoint
ref_name = '000_time_ref.pckl'
limit_meas_name='070_acting.pckl' # measurement to check for limit
limit_value = 1000 # value for limit percentage calculation
limit_checked_datapoints = 0 # how many points were checked
points_over_limit = 0
for name in sorted(statistics,reverse=True): # for each named set of datapoints in the statistics files
    
    if name == ref_name: # dont add reference timestamps plot
        continue
    dataset = statistics[name]
    block_nr_array=[]
    value_array =[]
    time_offset_sum = 0 # for calculating average later
    nr_of_datapoints = 0 # for calculating average later
    for meas_ref_nr in dataset: # for each mesurement data point
        timestamp = dataset[meas_ref_nr]
        try:
            ref_timestamp = statistics[ref_name][meas_ref_nr]
        except KeyError: # if there is no matching reference data
            print(f"error: no reference data, skipping datapoint {meas_ref_nr} in {name}")
            continue
        nr_of_datapoints += 1

        time_offset = timestamp - ref_timestamp
        time_offset_sum += time_offset

        if name == limit_meas_name:
            if time_offset > limit_value:
                points_over_limit += 1

        block_nr_array.append(int(meas_ref_nr))
        value_array.append(time_offset)
    # at this point all datapoints for this named set were processed
    plt.scatter(block_nr_array,value_array,label=name, marker=next(marker))
    if nr_of_datapoints > 0:
        averages[name]=time_offset_sum/nr_of_datapoints
        if name == limit_meas_name: # if this is the set to check against the limit save number of points
            limit_checked_datapoints = nr_of_datapoints

percent_ok = (limit_checked_datapoints-points_over_limit)/limit_checked_datapoints*100
print(f"{points_over_limit} of {limit_checked_datapoints} points in {limit_meas_name} over limit [{percent_ok:.2f}% OK]")
print("averages:")
print("name,average delay [ms]")
for name,value in averages.items():
    print(f"\"{name}\",{value:.1f}")


plt.legend(loc="upper left")
plt.axhline(y=1000, color='r', linestyle='-') # add 1000 ms limit as line
plt.xlabel("block number")
plt.ylabel("time after data sensed [ms]")


# calculate event durations data
durations_to_calculate = [
    ("000_time_ref.pckl","070_acting.pckl"),

    ("030_seal_start.pckl","033_seal_end.pckl"),
    ("031_send_UPP_start.pckl","032_send_UPP_end.pckl"),

    ("050_verify_start.pckl","060_verify_end.pckl"),
    ("051_get_BE_UPP_start.pckl","052_get_BE_UPP_end.pckl"),

    ("033_seal_end.pckl","040_received.pckl"),

    ("000_time_ref.pckl", "030_seal_start.pckl")
    ]
durations = [] # will become of list of lists with the duration values for each event (i.e. durations[eventname][datapoint])
durations_names = [] # the names for above list of lists

for curr_duration in durations_to_calculate:
    start_name, end_name = curr_duration
    duration_datapoints = [] # list for storing results
    for datapoint_start_ref in statistics[start_name]: # iterate over datapoints from start dataset
        start_ts = statistics[start_name][datapoint_start_ref]
        # find end timestamp for the same datapoint reference in end dataset
        try:
            end_ts = statistics[end_name][datapoint_start_ref]
        except KeyError: # if there is no matching reference data
            print(f"error: no end data found, skipping datapoint {datapoint_start_ref} in {end_name}")
            continue
        duration = end_ts-start_ts
        duration_datapoints.append(duration)
    # all points done, add calculated durations to list
    event_name = start_name+"->"+end_name
    durations.append(duration_datapoints)
    durations_names.append(event_name)

plt.figure(1)
plt.xlabel('event name')
plt.ylabel('event duration [ms]')
plt.xticks(ticks=range(1,len(durations)+1), labels=durations_names, rotation=10) # add x labels for events
plt.violinplot(durations,showmedians=True)


plt.show()# show all figures

