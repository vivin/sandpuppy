import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

from matplotlib.colors import LogNorm

fuzzers = ["afl-plain", "aflplusplus-plain", "aflplusplus-lafintel", "aflplusplus-redqueen", "sandpuppy"]
colors = ['darkblue', 'darkgreen', 'olive', 'darkorchid', 'crimson']
labels = ['AFL', 'AFL++', 'AFL++ (LAFIntel)', 'AFL++ (RedQueen)', 'SandPuppy']
length_max = [167, 149, 154, 192, 103]
#length_max = [192, 192, 192, 192, 192]

for i in range(0, 5):
    print("Generating found sequence-length counts heatmap for " + labels[i])

    length_counts_by_hour = dict()
    for hour in range(0, 111):
        length_counts_by_hour[hour] = []
        for length in range(0, length_max[i] + 1):
            length_counts_by_hour[hour].append(1)

    file = open(
        "/mnt/vivin-nfs/vivin/smartdsf/libtpms/results/di-ec-run/aggregated/" + fuzzers[i] + "-cslot.dat",
        'r'
    )
    lines = file.readlines()
    file.close()

    for hour in range(0, len(lines)):
        line = lines[hour].rstrip()
        if len(line) == 0:
            continue

        for length in line.split(' '):
            length = int(length)
            if length != 0:
                length_counts_by_hour[hour][int(length) - 1] += 1

    df = pd.DataFrame.from_dict(length_counts_by_hour)
    df.index = np.arange(1, len(df) + 1)
    #with pd.option_context('display.max_rows', None, 'display.max_columns', 200):  # more options can be specified also
    #    print(df)

    sns.set(font="Times New Roman", font_scale=2)
    plt.subplots(figsize=(9, 7))
    ax = sns.heatmap(
        df,
        norm=LogNorm(),
        cmap='crest',
        cbar_kws={'label': 'Number of sequences found'},
        xticklabels=10,
        yticklabels=9
    )
    ax.invert_yaxis()
    ax.set_xlabel("Hours", size=24)
    ax.set_ylabel("Sequence Length", size=24)
    ax.set_title("Counts of various sequence lengths\nfound over time by " + labels[i], size=24)
    ax.set_yticklabels(ax.get_yticklabels(), rotation=0)

    plt.subplots_adjust(left=0.1075, right=1, bottom=0.0975, top=0.9)
    #plt.tight_layout()
    plt.savefig("/home/vivin/Projects/sandpuppy-paper/seq_length_heatmap-" + fuzzers[i] + ".png")

    plt.clf()

