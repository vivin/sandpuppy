import matplotlib.pyplot as plt
import numpy as np
import matplotlib.gridspec as gridspec
import bz2
import pickle
import _pickle as c_pickle
import os

BASE_PATH="/home/vivin/Projects/sandpuppy-paper"
colors = ['darkblue', 'darkgreen', 'olive', 'darkorchid', 'crimson']
labels = ['AFL', 'AFL++', 'AFL++ (LAFIntel)', 'AFL++ (RedQueen)', 'SandPuppy']


def set_axis_style(ax, labels):
    ax.xaxis.set_tick_params(direction='out')
    ax.xaxis.set_ticks_position('bottom')
    ax.set_xticks(np.arange(1, len(labels) + 1), labels=labels)
    ax.set_xlim(0.25, len(labels) + 0.75)
    ax.set_xlabel('Fuzzer', size=12)


def adjacent_values(vals, q1, q3):
    upper_adjacent_value = q3 + (q3 - q1) * 1.5
    upper_adjacent_value = np.clip(upper_adjacent_value, q3, vals[-1])

    lower_adjacent_value = q1 - (q3 - q1) * 1.5
    lower_adjacent_value = np.clip(lower_adjacent_value, vals[0], q1)
    return lower_adjacent_value, upper_adjacent_value


seq_size_counts = [
    [1, 516, 247, 207, 81, 47, 32, 32, 40, 42, 34, 20, 29, 24, 20, 21, 27, 32, 18, 18, 25, 13, 16, 18, 19, 8, 13, 14,
     12, 15, 16, 26, 27, 19, 9, 10, 3, 14, 5, 11, 7, 5, 9, 9, 5, 6, 9, 5, 4, 9, 9, 2, 2, 6, 6, 4, 1, 6, 4, 0, 2, 4, 6,
     14, 4, 5, 4, 3, 1, 3, 2, 1, 2, 2, 2, 2, 1, 2, 3, 2, 1, 1, 1, 4, 2, 3, 0, 0, 0, 3, 0, 2, 1, 2, 0, 0, 0, 1, 1, 0, 1,
     2, 2, 2, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [1, 526, 239, 254, 85, 57, 52, 46, 37, 43, 36, 31, 23, 21, 40, 34, 29, 44, 33, 28, 33, 40, 31, 33, 43, 28, 27, 21,
     35, 31, 32, 21, 22, 25, 13, 18, 14, 19, 11, 13, 7, 10, 15, 13, 13, 18, 9, 14, 10, 8, 10, 10, 11, 17, 8, 11, 4, 8,
     8, 5, 7, 10, 4, 21, 13, 14, 9, 4, 4, 9, 4, 5, 2, 3, 8, 6, 4, 4, 6, 5, 5, 3, 6, 7, 7, 5, 7, 2, 5, 2, 1, 3, 4, 3, 3,
     2, 1, 1, 0, 3, 1, 2, 7, 5, 0, 2, 2, 2, 4, 2, 7, 3, 1, 8, 3, 3, 3, 21, 2, 2, 2, 8, 5, 3, 4, 9, 3, 13, 26, 7, 3, 7,
     5, 7, 10, 5, 2, 1, 7, 1, 1, 1, 0, 21, 3, 14, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [1, 605, 336, 335, 108, 87, 50, 51, 38, 60, 32, 42, 31, 24, 32, 23, 16, 46, 24, 28, 34, 25, 17, 19, 24, 20, 17, 23,
     16, 25, 15, 13, 16, 23, 12, 18, 5, 13, 16, 9, 11, 14, 11, 13, 11, 12, 11, 9, 10, 14, 21, 2, 8, 10, 5, 6, 7, 4, 11,
     5, 1, 5, 3, 13, 6, 11, 9, 3, 5, 5, 4, 6, 6, 1, 7, 2, 1, 3, 4, 3, 3, 5, 5, 5, 12, 5, 2, 4, 5, 3, 3, 5, 2, 3, 0, 4,
     0, 0, 0, 0, 2, 0, 3, 0, 2, 0, 0, 1, 0, 0, 4, 2, 0, 0, 0, 0, 7, 3, 2, 1, 1, 15, 2, 4, 0, 2, 3, 4, 5, 4, 3, 0, 0, 1,
     0, 3, 0, 0, 0, 1, 2, 0, 0, 2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [1, 516, 217, 245, 77, 89, 66, 64, 48, 45, 35, 65, 36, 42, 36, 35, 48, 58, 55, 39, 60, 79, 55, 58, 49, 36, 32, 32,
     44, 44, 19, 32, 30, 23, 25, 34, 48, 38, 17, 31, 17, 19, 22, 24, 19, 23, 16, 17, 17, 12, 17, 10, 6, 9, 6, 8, 9, 2,
     8, 7, 7, 12, 15, 35, 27, 9, 3, 10, 4, 4, 6, 4, 7, 6, 7, 12, 9, 8, 11, 7, 10, 12, 4, 0, 11, 9, 6, 3, 3, 2, 6, 1, 2,
     4, 4, 5, 3, 3, 3, 5, 3, 3, 2, 6, 4, 0, 2, 2, 2, 0, 3, 11, 4, 2, 1, 3, 6, 16, 6, 4, 2, 5, 5, 2, 6, 0, 1, 6, 9, 3, 0,
     1, 7, 3, 5, 4, 6, 5, 8, 3, 4, 2, 1, 16, 3, 7, 0, 1, 0, 0, 2, 1, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 2, 1, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0],
    [1, 114597, 1485, 618, 401, 365, 278, 199, 141, 92, 55, 43, 56, 34, 37, 31, 35, 28, 20, 20, 21, 18, 29, 27, 30, 19,
     19, 15, 14, 11, 12, 35, 28, 19, 23, 21, 15, 13, 14, 20, 19, 12, 16, 9, 15, 10, 9, 11, 14, 13, 11, 8, 15, 7, 8, 10,
     5, 5, 6, 4, 2, 7, 9, 22, 7, 10, 4, 9, 3, 4, 5, 3, 4, 3, 5, 1, 3, 4, 5, 0, 1, 2, 2, 0, 1, 7, 3, 0, 0, 0, 0, 0, 1, 1,
     0, 0, 0, 0, 0, 0, 2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
]

fuzzer_seq_lengths = {}
if not os.path.isfile(f"{BASE_PATH}/fuzzer_seq_lengths-fullcmd.pbz2"):
    for i in range(0, len(seq_size_counts)):

        seq_sizes = []
        counts = seq_size_counts[i]
        for seq_length_idx in range(0, len(counts)):

            count = counts[seq_length_idx]
            for k in range(0, count):
                seq_sizes.append(seq_length_idx + 1)

        fuzzer_seq_lengths[labels[i]] = seq_sizes

    with bz2.BZ2File(f"{BASE_PATH}/fuzzer_seq_lengths-fullcmd.pbz2", "w") as f:
        c_pickle.dump(fuzzer_seq_lengths, f)
else:
    fuzzer_seq_lengths = bz2.BZ2File(f"{BASE_PATH}/fuzzer_seq_lengths-fullcmd.pbz2", "rb")
    fuzzer_seq_lengths = c_pickle.load(fuzzer_seq_lengths)

fig, ax = plt.subplots(figsize=(12, 8))
parts = ax.violinplot(
    fuzzer_seq_lengths,
    positions=[1, 2, 3, 4, 5],
    showmeans=False,
    showmedians=False,
    showextrema=True
)

quartiles1 = []
medians = []
quartiles3 = []
for i in range(0, len(labels)):
    body = parts['bodies'][i]
    body.set_facecolor(colors[i])
    body.set_edgecolor('black')
    body.set_alpha(0.75)

    quartile1, median, quartile3 = np.percentile(fuzzer_seq_lengths[i], [25, 50, 75])
    quartiles1.append(quartile1)
    medians.append(median)
    quartiles3.append(quartile3)

whiskers = np.array([
    adjacent_values(sorted_array, q1, q3)
    for sorted_array, q1, q3 in zip(fuzzer_seq_lengths, quartiles1, quartiles3)])
whiskers_min, whiskers_max = whiskers[:, 0], whiskers[:, 1]

inds = np.arange(1, len(medians) + 1)
ax.scatter(inds, medians, marker='o', color='white', s=30, zorder=3)
ax.vlines(inds, quartiles1, quartiles3, color='k', linestyle='-', lw=5)
ax.vlines(inds, whiskers_min, whiskers_max, color='k', linestyle='-', lw=1)

ax.set_ylabel("Sequence length", size=12)
ax.set_title('Distributions of lengths of unique sequences found', size=14)

set_axis_style(ax, labels)

plt.tight_layout()
plt.savefig(
    "/home/vivin/Projects/sandpuppy-paper/command_seq_size_counts_diverse_inputs_equal_compute_violin-fullcmd.png",
    bbox_inches="tight"
)

