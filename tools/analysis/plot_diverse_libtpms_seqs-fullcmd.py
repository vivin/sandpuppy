import matplotlib.pyplot as plt
import numpy as np
import matplotlib.gridspec as gridspec

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
X_axis = np.arange(1, 196, 1)

gs = gridspec.GridSpec(3, 4)
ax0 = plt.subplot(gs[0, 0:2])
ax1 = plt.subplot(gs[0, 2:])
ax2 = plt.subplot(gs[1, 0:2])
ax3 = plt.subplot(gs[1, 2:])
ax4 = plt.subplot(gs[2, 1:3])

fig = plt.gcf()
fig.set_size_inches(16, 7)

colors = ['darkblue', 'darkgreen', 'olive', 'darkorchid', 'crimson']
labels = ['AFL', 'AFL++', 'AFL++ (LAFIntel)', 'AFL++ (RedQueen)', 'SandPuppy']

ax0.bar(X_axis, seq_size_counts[0], color=colors[0], log=False)
ax0.set_xlabel("Command sequence lengths", size=12)
ax0.set_ylabel("Count", size=12)
ax0.set_title('Histogram of command-sequence lengths with parameter size for AFL', size=14)
ax0.set_ylim([0, 630])

ax1.bar(X_axis, seq_size_counts[1], color=colors[1], log=False)
ax1.set_xlabel("Command sequence lengths", size=12)
ax1.set_ylabel("Count", size=12)
ax1.set_title('Histogram of command-sequence lengths with parameter size for AFL++', size=14)
ax1.set_ylim([0, 630])

ax2.bar(X_axis, seq_size_counts[2], color=colors[2], log=False)
ax2.set_xlabel("Command sequence lengths", size=12)
ax2.set_ylabel("Count", size=12)
ax2.set_title('Histogram of command-sequence lengths with parameter size for AFL++ (LAFIntel)', size=14)
ax2.set_ylim([0, 630])

ax3.bar(X_axis, seq_size_counts[3], color=colors[3], log=False)
ax3.set_xlabel("Command sequence lengths", size=12)
ax3.set_ylabel("Count", size=12)
ax3.set_title('Histogram of command-sequence lengths with parameter size for AFL++ (RedQueen)', size=14)
ax3.set_ylim([0, 630])

ax4.bar(X_axis, seq_size_counts[4], color=colors[4], log=False)
ax4.set_xlabel("Command sequence lengths", size=12)
ax4.set_ylabel("Count", size=12)
ax4.set_title('Histogram of command-sequence lengths with parameter size for SandPuppy', size=14)
ax4.set_yscale('log')

gs.tight_layout(fig)
plt.subplots_adjust(bottom=0.11, top=0.945)
plt.savefig("/home/vivin/Projects/sandpuppy-paper/command_seq_size_counts_diverse_inputs_equal_compute_fullcmd.png")
