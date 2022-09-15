import matplotlib.pyplot as plt
import numpy as np


seq_size_counts = [
    [1, 58, 6, 11, 5, 4, 4, 6, 2, 4, 3, 4, 4, 4, 3, 8, 4, 5, 7, 5, 3, 3, 2, 2, 2, 3, 2, 3, 4, 0, 2, 4, 2, 2, 1, 3, 7, 7,
     4, 1, 1, 5, 3, 6, 1, 3, 2, 1, 0, 0, 2, 4, 1, 0, 1, 2, 1, 0, 1, 3, 0, 1, 2, 2, 3, 2, 0, 1, 1, 1, 0, 0, 3, 2, 1, 0,
     2, 1, 0, 0, 2, 1, 0, 1, 3, 3, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0,
     0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 2, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0],
    [1, 101, 93, 156, 257, 321, 317, 336, 248, 194, 134, 131, 123, 104, 93, 87, 64, 76, 55, 47, 53, 36, 54, 45, 50, 38,
     37, 30, 26, 33, 29, 51, 38, 18, 36, 18, 16, 19, 28, 24, 15, 22, 20, 18, 15, 14, 15, 10, 14, 15, 24, 16, 10, 14, 11,
     5, 8, 13, 7, 5, 8, 8, 11, 25, 23, 6, 9, 8, 5, 6, 4, 5, 5, 4, 6, 5, 4, 5, 5, 4, 9, 3, 1, 0, 6, 5, 4, 0, 2, 0, 0, 2,
     1, 3, 3, 1, 1, 1, 0, 6, 5, 1, 5, 0, 0, 2, 0, 4, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 3, 10, 0, 1,
     0, 1, 0, 0, 2, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 1,
     0, 0, 1]
]

X_axis = np.arange(1, 172, 1)

fig, (ax0, ax1) = plt.subplots(nrows=2, ncols=1)
fig.set_size_inches(9, 4.5)

colors = ['darkblue', 'crimson']
labels = ['AFL++ (LAFIntel)', 'SandPuppy']

ax0.bar(X_axis, seq_size_counts[0], color=colors[0], log=False)
#ax0.set_xticks(X_axis)
ax0.set_xlabel("Command sequence lengths", size=12)
ax0.set_ylabel("Count", size=12)
ax0.set_title('Histogram of command sequence lengths for AFL++ (LAFIntel)', size=14)

ax1.bar(X_axis, seq_size_counts[1], color=colors[1], log=False)
#ax1.set_xticks(X_axis)
ax1.set_xlabel("Command sequence lengths", size=12)
ax1.set_ylabel("Count", size=12)
ax1.set_title('Histogram of command sequence lengths for SandPuppy', size=14)


fig.tight_layout()
plt.subplots_adjust(bottom=0.11, top=0.945)
plt.savefig("/home/vivin/Projects/sandpuppy-paper/command_seq_size_counts.png")
#plt.show()