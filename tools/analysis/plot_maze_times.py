import matplotlib.pyplot as plt
import numpy as np


X = [1, 2, 3, 4, 5]
klee_times = [
    [11.6, 28.67, 22.97, 51.13, 38.97],
    [0, 814.6, 0, 0, 970.37]
]
ijon_times = [
    [395.35, 270, 310.67, 229.92, 168.17],
    [0, 0, 0, 0, 0]
]
sandpuppy_times = [
    [278.12, 689.35, 1178.77, 202.13, 231.3],
    [0, 0, 0, 0, 0]
]

X_axis = np.arange(len(X))

fig, (ax0, ax1, ax2) = plt.subplots(nrows=1, ncols=3)
fig.set_size_inches(12, 4)

colors = ['crimson', 'darkblue']
labels = ['SandPuppy', 'AFL']

bar1 = ax0.bar(X_axis - 0.2, klee_times[0], 0.4, color=colors[0], label=labels[0])
bar2 = ax0.bar(X_axis + 0.2, klee_times[1], 0.4, color=colors[1], label=labels[1])
ax0.set_xticks(X_axis, X)
ax0.set_xlabel("Runs", size=10)
ax0.set_ylabel("Solution times in minutes", size=10)
ax0.set_title('KLEE Maze', size=12)
ax0.set_ylim([0, 1200])
ax0.legend()
#ax0.bar_label(bar1, padding=3)
#ax0.bar_label(bar2, padding=3)

bar3 = ax1.bar(X_axis - 0.2, ijon_times[0], 0.4, color=colors[0], label=labels[0])
bar4 = ax1.bar(X_axis + 0.2, ijon_times[1], 0.4, color=colors[1], label=labels[1])
ax1.set_xticks(X_axis, X)
ax1.set_xlabel("Runs", size=10)
ax1.set_ylabel("Solution times in minutes", size=10)
ax1.set_title('IJON Maze', size=12)
ax1.set_ylim([0, 1200])
ax1.legend()
#ax1.bar_label(bar3, padding=3)
#ax1.bar_label(bar4, padding=3)

bar5 = ax2.bar(X_axis - 0.2, sandpuppy_times[0], 0.4, color=colors[0], label=labels[0])
bar6 = ax2.bar(X_axis + 0.2, sandpuppy_times[1], 0.4, color=colors[1], label=labels[1])
ax2.set_xticks(X_axis, X)
ax2.set_xlabel("Runs", size=10)
ax2.set_ylabel("Solution times in minutes", size=10)
ax2.set_title('SandPuppy Maze', size=12)
ax2.set_ylim([0, 1200])
ax2.legend()
#ax2.bar_label(bar5, padding=3)
#ax2.bar_label(bar6, padding=3)

fig.tight_layout()
plt.subplots_adjust(bottom=0.1, left=0.055, right=0.995)
plt.savefig("/home/vivin/Projects/sandpuppy-paper/maze_solution_times.png")
#plt.show()