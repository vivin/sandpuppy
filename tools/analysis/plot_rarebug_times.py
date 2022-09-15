import matplotlib.pyplot as plt
import numpy as np

plt.rcParams["font.family"] = "Times New Roman"

X = [1, 2, 3, 4, 5]
solution_times = [
    [0, 235.63, 931.92, 0, 0],
    [0, 0, 0, 0, 0],
    [0, 0, 0, 28.73, 23.12],
    [920.42, 1361.3, 141.18, 960.08, 0],
    [73.48, 88.55, 127.12, 60.13, 64.52]
]

X_axis = np.arange(len(X))

fig, ax = plt.subplots(nrows=1, ncols=1)
fig.set_size_inches(9, 4.5)

colors = ['darkblue', 'darkgreen', 'darkorchid', 'olive', 'crimson']
labels = ['AFL', 'AFL++', 'AFL++ (RedQueen)', 'AFL++ (LAFIntel)', 'SandPuppy']

ax.bar(X_axis - 0.2, solution_times[0], 0.1, color=colors[0], label=labels[0])
ax.bar(X_axis - 0.1, solution_times[1], 0.1, color=colors[1], label=labels[1])
ax.bar(X_axis, solution_times[2], 0.1, color=colors[2], label=labels[2])
ax.bar(X_axis + 0.1, solution_times[3], 0.1, color=colors[3], label=labels[3])
ax.bar(X_axis + 0.2, solution_times[4], 0.1, color=colors[4], label=labels[4])

ax.tick_params(axis='both', labelsize=16)
ax.set_xticks(X_axis, X)
ax.set_xlabel("Runs", size=18)
ax.set_ylabel("Solution times in minutes", size=18)
#ax.set_title('Evaluation of Rarebug', size=18)
ax.set_ylim([0, 1400])
ax.legend(fontsize=12)

fig.tight_layout()
plt.subplots_adjust(top=0.985, left=0.095, bottom=0.12)
plt.savefig("/home/vivin/Projects/sandpuppy-paper/rarebug_solution_times.png")
#plt.show()