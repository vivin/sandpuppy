import matplotlib.pyplot as plt
import numpy as np

plt.rcParams["font.family"] = "Times New Roman"

X = [1, 2, 3, 4, 5]
solution_times = [
    [2.23, 2.38, 1.90, 1.55, 1.90],
    [11.65, 7.50, 6.75, 21.88, 18.02],
    [8.38, 3.45, 7.57, 1.60, 4.82],
    [7.00, 4.18, 4.60, 5.32, 4.95],
    [0.48, 0.63, 0.65, 0.47, 0.48]
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
#ax.set_title('Evaluation of Rarebug (diverse seeds and equal compute)', size=18)
ax.set_ylim([0, 25])
ax.legend(fontsize=12)

fig.tight_layout()
plt.subplots_adjust(top=0.985, left=0.07, bottom=0.12)
plt.savefig("/home/vivin/Projects/sandpuppy-paper/rarebug_diverse_seeds_equal_compute_solution_times.png")
#plt.show()