import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
import json

from matplotlib.colors import LogNorm

run_labels = ["hash", "perm", "max", "max2", "-hash", "-perm", "-max", "-max2", "random", "original"]
with open("/mnt/vivin-nfs/vivin/smartdsf/libpng-1.5.9/results/feedback/coverage_map.json", "r") as f:
    coverage_map = json.load(f)

labels = ['AFL', 'AFL++', 'AFL++ (LAFIntel)', 'AFL++ (RedQueen)', 'SandPuppy']

print("Generating coverage heatmap")

df = pd.DataFrame.from_dict(coverage_map)
df = df.reindex(columns=['hash', 'perm', 'max', 'max2', '-hash', '-perm', '-max', '-max2', 'random', 'original'])
df = df.transpose()
#with pd.option_context('display.max_rows', None, 'display.max_columns', 200):  # more options can be specified also
#    print(df)

#sns.set(font="Times New Roman", font_scale=2)
plt.subplots(figsize=(16, 8))
ax = sns.heatmap(
    df,
    norm=LogNorm(),
    cmap='crest',
    cbar_kws={'label': 'Basic block covered'}
    #xticklabels=10,
    #yticklabels=9
)
#ax.invert_yaxis()
ax.set_xlabel("Basic blocks")#, size=24)
ax.set_ylabel("Run")#, size=24)
ax.set_title("Coverage heatmap", size=24)
ax.set_yticklabels(ax.get_yticklabels(), rotation=0)

ax.hlines([1, 2, 3, 4, 5, 6, 7, 8, 9], 0, ax.get_xlim()[1], color="lightgray", zorder=-1)
for _, spine in ax.spines.items():
    spine.set_visible(True)
#plt.subplots_adjust(left=0.1075, right=1, bottom=0.0975, top=0.9)
#plt.tight_layout()
plt.savefig("/home/vivin/Projects/sandpuppy-paper/coverage_heatmap.png")

plt.clf()

