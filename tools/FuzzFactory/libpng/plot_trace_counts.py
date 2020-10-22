import matplotlib.pyplot as plt
import pandas as pd
import sys

if len(sys.argv) < 2:
    print("version must be provided")
    exit(1)

version = sys.argv[1]
df = pd.read_csv("trace-length-{version}.csv".format(**locals()))
df.head()

fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 9))

x1 = df.loc[df.waypoint == "plain", "calls"]
x2 = df.loc[df.waypoint == "heap", "calls"]
x3 = df.loc[df.waypoint == "heap2", "calls"]
x4 = df.loc[df.waypoint == "heap3", "calls"]

kwargs = dict(alpha=0.5, bins=50)

ax1.hist(x1, **kwargs, color='r', label='plain')
ax2.hist(x2, **kwargs, color='g', label='heap')
ax3.hist(x3, **kwargs, color='b', label='heap2')
ax4.hist(x4, **kwargs, color='y', label='heap3')

ax1.legend()
ax2.legend()
ax3.legend()
ax4.legend()

fig.suptitle("Frequency histogram of trace lengths")
plt.savefig("trace-length-{version}.png".format(**locals()))
