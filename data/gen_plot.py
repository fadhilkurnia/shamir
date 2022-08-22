import matplotlib.pyplot as plt
import numpy as np
import random
import pandas as pd
import scipy as sp
from sklearn.linear_model import LinearRegression
from mpl_toolkits.axes_grid1.inset_locator import zoomed_inset_axes
from mpl_toolkits.axes_grid1.inset_locator import mark_inset
from scipy.optimize import curve_fit

data = pd.read_csv('proc_time_randomizer.csv')
data_algos = [x for _,x in data.groupby('algo')]
data_shamir = data_algos[0][:600]
data_ssms = data_algos[1][:600]

sizes = data_shamir.iloc[:,1]/1000
proc_time_shamir_avg = data_shamir.iloc[:,2]
proc_time_shamir_std_dev = data_shamir.iloc[:,4]
proc_time_ssms_avg = data_ssms.iloc[:,2]
proc_time_ssms_std_dev = data_ssms.iloc[:,4]

fig, ax = plt.subplots()
fig.set_size_inches(5, 3)

ax.plot(sizes, proc_time_shamir_avg, label='Shamir', color='#ff7f0e')
ax.fill_between(sizes, proc_time_shamir_avg-proc_time_shamir_std_dev, proc_time_shamir_avg+proc_time_shamir_std_dev, facecolor='#ff7f0e', alpha=0.5)
ax.plot(sizes, proc_time_ssms_avg, label='SSMS', color='#2ca02c')
ax.fill_between(sizes, proc_time_ssms_avg-proc_time_ssms_std_dev, proc_time_ssms_avg+proc_time_ssms_std_dev, facecolor='#2ca02c', alpha=0.5)
ax.grid()
ax.set_ylabel('Avg latency (ms)')
ax.set_xlabel('Secret size (KB)')
ax.legend(loc='lower right')

# set x and y limit
x_max = sizes.max()
y_max = max(proc_time_shamir_avg.max(), 0)
ax.set_xlim([0, x_max])
ax.set_ylim([0, y_max])

# Make the zoom-in plot:
axins = ax.inset_axes([0.03, 0.57, 0.40, 0.40])
axins.plot(sizes, proc_time_shamir_avg, label='shamir', color='#ff7f0e')
axins.fill_between(sizes, proc_time_shamir_avg-proc_time_shamir_std_dev, proc_time_shamir_avg+proc_time_shamir_std_dev, facecolor='#ff7f0e', alpha=0.5)
axins.plot(sizes, proc_time_ssms_avg, label='ssms', color='#2ca02c')
axins.fill_between(sizes, proc_time_ssms_avg-proc_time_ssms_std_dev, proc_time_ssms_avg+proc_time_ssms_std_dev, facecolor='#2ca02c', alpha=0.5)
axins.set_xlim(0.001, 1.49)
axins.set_ylim(0.0, 0.026)
axins.get_yaxis().set_visible(False)
axins.grid()
ax.indicate_inset_zoom(axins, edgecolor="black")

fig.savefig('ss_latency.png', bbox_inches='tight')