import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

data = pd.read_csv('proc_time_randomizer.csv')

algorithms = ['rsa', 'shamir', 'ssms', 'aes256']
algolabel = ['RSA', 'Shamir', 'SSMS', 'AES']

for i, algo in enumerate(algorithms):
    algo_data = data[(data['algo'] == algo)]
    x = algo_data['size(bytes)']
    y = algo_data['avg_proc_time(ms)']
    stddev = algo_data['std_dev(ms)']
    plt.plot(x, y, label=algolabel[i])
    plt.fill_between(x, y-stddev, y+stddev, alpha=0.2)

# TODO: make the zoom-in plot

plt.legend()
plt.grid()
plt.xlim(left=0, right=10000)
plt.ylim(bottom=0, top=0.2)
plt.show()