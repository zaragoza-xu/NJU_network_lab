import matplotlib.pyplot as plt

# --- 配置 ---
data_file = "cwnd.txt"  # cwnd 数据文件名
time_unit_divisor = 1000  # 将时间单位从 us 转换为 ms (1000) 或 s (1000000)
time_unit_label = "ms"   # 时间轴标签单位 ('us', 'ms', 's')
# ------------

times = []
cwnds = []
ssthreshs = []
# adv_wnds = [] # 如果需要绘制 adv_wnd，取消注释

try:
    with open(data_file, 'r') as f:
        for line in f:
            try:
                parts = line.strip().split()
                if len(parts) >= 3: # 确保至少有时间和cwnd, ssthresh
                    time_us = int(parts[0])
                    cwnd = int(parts[1])
                    ssthresh = int(parts[2])
                    # adv_wnd = int(parts[3]) # 如果需要绘制 adv_wnd

                    times.append(time_us / time_unit_divisor)
                    cwnds.append(cwnd)
                    ssthreshs.append(ssthresh)
                    # adv_wnds.append(adv_wnd) # 如果需要绘制 adv_wnd
            except ValueError:
                print(f"Skipping invalid line: {line.strip()}")
            except IndexError:
                 print(f"Skipping incomplete line: {line.strip()}")


    if not times:
        print(f"Error: No valid data found in {data_file}")
    else:
        plt.figure(figsize=(12, 6)) # 创建图形

        # 绘制 cwnd
        plt.plot(times, cwnds, label='cwnd', color='blue', linewidth=1.5)

        # 绘制 ssthresh
        plt.plot(times, ssthreshs, label='ssthresh', color='red', linestyle='--', linewidth=1)

        # 绘制 adv_wnd (可选)
        # plt.plot(times, adv_wnds, label='adv_wnd', color='green', linestyle=':', linewidth=1)

        # 添加标题和标签
        plt.title('TCP NewReno Congestion Window Evolution')
        plt.xlabel(f'Time ({time_unit_label})')
        plt.ylabel('Window Size (Bytes)')

        # 添加图例
        plt.legend()

        # 添加网格
        plt.grid(True, linestyle='--', alpha=0.6)

        # 显示图形
        plt.tight_layout() # 调整布局防止标签重叠
        plt.savefig("cwnd.png")

except FileNotFoundError:
    print(f"Error: Data file '{data_file}' not found.")
except Exception as e:
    print(f"An unexpected error occurred: {e}")
