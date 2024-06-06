from collections import defaultdict

import plotly.graph_objects as go
import pandas as pd
import re


def extract_package(path):
    parts = path.split('/')
    if 'site-packages' in parts:
        idx = parts.index('site-packages') + 1
        package = parts[idx]
    elif 'Lib' in parts:
        idx = parts.index('Lib') + 1
        package = parts[idx]
    else:
        package = parts[1] if len(parts) > 1 else parts[0]
    return package


def parse_syscall_names(filepath):
    syscall_names = {}
    pattern = re.compile(r'@sysname\[(\d+)\] = "(.*?)"')
    with open(filepath, 'r') as file:
        for line in file:
            match = pattern.search(line)
            if match:
                number, name = match.groups()
                syscall_names[int(number)] = name
    return syscall_names


syscall_name_filepath = 'syscall_mapping.log'
syscall_names = parse_syscall_names(syscall_name_filepath)


def parse_log_file(filepath):
    packages_syscalls = defaultdict(lambda: defaultdict(int))
    pattern = re.compile(r'@syscalls\[(.*?), (\d+)\]: (\d+)')
    with open(filepath, 'r') as file:
        for line in file:
            match = pattern.search(line)
            if match:
                module, syscall, count = match.groups()
                package = extract_package(module)
                syscall, count = int(syscall), int(count)
                packages_syscalls[package][syscall] += count
    return packages_syscalls


log_filepath = 'syscall_per_module.log'
packages_syscalls = parse_log_file(log_filepath)

packages = sorted(packages_syscalls.keys())
syscalls = sorted(set(sys for scs in packages_syscalls.values() for sys in scs))
syscall_labels = [syscall_names.get(sc, f"Unknown Syscall {sc}") for sc in syscalls]
matrix = pd.DataFrame(0, index=packages, columns=syscall_labels)

for pkg, scs in packages_syscalls.items():
    for sc, count in scs.items():
        label = syscall_names.get(sc, f"Unknown Syscall {sc}")
        matrix.at[pkg, label] = count

colorscale = [
    [0, 'white'],
    [1.0 / matrix.max().max(), 'yellow'],
    [1, 'red']
]

fig = go.Figure(data=go.Heatmap(
    z=matrix.values,
    x=matrix.columns,
    y=matrix.index,
    colorscale=colorscale,
    zmin=0,
    zmax=matrix.max().max()
))

fig.update_layout(
    title='Package to Syscall Matrix',
    xaxis_nticks=50,
    yaxis_nticks=50,
    xaxis_title="Syscalls",
    yaxis_title="Packages",
    xaxis=dict(tickmode='array', tickvals=list(range(len(syscall_labels))), ticktext=syscall_labels, tickangle=-45),
    yaxis=dict(tickmode='array', tickvals=list(range(len(packages))), ticktext=packages)
)


fig_width = max(1000, len(syscall_labels) * 100)
fig_height = max(1000, len(packages) * 30)
left_margin = max(100, len(packages) * 0.3)

fig.update_layout(
    autosize=False,
    width=fig_width,
    height=fig_height,
    margin=dict(l=left_margin, r=50, b=100, t=100, pad=4),
    paper_bgcolor="LightSteelBlue",
)

fig.show()
