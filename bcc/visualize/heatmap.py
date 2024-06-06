import pandas as pd
import plotly.graph_objects as go


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


data = pd.read_csv('../profile/syscall_data.csv')
data['Package'] = data['Module'].apply(extract_package)
package_syscall_matrix = data.groupby(['Package', 'SysCall Name'])['Count'].sum().unstack(fill_value=0)

num_packages = len(package_syscall_matrix.index)
num_syscalls = len(package_syscall_matrix.columns)
width_per_syscall = 100
height_per_package = 30

colorscale = [
    [0, 'white'],
    [1.0 / package_syscall_matrix.max().max(), 'yellow'],
    [1, 'red']
]

fig = go.Figure(data=go.Heatmap(
    z=package_syscall_matrix.values,
    x=package_syscall_matrix.columns,
    y=package_syscall_matrix.index,
    colorscale=colorscale,
    zmin=0,
    zmax=package_syscall_matrix.max().max()
))

# Update layout for better readability
fig.update_layout(
    title='Package to Syscall Matrix',
    xaxis_nticks=50,
    yaxis_nticks=50,
    xaxis_title="Syscalls",
    yaxis_title="Packages",
    xaxis=dict(tickmode='array', tickvals=list(range(num_syscalls)), ticktext=package_syscall_matrix.columns,
               tickangle=-45),
    yaxis=dict(tickmode='array', tickvals=list(range(num_packages)), ticktext=package_syscall_matrix.index)
)

fig_width = max(1000, num_syscalls * width_per_syscall)
fig_height = max(1000, num_packages * height_per_package)
left_margin = max(100, num_packages * 0.3)

fig.update_layout(
    autosize=False,
    width=fig_width,
    height=fig_height,
    margin=dict(l=left_margin, r=50, b=100, t=100, pad=4),
    paper_bgcolor="LightSteelBlue",
)

fig.show()
