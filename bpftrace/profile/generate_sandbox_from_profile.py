profile_file_path = 'trace.log'
template_file_path = 'template.bt'

syscalls = []
supervised_modules = set()
trusted_modules = []


def contains_trusted_module(line_, trusted_modules_):
    return any(module_ in line_ for module_ in trusted_modules_)


with open(profile_file_path, 'r') as file:
    lines = file.readlines()
    for line in lines:
        if line.startswith('@syscalls') and 'site-packages' in line and not contains_trusted_module(line,
                                                                                                    trusted_modules):
            parts = line.split(':')
            module_info = parts[0].split('[')[1].split(',')
            module = module_info[0].strip()
            syscall_id = int(module_info[1].strip(']').strip())
            syscalls.append((module, syscall_id))
            supervised_modules.add(module)

syscalls.sort(key=lambda x: x[0])
supervised_modules_str = "\n".join(f'    	@supervised_modules["{module}"] = 1;' for module in supervised_modules)
allowed_syscalls_str = "\n".join(
    f'    	@allowed_syscalls["{syscall[0]}", {syscall[1]}] = 1;' for syscall in syscalls)

with open(template_file_path, 'r') as file:
    content = file.read()
    content = content.replace('{{supervised_modules}}', supervised_modules_str)
    content = content.replace('{{allowed_syscalls}}', allowed_syscalls_str)

with open('../sandbox/generated_sandbox.bt', 'w') as file:
    file.write(content)
