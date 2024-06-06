import subprocess


def out(m, deviate=False):
    print(m)
    if deviate:
        subprocess.call("ps")

