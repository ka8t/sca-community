# CLEAN: Safe subprocess usage without shell injection
# Expected: Should NOT trigger "Entrée non validée" detection

import subprocess

def run_command(args_list):
    subprocess.call(args_list, shell=False)

def read_file(filename):
    subprocess.Popen(["cat", filename], shell=False)
