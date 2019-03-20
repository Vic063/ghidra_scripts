# Import a Linux kallsyms kernel file
# @category: Linux
# @author: Vico <biche@biche.re>

import sys
from ghidra.util.exception import CancelledException

f = None
try:
    f = askFile("kallsyms importer", "Import")
except CancelledException as e:
    print 'Cancelled importation'
    sys.exit(0)

num_lines = sum(1 for line in file(f.absolutePath))
monitor.initialize(num_lines)

for entry in file(f.absolutePath):
    addr = toAddr(entry.split()[0])
    name = entry.split()[2]

    monitor.checkCanceled() # check to see if the user clicked cancel

    # Check if a function already exists at this address
    func = getFunctionAt(addr)
    if func is not None:
        try:
            func.setName(name, None)
        except:
            # An exception is always triggered when the name is changed, so we don't care...
            pass
    else:
        createFunction(addr, name)

    monitor.incrementProgress(1) # update the progress
    monitor.setMessage("Kallsyming 0x{0}".format(addr)) # update the status message
