## Introduction ##

The VirusTotal Public API is quite constrained. So execution times can be long if there are a number of files to scan.

If there are problems, the lgvtotal checkpoint function provides an easy way to restart from (near) the point of termination.

## Quick howto ##

To restart execution, you need to be in the same directory as the previous run.

Then:
> _python lgvtotal.py --restart_

## Technical details ##

The code writes the main worker object in stream format to a file located in the current working directory:  _lgvtotal.pkl_

The contents of this file are read and used to reinitialize the objects in order to continue execution.

## Important things to note ##

> `*` There is only 1 copy of the checkpoint file kept (in the working directory). When execution restarts, it reuses the same file to record ongoing state.

> `*` At the end of execution, when all files have been scanned, be sure to keep a copy of the lgvtotal.pkl file handy somewhere. Doing a restart run will print out a fresh copy of the summary report (with all the Virustotal scan results).