## lgvtotal.py `[`-h`]` `[`-d loglevel`]` `[`--help`]` `[`--debug=loglevel`]` `[`directory`]` `[`filename`]`... ##

### -h --help ###
> Produce this help message.

### -l loglevel --log=loglevel ###

> Specify the level of logging:
> > debug, info, warning, error, critical.

> Logging is to standard output.

### -r --restart ###

> Restart execution from last checkpoint. Do not specify
> directories if you are doing a restart. Execution will
> continue with last set of directories / files being
> processed.

> The history file is named lgvtotal.pkl and is located in
> the working directory. It is reused for each execution.

> Results are kept in the history file. Doing a restart
> once all processing is done will print out all results.

### -a --noscan ###
> Submit files directly without first checking if there is
> already a report at VirusTotal.

> If Volatility memory samples are being submitted, it is
> not likely that VirusTotal will have these already on
> record. So it is faster just to submit for scanning
> without trying to retrieve the corresponding report.

> (Default action) For normal operation (ie scanning executables stored on
> disk), VirusTotal likely has already seen the file. So
> first the pgm tries to retrieve the corresponding
> file. If not found, then the file is submitted for
> scanning.

### directory, filename ###

> Specify list of directories and / or individual files to
> be submitted to VirusTotal. If a directory is specified,
> note that all its subdirectories will be processed as
> well.

# Examples #

### Scan a single file: ###

> python lgvtotal.py myfile.exe

### Scan two directories containing samples of executables extracted by Volatility from volatile memory: ###

> python lgvtotal.py -k ~/tmp/volatility\_results/exec\_dirs`*`

### Do a restart: ###

> cd my\_working\_directory\_for\_the\_previous\_execution
> python lgvtotal.py --restart

### Debug output: ###
> python lgvtotal.py -l "debug"

### Scan a list of filenames: ###
> cat my\_file\_list | xargs python lgvtotal.py