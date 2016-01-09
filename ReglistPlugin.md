## Introduction ##

This plugin lists registry keys from the various hives in memory. It is a port of Regripper to python specifically for Volatility 1.4


## Details ##

Install the plugin by copying it to:

> `my_src_lib/Volatility-1.4_rc1/volatility/plugins/registry/`

Plugin-specific parameters:

```
-o HIVE_OFFSET, --hive-offset=HIVE_OFFSET
```

This is the virtual (not physical) offset of a hive in memory. Normally this value would be obtained from the hivescan.py plugin.

This can be used to save time by focusing on a specific hive of interest.

Default is to find all the hives in memory and process them.

When this option is specified, the hive name is "user specified".

```
-H HIVE_NAME, --hive-name=HIVE_NAME
```

Name of a specific hive to process. All the checks for this hive will be run against the hive. The other hives will not be processed.

Hive names are:

  * system
  * ntuser.dat
  * software

All of the ntuser.dat hives will be found and processed.

Hives that are "`[no name]`" or "`user specified`" will have all possible checks run against them (since the actual hive contents cannot be determined with precision).

```
-C CHK, --chk=CHK
```

This is the name of a specific check to perform. The old Regripper plugin names were kept (insofar as possible).

The names of the actual checks can be found by looking at the source code (at the beginning).

The plugin will determine which hive a check targets, and will only process those specific hives (as well as the "unknown" hives).


## Performance ##

Generally the plugin is reasonably fast. However the "assoc" check (list all file associations) is slow. This is especially true on Win7.

## OS Support ##

Note that the plugin supports XP, and Win7 only. It has not been tested on other versions of Windows, but may function at least partially.

## Credits ##

Special thanks to the Regripper people (Harlan Carvey, Brendan Coles) who kindly gave permission to use their code as a basis for this plugin. Also the authors of the prtkey.py plugin (AAron Walters and Brendan Dolan-Gavitt) which was adapted to produce reglist.py.