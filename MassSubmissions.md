## Introduction ##

This article describes how to speed up mass submissions (ie 200-300+ modules at a time) for things like module samples extracted by the Volatility memory forensics tool.

## Details ##

The information contained here represents wisdom gained at time of writing (2010-12-04). YMMV

If you are submitting a big batch of executables for scanning (say 200-300+ samples from a forensics investigation), then here are some tricks that might help things go faster and better.

### When to use the "-a" parameter ###

First of all, you might consider using the "-a" parameter to speed up submissions.

This was added specifically for memory forensics use. A tool such as Volatility can extract modules from memory for scanning. But it turns out that the module in memory is never exactly the same as the PE file on disk (obviously). So the checksums never match and a fresh scan is always required. Therefore, it makes no sense to check if VirusTotal already has seen the checksum before submitting the module for scanning.

The "-a" parameter has the effect of submitting without asking first. The result is that 20 modules are submitted per 5 min window instead of 10. (The default action is to ask before submitting, which means that it takes 2 requests / module submitted).

### Side-effects of "-a" parameter use ###

When processing a sizeable batch (say 200-300 executables), then sometimes VirusTotal will start giving back errors systematically. lgvtotal.py wil then retry the same module repeatedly before finishing with an error. The next module is processed, and the same cycle repeats itself.

When this happens, the best thing to do is just ctl-c / stop the execution of lgvtotal.py for a while. Let VirusTotal's queues empty themselves.

Next start a fresh execution _without specifying "-a"_. This has the effect of trying to resubmit all the modules. But the program will now ask before submitting. However since in fact all the modules have _already been submitted_, the result comes back from VirusTotal immediately. This means that you get 20 results back / 5 min window.

### Getting a decent report ###

One way to get a decent report is to use "screen" on Ubuntu. Once the execution is finished, and all the results are in from VirusTotal, then:

```
   cd directory-where-lgvtotal.py lives
   screen -D -RL
   python lgvtotal.py -r
   ctl-D
```

The output is screenlog.0 which can be renamed appropriately. I also keep a copy of the checkpoint file lgvtotal.pkl just in case.