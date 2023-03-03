# Wojtek's WFPFirewall
_Manage your network in cumbersome and inefficient way!_

WFPFirewall is a rule-based firewall that allows for traffic shaping in one of the following ways:
- allow for a TCP connection to a given IP address range over a specified amount of time
- allow for a specified amount of data to be downloaded from a a given IP address range _**(experimental, see below)**_

after the specified limit is reached - the connection is blocked.

## System requirements

The project was created and tested on Windows 11. The WFP API used under the hood requires Windows Vista at minimum,
so there is a high chance it will work on older Windows releases as well.

To use the data limit feature, you either need to sign the driver yourself, or you need to turn drivers signature
check off. The 2nd option is dangerous and I highly discourage you to do this on your daily machine.

## Building

The project is delivered in the form of a Visual Studio solution. The easiest way to build it to an executable form
is to open the `.sln` file in Visual Studio and select `Build -> Build Solution`.

There are also some unit tests. Feel free to explore them with `Test -> Test Explorer`.

You can also use a pre-built release - check the [Releases](https://github.com/wzmuda/WFPFirewall/releases) section of the repository.

## Usage
### Rules file
Wojtek's WFPFirewall can be programmed using a rules file. As for today, the file must be named `wfpfirewall.cfg` and must be placed
alongside the program executable. The file is picked up automatically.

Rules placed in the rules file must conform to the following format:
```
<ipv4>:<port> <value><unit>
<ipv4>/<cidr> <value><unit>
```
where `<value>` is the amount of data or the amount of time the connection will be valid for and `<unit>` is:
- for time limit one of: `s` for seconds, `m` for minutes, `h` for hours
- for data limit one of: `B` for bytes, `kB` for kilobytes, `MB` for megabytes and `GB` for gigabytes.

Example rules:
```
0.0.0.0/0 10s
80.249.99.148/32 11MB
67.222.248.143:4287 2m
```

The above rules would translate to:
```
Connect to any other site using TCP connection for maximum of 10 seconds
Download maximum 11 megabytes of data from `80.249.99.148/32`
Connect to `67.222.248.143:4287` using TCP connection for maximum of 2 minutes
```

### Running the program
#### Data limit filter
To use data limit filters, a kernel module is necessary. If you plan to use only the time-based filtering, you may skip
this paragraph.

The kernel module is `KWFPFirewall.sys` along with the corresponding `.inf` and `.cat` files. They are the result of
the build and they're also included in the [GitHub release](https://github.com/wzmuda/WFPFirewall/releases).

If you build the module yourself, you need to sign it on your own with key enrolled to your Windows key store. Otherwise
the system will not let you install the module. The pre-built module included in the release is also not signed.

An alternative way would be to **turn off signature verification**. This can lead to your system being compromised, so you
do it at your own risk.

1. Right-click on the Start menu, select power off/restart options
1. Holding left Shift on your keyboard click Restart
1. Keep Shift pressed until a menu appears
1. Select Troubleshoot -> Advance Options -> Startup Settings -> Restart
1. Press `7` on your keyboard
1. The system restarts and will let you to install unsigned modules until the next reboot

Afterwards, the driver must be installed. The tricky part is, there must be something wrong with the .inf file, because
it cannot be installed by right click -> Install. A stop-gap here is to use [OSR System Loader](https://www.osronline.com/OsrDown.cfm/osrloaderv30.zip). This is probably even more dangerous than the driver itself, sorry.

#### Usage
Run the program by simply calling the executable name from the command line or by double-clicking on the executable from Windows Explorer.
**Please do keep in mind that the program requires administrative privileges.***

A welcome banner would appear. Below the banner, rules discovered in the rules file will be listed. If the program encounters a rule that
it's not able to parse, an error message will appear and the program will processed with next rules, until the end of the file.

After rules are installed, expiration timers are started in background. Once a filter expires, a message is logged.

**Data limit filters don't show their progress**. Currently there is no kernel -> app signalling mechanism implemented,
so the application doesn't know if the data limit is reached. As a stop-gap, it is possible to observe it in kernel log,
e.g. using [DebugView](https://learn.microsoft.com/en-us/sysinternals/downloads/debugview).

Please mind that terminating the program *before* a rule expires make it never expire - i.e. the permissive rule
remains in the system until the next reboot or until manual removal.

```
==============================================================================
========================                     =================================
========================     WFPFirewall     =================================
========================                     =================================
=========    Manage your network in cumbersome and inefficient way!   ========
=========             (C) 2023 Wojciech Zmuda                         ========
==============================================================================


Error parsing line: 80.249.99.148/32 11mb
Error parsing line: 999.999.999.999
wfpfirewall.cfg: found 3 rules:
         allow 0.0.0.0 for 10 seconds
         allow 67.222.248.143 for 120 seconds
         allow 127.0.0.1 for 600000000000 bytes

Rules added. Press any key to terminate the program.
Rules that have expired are now persistent and will remain after reboot.
Rules that have not expired will be removed automatically on reboot.

Rule expiration log:

Filter expired: 0.0.0.0/0: turning to persistent block.
Filter expired: 67.222.248.143/32: turning to persistent block.
```


## FAQ
### _How do I know it worked?_
Well, hopefully your rule now blocks the desired connection. Try connecting to the host over TCP and see if it's working.
Please do mind however, that web browsers keep websites in cache and serve them silently if they cannot connect
to the remote host in the timely manner.

### _I don't like my rules anymore - how to remove them?_
Try [WFPExplorer](https://github.com/zodiacon/WFPExplorer). Find rules with names starting with `Wojtek's WFPFirewall`
and remove them manually.

Or, if they didn't expire before you turned off the program - just reboot.

### _Are there any missing features?_
Plenty. The most painful are:
- Port number from the rules is ignored. Adding another filter condition should help here.
- The application has no clue if the data limit filter is triggered, i.e. if the data limit is reached, the connection
  is blocked, but the application does not receive any notification, therefore it's unable to log that to console.
- Data limit filters are not persistent - they expire on reboot.
- The application does not install the kernel module on it's own.