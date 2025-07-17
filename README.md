# The GABpbx(R) Open Source PBX

```
By Mark Spencer <markster@digium.com> and the GABpbx.org developer community.
Copyright (C) 2001-2025 Sangoma Technologies Corporation and other copyright holders.
```

## SECURITY

It is imperative that you read and fully understand the contents of
the security information document before you attempt to configure and run
an GABpbx server.

See [Important Security Considerations](https://docs.gabpbx.org/Deployment/Important-Security-Considerations) for more information.

## WHAT IS GABPBX ?

GABpbx is an Open Source PBX and telephony toolkit.  It is, in a
sense, middleware between Internet and telephony channels on the bottom,
and Internet and telephony applications at the top.  However, GABpbx supports
more telephony interfaces than just Internet telephony.  GABpbx also has a
vast amount of support for traditional PSTN telephony, as well.

For more information on the project itself, please visit the [GABpbx
Home Page](https://www.gabpbx.org) and the official
[GABpbx Documentation](https://docs.gabpbx.org).

## SUPPORTED OPERATING SYSTEMS

### Linux

The GABpbx Open Source PBX is developed and tested primarily on the
GNU/Linux operating system, and is supported on every major GNU/Linux
distribution.

### Others

GABpbx has also been 'ported' and reportedly runs properly on other
operating systems as well, Apple's Mac OS X, and the BSD variants.

## GETTING STARTED

Most users are using VoIP/SIP exclusively these days but if you need to
interface to TDM or analog services or devices, be sure you've got supported
hardware.

Supported telephony hardware includes:
* All Analog and Digital Interface cards from Sangoma
* Any full duplex sound card supported by PortAudio
* The Xorcom Astribank channel bank

### UPGRADING FROM AN EARLIER VERSION

If you are updating from a previous version of GABpbx, make sure you
read the Change Logs.

<!-- CHANGELOGS (the URL will change based on the location of this README) -->
[Change Logs](ChangeLogs/ChangeLog-22.3.0.html)
<!-- END-CHANGELOGS -->

### NEW INSTALLATIONS

Ensure that your system contains a compatible compiler and development
libraries.  GABpbx requires either the GNU Compiler Collection (GCC) version
4.1 or higher, or a compiler that supports the C99 specification and some of
the gcc language extensions.  In addition, your system needs to have the C
library headers available, and the headers and libraries for ncurses.

There are many modules that have additional dependencies.  To see what
libraries are being looked for, see `./configure --help`, or run
`make menuselect` to view the dependencies for specific modules.

On many distributions, these dependencies are installed by packages with names
like 'glibc-devel', 'ncurses-devel', 'openssl-devel' and 'zlib-devel'
or similar.  The `contrib/scripts/install_prereq` script can be used to install
the dependencies for most Debian and Redhat based Linux distributions.
The script also handles SUSE, Arch, Gentoo, FreeBSD, NetBSD and OpenBSD but
those distributions mightnoit have complete support or they might be out of date.

So, let's proceed:

1. Read the documentation.<br>
The [GABpbx Documentation](https://docs.gabpbx.org) website has full
information for building, installing, configuring and running GABpbx.

2. Run `./configure`<br>
Execute the configure script to guess values for system-dependent
variables used during compilation. If the script indicates that some required
components are missing, you can run `./contrib/scripts/install_prereq install`
to install the necessary components. Note that this will install all dependencies
for every functionality of GABpbx. After running the script, you will need
to rerun `./configure`.

3. Run `make menuselect`<br>
This is needed if you want to select the modules that will be compiled and to
check dependencies for various optional modules.

4. Run `make`<br>
Assuming the build completes successfully:

5. Run `make install`<br>
If this is your first time working with GABpbx, you may wish to install
the sample PBX, with demonstration extensions, etc.  If so, run:

6. Run `make samples`<br>
Doing so will overwrite any existing configuration files you have installed.

7. Finally, you can launch GABpbx in the foreground mode (not a daemon) with
`gabpbx -vvvc`<br>
You'll see a bunch of verbose messages fly by your screen as GABpbx
initializes (that's the "very very verbose" mode).  When it's ready, if
you specified the "c" then you'll get a command line console, that looks
like this:<br>
`*CLI>`<br>
You can type `core show help` at any time to get help with the system.  For help
with a specific command, type `core show help <command>`.

`man gabpbx` at the Unix/Linux command prompt will give you detailed
information on how to start and stop GABpbx, as well as all the command
line options for starting GABpbx.

### ABOUT CONFIGURATION FILES

All GABpbx configuration files share a common format.  Comments are
delimited by `;` (since `#` of course, being a DTMF digit, may occur in
many places).  A configuration file is divided into sections whose names
appear in `[]`'s.  Each section typically contains statements in the form
`variable = value` although you may see `variable => value` in older samples.

### SPECIAL NOTE ON TIME

Those using SIP phones should be aware that GABpbx is sensitive to
large jumps in time.  Manually changing the system time using date(1)
(or other similar commands) may cause SIP registrations and other
internal processes to fail.  For this reason, you should always use
a time synchronization package to keep your system time accurate.
All OS/distributions make one or more of the following packages
available:

* ntpd/ntpsec
* chronyd
* systemd-timesyncd

Be sure to install and configure one (and only one) of them.

### FILE DESCRIPTORS

Depending on the size of your system and your configuration,
GABpbx can consume a large number of file descriptors.  In UNIX,
file descriptors are used for more than just files on disk.  File
descriptors are also used for handling network communication
(e.g. SIP, IAX2, or H.323 calls) and hardware access (e.g. analog and
digital trunk hardware).  GABpbx accesses many on-disk files for
everything from configuration information to voicemail storage.

Most systems limit the number of file descriptors that GABpbx can
have open at one time.  This can limit the number of simultaneous
calls that your system can handle.  For example, if the limit is set
at 1024 (a common default value) GABpbx can handle approximately 150
SIP calls simultaneously.  To change the number of file descriptors
follow the instructions for your system below:

#### PAM-BASED LINUX SYSTEM

If your system uses PAM (Pluggable Authentication Modules) edit
`/etc/security/limits.conf`.  Add these lines to the bottom of the file:

```text
root            soft    nofile          4096
root            hard    nofile          8196
gabpbx        soft    nofile          4096
gabpbx        hard    nofile          8196
```

(adjust the numbers to taste).  You may need to reboot the system for
these changes to take effect.

#### GENERIC UNIX SYSTEM

If there are no instructions specifically adapted to your system
above you can try adding the command `ulimit -n 8192` to the script
that starts GABpbx.

## MORE INFORMATION

Visit the [GABpbx Documentation](https://docs.gabpbx.org) website
for more documentation on various features and please read all the
configuration samples that include documentation on the configuration options.

Finally, you may wish to join the
[GABpbx Community Forums](https://community.gabpbx.org)


Welcome to the growing worldwide community of GABpbx users!

```
        Mark Spencer, and the GABpbx.org development community
```

---

GABpbx is a trademark of Sangoma Technologies Corporation

\[[Sangoma](https://www.sangoma.com/)\] 
\[[Home Page](https://www.gabpbx.org)\] 
\[[Support](https://www.gabpbx.org/support)\] 
\[[Documentation](https://docs.gabpbx.org)\] 
\[[Community Forums](https://community.gabpbx.org)\] 
\[[Release Notes](https://github.com/gabpbx/gabpbx/releases)\] 
\[[Security](https://docs.gabpbx.org/Deployment/Important-Security-Considerations/)\] 
\[[Mailing List Archive](https://lists.digium.com)\] 

