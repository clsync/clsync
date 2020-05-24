[![Build Status](https://travis-ci.org/clsync/clsync.png?branch=master)](https://travis-ci.org/clsync/clsync)
[![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/xaionaro/clsync?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

clsync
======
0 - Contents
------------

1.  Name
2.  Motivation
3.  inotify vs fanotify
4.  Installing
5.  How to use
6.  Example of usage
7.  Other uses
8.  Clustering
9.  FreeBSD support
10. Support
11. Developing
12. Articles
13. See also


1 - Name
--------

Why `clsync`? The first name of the utility was `insync` (due to `inotify`) but
then I was suggested to use `fanotify` instead of `inotify` and utility has been
renamed to `fasync`. Then I started to intensively write the program and
I faced with some problems in `fanotify` (see "inotify vs fanotify"). So I was
have to temporary fallback to `inotify`, so I decided that the best name is
"Runtime Sync" or "Live Sync" but `rtsync` is a name of some corporation and
`lsync` is busy by "[lsyncd](https://github.com/axkibe/lsyncd)". So I called it
`clsync` that should be interpreted as "lsync but on c" due to "lsyncd" that
written on "LUA" and may be used for similar purposes.

2 - Motivation
--------------

This utility has been written for two purposes:
- for making high availability clusters
- for making backups of them

To do a HA cluster I've tried a lot of different solutions, like "simple
rsync by cron", "glusterfs", "ocfs2 over drbd", "shared replicated external
storage", "incron + perl + rsync", "inosync", "lsyncd" and so on. When I
started to write the utility we were using "lsyncd", "ceph" and
"ocfs2 over drbd". However all of this solutions doesn't satisfy me, so I
was have to write own utility for this purpose.

To do backups we also tried a lot of different solution, and again I was have
to write own utility for this purpose.

The best known (for me) replacement for this utility is "lsyncd", however:
- It's code is `>½` on LUA. There a lot of problems connected with it,
for example:
    - It's more difficult to maintain the code with ordinary sysadmin.
    - It really eats 100% CPU sometimes.
    - It requires LUA libs, that cannot be easily installed to few
of our systems.
- It's a little buggy (it crashed on our cases).
- Sometimes, it's too complex in configuration for our situation (not flexible
enough). For example it doesn't have another event-collecting delay for big files.
We don't want to sync big files (`>1GiB`) so often as ordinary files.
- Shared object (.so file) cannot be used as rsync-wrapper.
- It doesn't support kqueue/bsm (we also had a FreeBSD-based system).
- It's not secure enough. No builtin containerization support to reduce risks.
- ... and other tiny problems...

"lsyncd" - is a good and useful utility, just did not fit to our needs will
enough. And we spent enough much time on tuning "lsyncd" to realize that we
could've write an new solution sharpened by our tasks. So there it is :)

Also `clsync` had been used for some other tiny tasks, like to replace
incron/csync2/etc in our HPC-clusters for syncing /etc/{passwd,shadow,group,shells}
files and running post-scripts.

3 - inotify vs fanotify
------------------------

It's said that fanotify is much better than inotify. So I started to write
this program with using of fanotify. However I encountered the problem, that
fanotify was unable to catch some important events at the moment of writing
the program, like "directory creation" or "file deletion". So I switched to
"inotify", leaving the code for "fanotify" in the safety... So, don't use
"fanotify" in this utility ;).

UPD: Starting with kernels 5.1 we will be able to use fanotify for all events ;)

4 - Installing
--------------

**Linux Distributions**

Some distributions already have clsync supported in the main repo:

*Debian/Ubuntu:*

    apt-get install clsync

An optional clsync socket monitoring and control library is available
in the *libclsync0* package and its devel files are in the
*libclsync-dev*

*Gentoo:*

    emerge clsync

You may customize *all* clsync features via a multitude of USE flags.

*Alt Linux:*

    apt-get install clsync

An optional clsync socket monitoring and control library is available
in the *libclsync* package and its devel files are in the
*libclsync-devel*. Examples are located in the *clsync-examples*
package and doxygen API documentation is in *clsync-apidocs*.

**From the Source Code**

If it's required to install clsync from the source, first of all, you should
install dependencies to compile it. Names may vary in various
distributions, but you'll get the idea:

Only the following packages are mandatory:
    glib2-devel autoreconf gcc

Dependencies for optional features:
* libcap-devel — capabilities support for privilege separation
* libcgroup-devel — cgroups support for privilege separation
* libmhash-devel — use mhash for faster Adler-32 implementation
  (used only in cluster and kqueue code)
* doxygen — to build API documentation
* graphviz — to build API documentation

Next step is generating Makefile. To do that usually it's enough to execute:

    autoreconf -i && ./configure

You may be interested in various configuration options, so see for
details:

    ./configure --help

Next step is compiling. To compile usually it's enough to execute:

    make -j$(nproc)

Next step is installing. To install usually it's enough to execute:

    su -c 'make install'


5 - How to use
--------------

How to use is described in "man" ;). What is not described, you can ask me
personally (see "Support").

See also section 7 of this document.

6 - An example from scratch
---------------------------

Example of usage, that works on my PC is in directory "examples". Just run
"clsync-start-rsyncdirect.sh" and try to create/modify/delete files/dirs in
"example/testdir/from". All modifications should appear (with some delay) in
directory "example/testdir/to" ;)

For dummies:

    pushd /tmp
    git clone https://github.com/clsync/clsync
    cd clsync
    autoreconf -fi
    ./configure
    make
    export PATH_OLD="$PATH"
    export PATH="$(pwd):$PATH"
    cd examples
    ./clsync-start-rsyncdirect.sh
    export PATH="$PATH_OLD"

Now you can try to make changes in directory
"/tmp/clsync/examples/testdir/from" (in another terminal).
Wait about 7 seconds after the changes and check directory
"/tmp/clsync/examples/testdir/to". To finish the experiment press ^C
(control+c) in clsync's terminal.

    cd ../..
    rm -rf clsync
    popd

Note: There's no need to change PATH's value if clsync is installed
system-wide, e.g. with

    make install

For dummies, again (with "make install"):

    pushd /tmp
    git clone https://github.com/clsync/clsync
    cd clsync
    autoreconf -fi
    ./configure
    make
    sudo make install
    cd examples
    ./clsync-start-rsyncdirect.sh

Directory "/tmp/clsync/examples/testdir/from" is now synced to
"/tmp/clsync/examples/testdir/to" with 7 seconds delay. To terminate
the clsync press ^C (control+c) in clsync's terminal.

    cd ..
    sudo make uninstall
    cd ..
    rm -rf clsync
    popd

For really dummies or/and lazy users, there's a video demonstration:
[http://ut.mephi.ru/oss/clsync](http://ut.mephi.ru/oss/clsync)


7 - More examples (use cases)
-----------------------------

Mirroring a directory:
```
clsync -Mrsyncdirect -W/path/to/source_dir -D/path/to/destination_dir
```

Syncing `authorized_keys` files:
```
mkdir -p /etc/clsync/rules
printf "+w^$\n+w^[^/]+$\n+W^[^/]+/.ssh$\n+f^[^/]+/.ssh/authorized_keys$\n-*" > /etc/clsync/rules/authorized_files_only
clsync  -Mdirect -Scp -W/mnt/master/home/ -D/home -R/etc/clsync/rules/authorized_files_only -- -Pfp --parents %INCLUDE-LIST% %destination-dir%
```

Mirroring a directory, but faster:
```
clsync -w5 -t5 -T5 -Mrsyncdirect -W/path/to/source_dir -D/path/to/destination_dir
```

Instant mirroring of a directory:
```
clsync -w0 -t0 -T0 -Mrsyncdirect -W/path/to/source_dir -D/path/to/destination_dir
```

Making two directories synchronous:
```
clsync -Mrsyncdirect --background -z /var/run/clsync0.pid --output syslog -Mrsyncdirect -W/path/to/dir1 -D/path/to/dir2 --modification-signature '*'
clsync -Mrsyncdirect --background -z /var/run/clsync1.pid --output syslog -Mrsyncdirect -W/path/to/dir2 -D/path/to/dir1 --modification-signature '*'
```

Fixing privileges of a web-site:
```
clsync -w3 -t3 -T3 -x1 -W/var/www/site.example.org/root -Mdirect -Schown --uid  0  --gid  0  -Ysyslog  -b1  --modification-signature uid,gid -- --from=root www-data:www-data %INCLUDE-LIST%
```

'Atomic' sync:
```
clsync --exit-on-no-events --max-iterations=20 --mode=rsyncdirect -W/var/www_new -Srsync -- %RSYNC-ARGS% /var/www_new/ /var/www/
```

Moving a web-server:
```
clsync  --exit-on-no-events  --max-iterations=20 --pre-exit-hook=/root/stop-here.sh --exit-hook=/root/start-there.sh --mode=rsyncdirect --ignore-exitcode=23,24 --retries=3 -W /var/www -S rsync -- %RSYNC-ARGS% /var/www/ rsync://clsync@another-host/var/www/
```

Copying files to slave-nodes using pdcp(1):
```
clsync -Msimple -S pdcp -W /opt/global -b -Y syslog -- -a %INCLUDE-LIST% %INCLUDE-LIST%
```

Copying files to slave-nodes using uftp(1):
```
clsync -Mdirect -S uftp -W/opt/global --background=1 --output=syslog -- -M 248.225.233.1 %INCLUDE-LIST%
```

A dry running to see rsync(1) arguments that clsync will use:
```
clsync -Mrsyncdirect -S echo -W/path/to/source_dir -D/path/to/destination_dir
```

An another dry running to look how clsync will call pdcp(1):
```
clsync -Msimple -S echo -W /opt/global -b0 -- pdcp -a %INCLUDE-LIST% %INCLUDE-LIST%
```

Automatically run `make build` if any `*.c` file changed
```
printf "%s\n" "+f.c$" "-f" | clsync --have-recursive-sync -W . -R /dev/stdin -Mdirect -r1 --ignore-failures -t1 -w1 -Smake -- build
```

8 - Clustering
--------------

I've started to implement support of bi-directional syncing with using
multicast notifing of other nodes. However it became a long task, so it was
suspended for next releases.

However let's solve next hypothetical problem. For example, you're using
LXC and trying to replicate containers between two servers (to make failover
and load balancing).

In this case you have to sync containers in both directions. However, if you
just run clsync to sync containers to neighboring node on both of them, you'll
get sync-loop [file-update on A causes file-update on B causes file-update
on A causes ...].

Well, in this case I with my colleagues were using separate directories for
every node of cluster (e.g. "`/srv/nodes/<NODE NAME>/containers/<CONTAINERS>`")
and syncing every directory only in one direction. That was failover with
load-balancing, but very unconvenient. So I've started to write code for
bi-directional syncing, however it's no time to complete it :(. So
Andrew Savchenko proposed to run one clsync-instance per container. And this's
really good solution. It's just need to start clsync-process when container
starts and stop the process when containers stops. The only problem is
split-brain, that can be solved two ways:
- by human every time;
- by scripts that chooses which variant of container to save.

Example of the script is just a script that calls "find" on both sides to
determine which side has the latest changes :)

UPD: I've added option "--modification-signature" that helps to prevent syncing file, that is not changed. You can easily use it to prevent sync-loops for bi-directional syncing.

9 - FreeBSD support
-------------------

clsync has been ported to FreeBSD.

FreeBSD doesn't support inotify, so there're 3.5 ways to use clsync on it:
* using [libinotify](https://github.com/dmatveev/libinotify-kqueue);
* using BSM API (with or without a prefetcher thread);
* using kqueue/kevent directly.

And any of this methods is bad (in it's own way), see the excerpt from the
manpage:

     Possible values:
            inotify
                   inotify(7) [Linux, (FreeBSD via libinotify)]

                   Native, fast, reliable and well tested Linux FS monitor subsystem.

                   There's no essential performance profit to use "inotify"  instead  of
                   "kevent"  on FreeBSD using "libinotify". It backends to "kevent" any‐
                   way.

                   FreeBSD users: The libinotify on FreeBSD is still not ready and unus‐
                   able for clsync to sync a lot of files and directories.

            kqueue
                   kqueue(2) [FreeBSD, (Linux via libkqueue)]

                   A  *BSD  kernel  event  notification  mechanism (inc. timer, sockets,
                   files etc).

                   This monitor subsystem cannot determine file creation event,  but  it
                   can determine a directory where something happened. So clsync is have
                   to rescan whole dir every  time  on  any  content  change.  Moreover,
                   kqueue  requires  an  open()  on  every watched file/dir. But FreeBSD
                   doesn't allow to open() symlink itself (without following)  and  it's
                   highly  invasively  to open() pipes and devices. So clsync just won't
                   call open() on everything except regular files and directories.  Con‐
                   sequently,  clsync  cannot  determine  if  something  changed in sym‐
                   link/pipe/socket and so on.  However it still  can  determine  if  it
                   will  be created or deleted by watching the parent directory and res‐
                   caning it on every appropriate event.

                   Also this API requires to open every monitored file and directory. So
                   it  may  produce  a  huge  amount  of  file descriptors. Be sure that
                   kern.maxfiles is big enough (in FreeBSD).

                   CPU/HDD expensive way.

                   Not well tested. Use with caution!

                   Linux users: The libkqueue on Linux is not working. He-he :)

            bsm
                   bsm(3) [FreeBSD]

                   Basic Security Module (BSM) Audit API.

                   This is not a FS monitor subsystem, actually. It's  just  an  API  to
                   access  to  audit information (inc. logs).  clsync can setup audit to
                   watch FS events and report it into log. After that clsync  will  just
                   parse the log via auditpipe(4) [FreeBSD].

                   Reliable,  but  hacky  way.  It requires global audit reconfiguration
                   that may hopple audit analysis.

                   Warning!  FreeBSD has a limit for queued events. In  default  FreeBSD
                   kernel it's only 1024 events. So choose one of:
                          - To patch the kernel to increase the limit.
                          - Don't use clsync on systems with too many file events.
                          - Use bsm_prefetch mode (but there's no guarantee in this case
                          anyway).
                   See also option --exit-on-sync-skip.

                   Not  well  tested.  Use   with   caution!    Also   file   /etc/secu‐
                   rity/audit_control will be overwritten with:
                          #clsync

                          dir:/var/audit
                          flags:fc,fd,fw,fm,cl
                          minfree:0
                          naflags:fc,fd,fw,fm,cl
                          policy:cnt
                          filesz:1M
                   unless it's already starts with "#clsync\n" ("\n" is a new line char‐
                   acter).

            bsm_prefetch
                   The same as bsm but all BSM events will be  prefetched  by  an  addi‐
                   tional  thread  to prevent BSM queue overflow. This may utilize a lot
                   of memory on systems with a high FS events frequency.

                   However the thread may be not fast enough to unload  the  kernel  BSM
                   queue. So it may overflow anyway.

     The default value on Linux is "inotify". The default value on FreeBSD is "kqueue".

I hope you will send me bugreports to make me able to improve the FreeBSD support :)

10 - Support
-----------

To get support, you can contact with me this ways:
- Official IRC channel of "clsync": irc.freenode.net#clsync
- Where else can you find me: IRC:SSL+UTF-8 irc.campus.mephi.ru:6695#mephi,xaionaro,xai
- And e-mail: <dyokunev@ut.mephi.ru>, <xaionaro@gmail.com>; PGP pubkey: 0x8E30679C

11 - Developing
--------------

I started to write "DEVELOPING" and "PROTOCOL" files.
You can look there if you wish. ;)

I'll be glad to receive code contribution :)

The astyle command:
```
astyle --style=linux --indent=tab --indent-cases --indent-switches --indent-preproc-define --break-blocks --pad-oper --pad-paren --delete-empty-lines
```

12 - Articles
------------

Russian:
- [HA clustering](https://gitlab.ut.mephi.ru/ut/articles/blob/master/clsync/ha)
- [syncing to many nodes](https://gitlab.ut.mephi.ru/ut/articles/blob/master/clsync/inotify-to-many-nodes)
- [atomic sync](https://gitlab.ut.mephi.ru/ut/articles/blob/master/clsync/atomicsync)

LVEE (Russian):
- [clsync - live sync utility (abstract)](http://lvee.org/en/abstracts/118) [presentation](http://lvee.org/uploads/image_upload/file/337/winter_2014_15_clsync.pdf)
- [clsync progress: security and porting to freebsd](http://lvee.org/en/abstracts/138)

13 - See also
------------

- [lrsync](https://github.com/xaionaro/lrsync)
