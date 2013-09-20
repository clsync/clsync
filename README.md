[![Build Status](https://travis-ci.org/xaionaro/clsync.png?branch=master)](https://travis-ci.org/xaionaro/clsync)

clsync
======
Contents
--------

1.  Name
2.  Motivation
3.  inotify vs fanotify
4.  Installing
5.  How to use
6.  Example of usage
7.  Clustering
8.  Known issues
9.  Support
10. Developing


1. Name
-------

Why "clsync"? The first name of the utility was "insync" (due to inotify), but
then I suggested to use "fanotify" instead of "inotify" and utility was been
renamed to "fasync". After that I started to intensively write the program.
However I faced with some problems in "fanotify", so I was have to temporary
fallback to "inotify", then I decided, that the best name is "Runtime Sync" or
"Live Sync", but "rtsync" is a name of some corporation, and "lsync" is busy
by "lsyncd" project ("https://github.com/axkibe/lsyncd"). So I called it
"clsync", that should be interpreted as "lsync, but on c" due to "lsyncd" that
written on "LUA" and may be used for the same purposes.

UPD: Also I was have to add somekind of clustering support. It's multicast
notifing subsystem to prevent loops on bidirection syncing. So "clsync" also
can be interpreted as "cluster live sync". ;)

2. Motivation
-------------

This utility was been writted for two purposes:
- for making failover clusters
- for making backups of them

To do failover cluster I've tried a lot of different solutions, like "simple 
rsync by cron", "glusterfs", "ocfs2 over drbd", "common mirrorable external 
storage", "incron + perl + rsync", "inosync", "lsyncd" and so on. Currently we
are using "lsyncd", "ceph" and "ocfs2 over drbd". However all of this
solutions doesn't arrange me, so I was have to write own utility for this
purpose.

To do backups we also tried a lot of different solution, and again I was have
to write own utility for this purpose.

The best known (for me) replacement for this utility is "lsyncd", however:
- It's code is `>½` on LUA. There a lot of problems connected with it,
for example:
    - It's more difficult to maintain the code with ordinary sysadmin.
    - It really eats 100% CPU sometimes.
    - It requires LUA libs, that cannot be easily installed to few
of our systems.
- It's a little buggy. That may be easily fixed for our cases,
but LUA. :(
- It doesn't support pthread or something like that. It's necessary
to serve huge directories with a lot of containers right.
- It cannot run rsync for a pack of files. It runs rsync for every
event. :(
- Sometimes, it's too complex in configuration for our situation.
- It can't set another event-collecting delay for big files. We don't
want to sync big files (`>1GiB`) so often as ordinary files.

Sorry, if I'm wrong. Let me know if it is, please :). "lsyncd" - is really
good and useful utility, just it's not appropriate for us.


3. inotify vs fanotify:
-----------------------

It's said, that fanotify is much better, than inotify. So I started to write 
this program with using of fanotify. However I encountered the problem, that
fanotify was unable to catch some important events at the moment of writing
the program, like "directory creation" or "file deletion". So I switched to
"inotify", leaving the code for "fanotify" in the safety... So, don't use
"fanotify" in this utility ;).


4. Installing
-------------

First of all, you should install dependencies to compile clsync. As you can
see from GNUmakefile clsync depends only on "glib-2.0" and "mhash", so on
debian-like systems you should execute something like
"apt-get install libglib2.0-dev libmhash-dev".

Next step is generating Makefile. To do that usually it's enought to execute
"autoreconf -i && ./configure".

Next step is compiling. To compile usually it's enough to execute "make".

Next step in installing. To install usually it's enough to execute
"su -c 'make install'".

Also, debian-users can use my repository to install the clsync:
deb [arch=amd64] http://mirror.mephi.ru/debian-mephi/ unstable main


5. How to use
-------------

How to use is described in "man" ;). What is not described, you can ask me
personally (see "Support").


6. Example of usage
-------------------

Example of usage, that works on my PC is in directory "examples". Just run
"clsync-start-rsyncdirect.sh" and try to create/modify/delete files/dirs in
"example/testdir/from". All modifications should appear (with some delay) in
directory "example/testdir/to" ;)


7. Clustering
-------------

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

8. Known building issues
------------------------

May be problems with "configuring" or compilation. In this case just try
next command:
> gcc -std=gnu99 -D\_FORTIFY\_SOURCE=2 -DPARANOID -pthread -DHAVE\_MHASH  -pipe -Wall -ggdb3 --param ssp-buffer-size=4 -fstack-check -fstack-protector-all -Xlinker -zrelro -pthread $(pkg-config --cflags glib-2.0) $(pkg-config --libs glib-2.0) -ldl -lmhash \*.c -o /tmp/clsync

9. Support
-----------

To get support, you can contact with me this ways:
- Official IRC channel of "clsync": irc.freenode.net#clsync
- Where else can you find me: IRC:SSL+UTF-8 irc.campus.mephi.ru:6695#mephi,xaionaro,xai
- And e-mail: <dyokunev@ut.mephi.ru>, <xaionaro@gmail.com>; PGP pubkey: 0x8E30679C

10. Developing
--------------

I started to write "DEVELOPING" and "PROTOCOL" files.
You can look there if you wish. ;)

I'll be glad to receive code contribution :)



                                               -- Dmitry Yu Okunev <dyokunev@ut.mephi.ru> 0x8E30679C

