# ynl-c

Standalone copy of generated YNL C lib.

Development happens in the Linux kernel:

https://git.kernel.org/pub/scm/linux/kernel/git/netdev/net-next.git/tree/tools/net/ynl/

This repo contains just the C parts, excluding all Python and
scripts, even the code generator which generated the code.

Basic intro:

https://docs.kernel.org/next/userspace-api/netlink/intro-specs.html#ynl-lib

Using the library
=================

Building the library generates an archive for static linking called
``libynl.a``.
