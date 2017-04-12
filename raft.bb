#
# Yocto recipe for a RAFT out-of-tree kernel module
# raft.bb  
#

DESCRIPTION = "Raft kernel module out of the kernel tree"
SECTION = "examples"
LICENSE = "GPLv2"
LIC_FILES_CHKSUM = "file://COPYING;md5=12f884d2ae1ff87c09e5b7ccc2c4ca7e"
PR = "r0"

inherit module

#SRC_URI = "\
# file://*\
#"
SRC_URI = "\
 file://raft.h\
 file://init.c\
 file://conf.c\
 file://relations.h\
 file://relations.c\
 file://socket.c\
 file://netlink.c\
 file://structs.h\
 file://netlink.h\
 file://raft_netlink.h\
 file://Makefile\
 file://COPYING\
"

S = "${WORKDIR}"
