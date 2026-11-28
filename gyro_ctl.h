/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _NFK_GYRO_CTL_H_
#define _NFK_GYRO_CTL_H_

#include <linux/types.h>

/*
 * Private nfkernel gyro control channel.
 *
 * This header is shared by the kernel and the userland helper, but it is NOT
 * part of the enenkernel ioctl ABI.  Messages travel over NETLINK_USERSOCK
 * with NFK_GYRO_MAGIC; a foreign driver ignores them.
 */
#define NFK_GYRO_MAGIC 0x4E464B47u /* "NFKG" */
#define NFK_GYRO_NL_PROTO 31 /* private AF_NETLINK protocol, no /dev node */

enum nfk_gyro_cmd {
	NFK_GYRO_CMD_SET = 1, /* install/update x/y, enable rewrite */
	NFK_GYRO_CMD_STOP = 2, /* pause rewriting, keep probes */
	NFK_GYRO_CMD_RESUME = 3, /* resume rewriting */
	NFK_GYRO_CMD_REMOVE = 4, /* unregister probes */
};

struct nfk_gyro_msg {
	__u32 magic;   /* NFK_GYRO_MAGIC */
	__u16 cmd;     /* enum nfk_gyro_cmd */
	__u16 reserved;
	__s32 pid;     /* target tgid, normally system_server; 0 = all */
	__u32 x_bits;  /* IEEE-754 float bits, rad/s */
	__u32 y_bits;
	__u32 enable;  /* reserved for SET */
};

int nfk_gyro_init(void);
void nfk_gyro_exit(void);

#endif /* _NFK_GYRO_CTL_H_ */
