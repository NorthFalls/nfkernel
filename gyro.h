/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _NFK_GYRO_H_
#define _NFK_GYRO_H_

#include <linux/kernel.h>
#include <linux/types.h>

/*
 * nfkernel internal gyro support.
 *
 * This is intentionally NOT part of the enenkernel ioctl ABI.  The kernel
 * module keeps abi.h identical to upstream and exposes control through a
 * private NETLINK_USERSOCK message.  The gyro rewrite happens on the sensor
 * receive path in system_server (ASensorEvent type 4 / 16), using kretprobes.
 */

int  gyro_sock_install(pid_t target_tgid);
void gyro_sock_remove(void);
void gyro_sock_set(u32 x_bits, u32 y_bits);
void gyro_sock_set_enabled(bool enabled);
bool gyro_sock_active(void);

/* Called from nfk_gyro_exit() before unregistering probes. */
void gyro_sock_shutdown(void);

#endif /* _NFK_GYRO_H_ */
