/* nfkernel private gyro control, kept outside the enenkernel 'D' ABI. */
#ifndef NFK_GYRO_H
#define NFK_GYRO_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define NFK_GYRO_ABI_VERSION 1u
#define NFK_GYRO_IOC_TYPE 'N'

enum nfk_gyro_cmd {
	NFK_GYRO_CMD_SET = 1,
	NFK_GYRO_CMD_ENABLE,
	NFK_GYRO_CMD_DISABLE,
	NFK_GYRO_CMD_REMOVE,
	NFK_GYRO_CMD_QUERY,
};

struct nfk_gyro_req {
	__u32 abi_version;
	__u32 cmd;
	__s32 pid;
	__u32 enable;
	__u32 x_bits;
	__u32 y_bits;
	__u32 active;
	__u32 processed;
	__u32 rewritten;
	__u32 reserved[3];
};

#define NFK_GYRO_IOC_CTRL _IOWR(NFK_GYRO_IOC_TYPE, 0x01, struct nfk_gyro_req)

int nfk_gyro_init(void);
void nfk_gyro_exit(void);
long nfk_gyro_ioctl(void __user *arg);

#endif /* NFK_GYRO_H */
