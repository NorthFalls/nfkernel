/* dfm private gyro control, kept outside the enenkernel 'D' ABI. */
#ifndef DFM_GYRO_H
#define DFM_GYRO_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define DFM_GYRO_ABI_VERSION 1u
#define DFM_GYRO_IOC_TYPE 'D'

enum dfm_gyro_cmd {
	DFM_GYRO_CMD_SET = 1,
	DFM_GYRO_CMD_ENABLE,
	DFM_GYRO_CMD_DISABLE,
	DFM_GYRO_CMD_REMOVE,
	DFM_GYRO_CMD_QUERY,
};

struct dfm_gyro_req {
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
	__u32 samples[8][3];	/* first 12 bytes, up to 8 candidate buffers */
	__u32 sample_count;
	__u32 direct_events;	/* SensorDirectChannel gyro events seen */
	__u32 direct_writes;	/* direct-channel x/y writes completed */
	__u64 direct_addr;	/* discovered ashmem queue start, 0=none */
};

#define DFM_GYRO_IOC_CTRL _IOWR(DFM_GYRO_IOC_TYPE, 48, struct dfm_gyro_req)

int dfm_gyro_init(void);
void dfm_gyro_exit(void);
long dfm_gyro_ioctl(void __user *arg);

#endif /* DFM_GYRO_H */
