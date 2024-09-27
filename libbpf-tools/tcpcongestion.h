/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __TCPCONGESTION_H
#define __TCPCONGESTION_H

#define TASK_COMM_LEN	16

struct event {
	__u32 saddr[4];
	__u32 daddr[4];
	__u64 delta_us;
	pid_t pid;
	pid_t tid;
	__u16 dport;
	__u16 sport;
	__u16 family;
	char comm[TASK_COMM_LEN];
	__u32 snd_nxt;
	__u32 snd_una;
	__u32 snd_cwnd;
	__u32 ssthresh;
	__u32 snd_wnd;
	__u32 srtt;
	__u32 rcv_wnd;
	__u64 sock_ident;
};

#endif /* __TCPCONGESTION_H */
