/*
 * Copyright (C) 2018-2019 Hewlett Packard Enterprise Development LP.
 * All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _WILDCAT_ZMMU_H_
#define _WILDCAT_ZMMU_H_

extern uint wildcat_no_avx;

#define ROUND_DOWN_PAGE(_addr, _sz) ((_addr) & -(_sz))
#define ROUND_UP_PAGE(_addr, _sz)   (((_addr) + ((_sz) - 1)) & -(_sz))

enum containment_level {
	N  = 0,  /* Normal - no containment:             least severe */
	F  = 1,  /* Failed destination */
	C2 = 2,  /* Route exhaustion */
	C1 = 3   /* Poisoned or other containable event: most severe */
};

enum sync_type {
	NO_SYNC = 0,
	SYNC    = 1
};

enum valid_type {
	INVALID = 0,
	VALID   = 1
};

/* Several ZMMU structures must be read/written with 16- or 32-byte accesses.
 * These definitions are x86_64 only, using the xmm/ymm vector registers.
 * Callers must use kernel_fpu_begin() / kernel_fpu_end().
 */

#pragma GCC push_options
#pragma GCC target("avx")
static inline void ioread16by(void *dst, const volatile void __iomem *src)
{
	if (wildcat_no_avx) {  /* Revisit: workaround */
		uint64_t *d64 = dst;
		const volatile uint64_t __iomem *s64 = src;
		*d64 = ioread64(s64);
		*(d64 + 1) = ioread64(s64 + 1);
	} else {
		__asm__ __volatile__(
			"mfence     \n\t"
			"vmovntdqa  (%[s]), %%xmm0    \n\t"
			"vmovdqa    %%xmm0,   (%[d])"
			:
			: [s] "r" (src), [d] "r" (dst)
			: "memory", "%xmm0"
			);
	}
}

static inline void iowrite16by(void *src, volatile void __iomem *dst)
{
	if (wildcat_no_avx) {  /* Revisit: workaround */
		volatile uint64_t __iomem *d64 = dst;
		uint64_t *s64 = src;
		iowrite64(*s64, d64);
		iowrite64(*(s64 + 1), d64 + 1);
	} else {
		__asm__ __volatile__(
			"vmovdqa    (%[s]), %%xmm0    \n\t"
			"vmovdqa    %%xmm0,   (%[d])  \n\t"
			"mfence"
			:
			: [s] "r" (src), [d] "r" (dst)
			: "memory", "%xmm0"
			);
	}
}

static inline void ioread32by(void *dst, const volatile void __iomem *src)
{
	if (wildcat_no_avx) {  /* Revisit: workaround */
		uint64_t *d64 = dst;
		const volatile uint64_t __iomem *s64 = src;
		*d64 = ioread64(s64);
		*(d64 + 1) = ioread64(s64 + 1);
		*(d64 + 2) = ioread64(s64 + 2);
		*(d64 + 3) = ioread64(s64 + 3);
	} else {
		__asm__ __volatile__(
			"mfence     \n\t"
			"vmovntdqa  (%[s]), %%ymm0    \n\t"
			"vmovdqa    %%ymm0,   (%[d])"
			:
			: [s] "r" (src), [d] "r" (dst)
			: "memory", "%ymm0"
			);
	}
}

static inline void iowrite32by(void *src, volatile void __iomem *dst)
{
	if (wildcat_no_avx) {  /* Revisit: workaround */
		volatile uint64_t __iomem *d64 = dst;
		uint64_t *s64 = src;
		iowrite64(*s64, d64);
		iowrite64(*(s64 + 1), d64 + 1);
		iowrite64(*(s64 + 2), d64 + 2);
		iowrite64(*(s64 + 3), d64 + 3);
	} else {
		__asm__ __volatile__(
			"vmovdqa    (%[s]), %%ymm0    \n\t"
			"vmovdqa    %%ymm0,   (%[d])  \n\t"
			"mfence"
			:
			: [s] "r" (src), [d] "r" (dst)
			: "memory", "%ymm0"
			);
	}
}
#pragma GCC pop_options

static inline struct bridge *wildcat_gzbr_to_br(struct genz_bridge_dev *gzbr)
{
	struct bridge *br = NULL;

	if (gzbr) {
		br = genz_get_drvdata(&gzbr->zdev);
	}

	return br;
}

/* tentative definitions */
struct zhpe_pte_info;

char *zhpe_gcid_str(const uint32_t gcid, char *str, const size_t len);
void wildcat_zmmu_clear_slice(struct slice *sl);
int wildcat_req_page_grid_write(struct genz_bridge_dev *br, uint pg_index,
				struct genz_page_grid genz_pg[]);
int wildcat_rsp_page_grid_write(struct genz_bridge_dev *br, uint pg_index,
				struct genz_page_grid genz_pg[]);
int wildcat_req_pte_write(struct genz_bridge_dev *gzbr,
			  struct genz_pte_info *info);
int wildcat_rsp_pte_write(struct genz_bridge_dev *gzbr,
			  struct genz_pte_info *info);
void wildcat_req_pte_clear(struct zhpe_pte_info *info);
void wildcat_rsp_pte_clear(struct zhpe_pte_info *info);
int wildcat_humongous_zmmu_rsp_pte_alloc(
	struct genz_pte_info **infop,
	struct genz_pte_info **humongous_zmmu_rsp_pte,
	spinlock_t *md_lock,
	uint64_t *rsp_zaddr,
	uint32_t *pg_ps);
#endif /* _WILDCAT_ZMMU_H_ */
