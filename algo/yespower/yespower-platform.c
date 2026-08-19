/*-
 * Copyright 2013-2018 Alexander Peslyak
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <sys/mman.h>
#include <errno.h>
#include <syslog.h>
#include <stdio.h>
extern void applog(int prio, const char *fmt, ...);

#define HUGEPAGE_THRESHOLD		(2 * 1024 * 1024)

#ifdef __x86_64__
#define HUGEPAGE_SIZE			(2 * 1024 * 1024)
#else
#undef HUGEPAGE_SIZE
#endif

static void *alloc_region(yespower_region_t *region, size_t size)
{
	size_t base_size = size;
	uint8_t *base, *aligned;
#ifdef MAP_ANON
	int flags =
#ifdef MAP_NOCORE
	    MAP_NOCORE |
#endif
	    MAP_ANON | MAP_PRIVATE;
#if defined(MAP_HUGETLB) && defined(HUGEPAGE_SIZE)
	/*
	 * PREFER Transparent Huge Pages (MAP_ANON + MADV_HUGEPAGE) over the
	 * explicit MAP_HUGETLB pool.  THP respects first-touch NUMA: each thread's
	 * scratchpad pages are placed on the DRAM node of the core that touches them
	 * first, keeping each thread's 2MB scratchpad in its own CCX/L3 and avoiding
	 * cross-CCD Infinity-Fabric traffic.  MAP_HUGETLB draws from the central
	 * hugepage pool, which is NOT NUMA/CCX-aware and can place pages on the other
	 * CCD -> cross-fabric access.  (AMD uProf measured 24.9% remote L3 misses
	 * on CCX0 / 12.5% on CCX1 with MAP_HUGETLB.)
	 */
	base = mmap(NULL, size, PROT_READ | PROT_WRITE, flags, -1, 0);
	if (base != MAP_FAILED) {
#ifdef MADV_HUGEPAGE
		madvise(base, size, MADV_HUGEPAGE);
#endif
		base_size = size;
		applog(LOG_INFO,
		    "yespower: THP-backed scratch (%zu MB, NUMA-local first-touch)",
		    size / (1024 * 1024));
	} else {
		/* Fallback: explicit MAP_HUGETLB from the central pool (no locality). */
		size_t new_size = size;
		const size_t hugepage_mask = (size_t)HUGEPAGE_SIZE - 1;
		if (size >= HUGEPAGE_THRESHOLD && size + hugepage_mask >= size) {
			int hp_flags = flags | MAP_HUGETLB;
#ifdef MAP_HUGE_2MB
			/* Explicitly request 2MB hugepages.  On systems with multiple
			 * hugepage sizes (2MB + 1GB), plain MAP_HUGETLB may default to
			 * the 1GB pool which may have 0 free -> errno=12.  MAP_HUGE_2MB
			 * (0x40000) pins the 2MB pool. */
			hp_flags |= MAP_HUGE_2MB;
#endif
			/*
			 * Linux's munmap() fails on MAP_HUGETLB mappings if size is not a
			 * multiple of huge page size, so round up to huge page size here.
			 */
			new_size = size + hugepage_mask;
			new_size &= ~hugepage_mask;
			base = mmap(NULL, new_size, PROT_READ | PROT_WRITE, hp_flags, -1, 0);
			if (base != MAP_FAILED) {
				base_size = new_size;
				applog(LOG_INFO,
				    "yespower: MAP_HUGETLB OK — %zu MB with 2MB pages",
				    new_size / (1024 * 1024));
			}
		}
	}
	if (base == MAP_FAILED) {
		applog(LOG_WARNING, "yespower: hugepage alloc FAILED (errno=%d: %s)",
		       errno, strerror(errno));
		base = NULL;
	}

#else
	applog(LOG_WARNING, "yespower: MAP_HUGETLB not available at compile time — using 4KB pages");
	base = mmap(NULL, size, PROT_READ | PROT_WRITE, flags, -1, 0);
#endif
	if (base == MAP_FAILED)
		base = NULL;
	aligned = base;
#elif defined(HAVE_POSIX_MEMALIGN)
	if ((errno = posix_memalign((void **)&base, 64, size)) != 0)
		base = NULL;
	aligned = base;
#else
	base = aligned = NULL;
	if (size + 63 < size) {
		errno = ENOMEM;
	} else if ((base = malloc(size + 63)) != NULL) {
		aligned = base + 63;
		aligned -= (uintptr_t)aligned & 63;
	}
#endif
	region->base = base;
	region->aligned = aligned;
	region->base_size = base ? base_size : 0;
	region->aligned_size = base ? size : 0;
	return aligned;
}

static inline void init_region(yespower_region_t *region)
{
	region->base = region->aligned = NULL;
	region->base_size = region->aligned_size = 0;
}

static int free_region(yespower_region_t *region)
{
	if (region->base) {
#ifdef MAP_ANON
		if (munmap(region->base, region->base_size))
			return -1;
#else
		free(region->base);
#endif
	}
	init_region(region);
	return 0;
}
