/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SELFTESTS_VFIO_LIB_INCLUDE_LIBVFIO_IOMMU_H
#define SELFTESTS_VFIO_LIB_INCLUDE_LIBVFIO_IOMMU_H

#include <linux/list.h>
#include <linux/types.h>

#include <libvfio/assert.h>

typedef u64 iova_t;

struct iommu_mode {
	const char *name;
	const char *container_path;
	unsigned long iommu_type;
};

struct dma_region {
	struct list_head link;
	void *vaddr;
	iova_t iova;
	u64 size;
};

struct iommu {
	const struct iommu_mode *mode;
	int container_fd;
	int iommufd;
	u32 ioas_id;
	struct list_head dma_regions;
};

/*
 * Pass NULL for iommu_mode to use the most preferred IOMMU mode that is
 * available on the current system. iommu_init() fails the test if the mode
 * is not available, so check iommu_mode_is_available() first to skip instead.
 */
struct iommu *iommu_init(const char *iommu_mode);
void iommu_cleanup(struct iommu *iommu);

/*
 * Returns true if the given IOMMU mode is available on the current system,
 * or, if iommu_mode is NULL, if any IOMMU mode is available.
 */
bool iommu_mode_is_available(const char *iommu_mode);

/*
 * Returns a message explaining that the given IOMMU mode is not available,
 * or, if iommu_mode is NULL, that no IOMMU mode is available, e.g. for tests
 * to print when skipping. The returned string may be overwritten by the next
 * call.
 */
const char *iommu_mode_unavailable_msg(const char *iommu_mode);

int __iommu_map(struct iommu *iommu, struct dma_region *region);

static inline void iommu_map(struct iommu *iommu, struct dma_region *region)
{
	VFIO_ASSERT_EQ(__iommu_map(iommu, region), 0);
}

int __iommu_unmap(struct iommu *iommu, struct dma_region *region, u64 *unmapped);

static inline void iommu_unmap(struct iommu *iommu, struct dma_region *region)
{
	VFIO_ASSERT_EQ(__iommu_unmap(iommu, region, NULL), 0);
}

int __iommu_unmap_all(struct iommu *iommu, u64 *unmapped);

static inline void iommu_unmap_all(struct iommu *iommu)
{
	VFIO_ASSERT_EQ(__iommu_unmap_all(iommu, NULL), 0);
}

int __iommu_hva2iova(struct iommu *iommu, void *vaddr, iova_t *iova);
iova_t iommu_hva2iova(struct iommu *iommu, void *vaddr);

struct iommu_iova_range *iommu_iova_ranges(struct iommu *iommu, u32 *nranges);

#define MODE_VFIO_TYPE1_IOMMU "vfio_type1_iommu"
#define MODE_VFIO_TYPE1V2_IOMMU "vfio_type1v2_iommu"
#define MODE_IOMMUFD_COMPAT_TYPE1 "iommufd_compat_type1"
#define MODE_IOMMUFD_COMPAT_TYPE1V2 "iommufd_compat_type1v2"
#define MODE_IOMMUFD "iommufd"

/*
 * Generator for VFIO selftests fixture variants that replicate across all
 * possible IOMMU modes. Tests must define FIXTURE_VARIANT_ADD_IOMMU_MODE()
 * which should then use FIXTURE_VARIANT_ADD() to create the variant.
 */
#define FIXTURE_VARIANT_ADD_ALL_IOMMU_MODES(...) \
FIXTURE_VARIANT_ADD_IOMMU_MODE(vfio_type1_iommu, ##__VA_ARGS__); \
FIXTURE_VARIANT_ADD_IOMMU_MODE(vfio_type1v2_iommu, ##__VA_ARGS__); \
FIXTURE_VARIANT_ADD_IOMMU_MODE(iommufd_compat_type1, ##__VA_ARGS__); \
FIXTURE_VARIANT_ADD_IOMMU_MODE(iommufd_compat_type1v2, ##__VA_ARGS__); \
FIXTURE_VARIANT_ADD_IOMMU_MODE(iommufd, ##__VA_ARGS__)

/*
 * Skip the current kselftest harness test if _iommu_mode is not available,
 * or, if _iommu_mode is NULL, if no IOMMU mode is available. The statement
 * argument is passed to SKIP(), e.g. return.
 */
#define SKIP_IF_IOMMU_MODE_UNAVAILABLE(statement, _iommu_mode) do {		\
	const char *__iommu_mode = (_iommu_mode);				\
										\
	if (!iommu_mode_is_available(__iommu_mode))				\
		SKIP(statement, "%s",						\
		     iommu_mode_unavailable_msg(__iommu_mode));			\
} while (0)

#endif /* SELFTESTS_VFIO_LIB_INCLUDE_LIBVFIO_IOMMU_H */
