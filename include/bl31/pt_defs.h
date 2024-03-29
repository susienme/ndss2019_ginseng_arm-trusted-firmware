#define NST_MASK 	0x8000000000000000
#define NST_SHIFT	63

#define APT_MASK	0x6000000000000000
#define APT_SHIFT	61

#define UXNT_MASK	0x1000000000000000
#define UXNT_SHIFT 	60

#define PXNT_MASK	0x800000000000000
#define PXNT_SHIFT 	59

#define RES0_MASK	0x7000000000000
#define RES0_SHIFT	48

#define TRANSLATION_ADDR_MASK 			0xFFFFFFFFF000
/*#define PUD_ADDR_MASK 			0xFFFFFFFFF000
#define PMD_ADDR_MASK 			PUD_ADDR_MASK
#define PT_ADDR_MASK 			PUD_ADDR_MASK
#define OA_ADDR_MASK 			PUD_ADDR_MASK*/
#define PMD_BLOLCK_ADDR_MASK	0xFFFFFFE00000
// #define PUD_BLOLCK_ADDR_MASK	PMD_BLOLCK_ADDR_MASK

// for BLOCK
#define BLOCK_UXN_SHIFT			54
#define BLOCK_UXN_MASK			(1UL << BLOCK_UXN_SHIFT)

#define BLOCK_PXN_SHIFT			53
#define BLOCK_PXN_MASK			(1UL << BLOCK_PXN_SHIFT)

#define BLOCK_CONT_SHIFT		53
#define BLOCK_CONT_MASK			(1UL << BLOCK_CONT_SHIFT)

#define BLOCK_NG_SHIFT			11
#define BLOCK_NG_MASK			(1UL << BLOCK_NG_SHIFT)

#define BLOCK_AF_SHIFT			10
#define BLOCK_AF_MASK			(1UL << BLOCK_AF_SHIFT)

#define BLOCK_SH_SHIFT			8
#define BLOCK_SH_MASK			(0x3UL << BLOCK_SH_SHIFT)

#define BLOCK_AP_SHIFT			6
#define BLOCK_AP_MASK			(0x3UL << BLOCK_AP_SHIFT)

#define BLOCK_NS_SHIFT			5
#define BLOCK_NS_MASK			(1UL << BLOCK_NS_SHIFT)

#define BLOCK_ATTR_IDX_SHIFT	2
#define BLOCK_ATTR_IDX_MASK		(0x31UL << BLOCK_ATTR_IDX_SHIFT)

#define PTE_UXN_SHIFT 			BLOCK_UXN_SHIFT
#define PTE_UXN_MASK 			BLOCK_UXN_MASK
#define PTE_PXN_SHIFT 			BLOCK_PXN_SHIFT
#define PTE_PXN_MASK 			BLOCK_PXN_MASK
#define PTE_CONT_SHIFT 			BLOCK_CONT_SHIFT
#define PTE_CONT_MASK 			BLOCK_CONT_MASK
#define PTE_NG_SHIFT 			BLOCK_NG_SHIFT
#define PTE_NG_MASK 			BLOCK_NG_MASK
#define PTE_AF_SHIFT 			BLOCK_AF_SHIFT
#define PTE_AF_MASK 			BLOCK_AF_MASK
#define PTE_SH_SHIFT 			BLOCK_SH_SHIFT
#define PTE_SH_MASK 			BLOCK_SH_MASK
#define PTE_AP_SHIFT 			BLOCK_AP_SHIFT
#define PTE_AP_MASK 			BLOCK_AP_MASK
#define PTE_NS_SHIFT 			BLOCK_NS_SHIFT
#define PTE_NS_MASK 			BLOCK_NS_MASK
#define PTE_ATTR_IDX_SHIFT 		BLOCK_ATTR_IDX_SHIFT
#define PTE_ATTR_IDX_MASK 		BLOCK_ATTR_IDX_MASK

#define GET_FIELD(e, name)\
	((e & name##_MASK) >> name##_SHIFT)

#define GET_PTE_FIELD(e, name)\
	((e & PTE_##name##_MASK) >> PTE_##name##_SHIFT)

#define GET_TABLE_ADDR(e)\
	(e & TRANSLATION_ADDR_MASK)
