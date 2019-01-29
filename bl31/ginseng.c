// #include <debug.h>
// #include <stdlib.h>
// #include <ginseng_smc_cmd.h>
// #include <ginseng_rs.h>
// #include <string.h>
#include <platform_def.h>
#include <pt_defs.h>
#include <arch_helpers.h>
#include <xlat_tables_arch.h>
#include "../lib/xlat_tables/xlat_tables_private.h"

#define NUM_BASE_LEVEL_ENTRIES	\
       GET_NUM_BASE_LEVEL_ENTRIES(PLAT_VIRT_ADDR_SPACE_SIZE)
extern uint64_t base_xlation_table[NUM_BASE_LEVEL_ENTRIES];
#define TEMP_TABLES_NR	4
static unsigned long tempTables[TEMP_TABLES_NR][512] __aligned(4096);
unsigned long *getTempTables_native() { return (unsigned long *)tempTables; }
unsigned long *getL1XlationTable_native() { return (unsigned long *)base_xlation_table; }
