
const TEMP_TABLES_NR: usize = 4;

const TEMP_VADDR_HIBITS: u64 = 0x1_C000_0000u64;
const PAR_PA_MASK: u64 = 0xFFFF_FFFF_F000u64;
const PAGEOFFSET_MASK: u64 = 0x0FFFu64;
const TRANSLATION_ADDR_MASK: u64 = 0xFFFF_FFFF_F000u64;

const OA_MASK:u64 = 0x1FF; //=0b111111111UL	// nine 1's
const PGD_SHIFT:u64 = 39;
const PUD_SHIFT:u64 = 30;
const PMD_SHIFT:u64 = 21;
const PT_SHIFT:u64 = 12;

use debug::*;
use spin::Once;
use spin::Mutex;

extern {
	pub fn getTempTables_native() -> *mut u64;
	pub fn getL1XlationTable_native() -> *const u64;
	pub fn memset(s: *mut u8, c: i32, n: usize) -> *const u8;

	// for debug. Remove later
	// pub fn printTempTables();
}

static L1_TABLE: Once<u64> = Once::new();
static EMPTY_TABLE_MAP: Mutex<[bool; TEMP_TABLES_NR]> = Mutex::new([false; TEMP_TABLES_NR]);

fn getL1XlationTable() -> *mut u64 {
	*L1_TABLE.call_once(|| {
		unsafe{getL1XlationTable_native() as u64} 
	}) as *mut u64
}

fn getTempTable(idx: isize) -> *mut u64 {
	let tables = unsafe{getTempTables_native()};
	unsafe{tables.offset(512*idx)}
}

/*pub fn getOccupiedTableCount() -> u64 {
	let mut count = 0u64;
	let tempMap = *EMPTY_TABLE_MAP.lock();

	for i in 0..TEMP_TABLES_NR {
		if tempMap[i] { count = count + 1; }
	}

	count
}*/

/*
 * This minimizes the "unsafe block".
 */
pub fn userVaddr2PaddrEx(vaddr: u64, bGetPageAddr: bool) -> u64 {
	let mut out: u64;
	unsafe {
		asm! (
			"
			at s1e0r, $1
			mrs $0, par_el1
			"
			: "=r" (out)
			: "r" (vaddr)
			: "memory"
			);
	}

	// Now, 'out' has PAR. Thus:
	// 1. extract PA
	// 2. or with page_offset if !bGetPageAddr
	out = out & PAR_PA_MASK;
	if !bGetPageAddr { out = out | (vaddr & PAGEOFFSET_MASK); }
	out
}

pub fn el3Vaddr2Paddr(vaddr: u64, bGetPageAddr: bool) -> u64 {
	let mut out: u64;
	unsafe {
		asm! (
			"
			at s1e3r, $1
			mrs $0, par_el1
			"
			: "=r" (out)
			: "r" (vaddr)
			: "memory"
			);
	}

	out = out & PAR_PA_MASK;
	if !bGetPageAddr { out = out | (vaddr & PAGEOFFSET_MASK); }
	out
}

pub fn tlbi_vaddr(vaddr: u64) {
	let vaddr = vaddr << 12;
	unsafe {
		asm! (
			"
			tlbi vae3is, $0
			isb
			"
			:
			: "r" (vaddr)
			:
			);
	}
}

fn getEntry(pTable: *const u64, idx: isize) -> u64 {
	unsafe{*pTable.offset(idx)}
}

fn setEntry(pTable: *mut u64, idx: isize, entry: u64) -> u64 {
	unsafe{*pTable.offset(idx) = entry};
	getEntry(pTable, idx)
}

fn getTranslationAddrFromEntry(entry: u64) -> *mut u64 {
	(entry & TRANSLATION_ADDR_MASK) as *mut u64
}

/*
 * find a temp table
 * zero the table
 * return the table
 */
fn getEmptyTable() -> *mut u64{
	let mut emptyTableMap_lock = EMPTY_TABLE_MAP.lock();
	let mut emptyTableMap = *emptyTableMap_lock;

	for i in 0..TEMP_TABLES_NR {
		if emptyTableMap[i] {continue;}
		(*emptyTableMap_lock)[i] = true;

		let pTable = getTempTable(i as isize);
		return unsafe{memset(pTable as *mut u8, 0, 4096) as *mut u64}
	}


	0 as *mut u64
}

fn putTable(pTable: *const u64) {
	let mut emptyTableMap_lock = EMPTY_TABLE_MAP.lock();
	let mut emptyTableMap = *emptyTableMap_lock;
	// let emptyTables = getL1XlationTable();

	for i in 0..TEMP_TABLES_NR {
		if emptyTableMap[i] && getTempTable(i as isize) as *const u64== pTable {
			// emptyTableMap[i] = false;
			(*emptyTableMap_lock)[i] = false;
			return;
		}
	}
}

/*
 * Map @uaddr to a temp address and return the mapped temp addr.
 *
 * When we use 48-bit vaddr (or IA), we use 4-level translation.
 * In this case, the level-0 index is [47:39].
 *
 * Original implementation uses 32-bit vaddr for EL3, thus, we use three level translation because [47:39] contains zeroes.
 * I.e., we have level 1-3 translation tables. There is no level 0 translation which is unnecessary due to [47:39] = 0's.
 *
 * In the following implementation, I use three terms to reflect the 3-level translations: PUD, PMD, and PT. 
 * I.e., no PGD.
 */
pub fn tempMap(uvaddr: u64) -> u64{
 	let mut idx = 0 as isize;
 	let mut indices: [isize; 3] = [0; 3];
 	let paddr_page = userVaddr2PaddrEx(uvaddr, true /*a page addr*/);
 	let tempVaddr = uvaddr | TEMP_VADDR_HIBITS;

 	let mut pTable: *mut u64;
 	let mut pNextTable: *mut u64;
 	let l1_xlation_table = getL1XlationTable();
 	let mut entry: u64 = 0;

 	idx = PUD_IDX(tempVaddr);
 	indices[0] = idx;
 	entry = getEntry(l1_xlation_table, idx);
 	if entry != 0 { pTable = getTranslationAddrFromEntry(entry); }
 	else {
 		pTable = getEmptyTable();
 		entry = setEntry(l1_xlation_table, idx, (pTable as u64) | 0x3u64);
 	}

 	idx = PMD_IDX(tempVaddr);
 	indices[1] = idx;
 	entry = getEntry(pTable, idx);
 	if entry != 0 { pNextTable = getTranslationAddrFromEntry(entry); }
 	else {
 		pNextTable = getEmptyTable();
 		entry = setEntry(pTable, idx, (pNextTable as u64) | 0x703u64);
 	}
 	pTable = pNextTable;

 	idx = PT_IDX(tempVaddr);
 	indices[2] = idx;
 	entry = getEntry(pTable, idx);
 	if entry == 0 {
 		entry = setEntry(pTable, idx, paddr_page | (0x1u64 << 54 /*XN*/) | (0x1u64 << 5 /*NS*/) | 0x3u64 /* page */ | (0x1u64 << 10 /* AF */) );
 	} else { 
 		ymh_log_str("PTE is already TAKEN:\0");
 		ymh_log_hex(entry);
 		ymh_log_nl();
 	}

 	tlbi_vaddr(tempVaddr);

 	// check -- unnecessary but...
 	indices = [-1; 3];
 	idx = PUD_IDX(tempVaddr);
 	indices[0] = idx;
 	entry = getEntry(l1_xlation_table, idx);
 	if entry == 0 { ymh_log_str("WRONG1\n\0"); } 
 	else {
 		pTable = getTranslationAddrFromEntry(entry);
 		idx = PMD_IDX(tempVaddr);
 		indices[1] = idx;
 		entry = getEntry(pTable, idx);
 		if entry == 0 { ymh_log_str("WRONG2\n\0"); }
 		else {
 			pTable = getTranslationAddrFromEntry(entry);
 			idx = PT_IDX(tempVaddr);
 			indices[2] = idx;
 			entry = getEntry(pTable, idx);
 			if entry == 0 { ymh_log_str("WRONG3\n\0");}
 			else { 
 				// ymh_log(&format!("OA {:?}\n\0", getTranslationAddrFromEntry(entry))); 
 				/*ymh_log_str("OA:\0");
 				ymh_log_hex(getTranslationAddrFromEntry(entry) as u64); 
 				ymh_log_nl();*/
 			}
 		}
 	}

 	tempVaddr
}

/*
 * See comment on tempMap(). I don't use PGD.
 *
 * I assume we have only a single page is mapped temporarily.
 * So, for now, I unmap the page and remove all tables.
 */
pub fn tempUnmap(tempVaddr: u64) {
	let mut idx_pud = 0 as isize;
	let mut idx_pmd = 0 as isize;
	let mut idx_pt = 0 as isize;
	let l1_xlation_table = getL1XlationTable();
	let mut entry: u64 = 0;
	let mut pPmd: *mut u64;
 	let mut pPt: *mut u64;

	idx_pud = PUD_IDX(tempVaddr);
	entry = getEntry(l1_xlation_table, idx_pud);
	if entry == 0u64 { ymh_log_str("WRONG1\n\0"); return; }
	else {
		pPmd = getTranslationAddrFromEntry(entry);
		idx_pmd = PMD_IDX(tempVaddr);
		entry = getEntry(pPmd, idx_pmd);
		if entry == 0u64 { ymh_log_str("WRONG2\n\0"); return; }
		else {
			pPt = getTranslationAddrFromEntry(entry);
			idx_pt = PT_IDX(tempVaddr);
			entry = getEntry(pPt, idx_pt);
			if entry == 0u64 { ymh_log_str("WRONG3\n\0"); return; }

			// free PT
			putTable(pPt);
			setEntry(pPmd, idx_pmd, 0);
		}

		//free PMD
		putTable(pPmd);
		setEntry(l1_xlation_table, idx_pud, 0);
	}
}

fn getTtbr1_el1() -> *const u64 {
	let mut out: *const u64;
	unsafe {
		asm! ("mrs $0, ttbr1_el1"
			: "=r" (out)
			:
			: "memory"
			);
	}
	out
}

macro_rules! READ_KERN_PA {
	($kpaddr:expr, $out:expr) => {{
		unsafe{
			asm! (
				"
				mrs x15, sctlr_el3 		// x15 preserves SCTLR
				bic x15, x15, #1

				mov x10, $1	// kpaddr

				msr sctlr_el3, x15 		// no MMU ----------------- NO MEM ACCESS BELOW -----------
				isb sy

				ldr x9, [x10]			// COPY

				dmb sy
				orr x15, x15, #1
				msr sctlr_el3, x15 		// yes MMU ----------------- NO MEM ACCESS ABOVE -----------
				isb sy
				mov $0, x9
				"
				: "=r" ($out)
				: "r" ($kpaddr)
				: "memory", 
				"x15", 	// sctrl save
				"x9", 	// out
				"x10"	// src_Val
				);
		}
	}};
}

fn tableWalk_pt(pt_paddr: u64) {
	for i in 0..512 {
		// let pte = readKernPA( (pt_paddr) + 8*i );
		let mut pte: u64;
		READ_KERN_PA!(((pt_paddr) + 8*i), pte);
		if pte != 0 {
			if (pte & 0b11) == 0b11 {
				let pagePaddr = pte & 0xFFFF_FFFF_F000;
			}
		}
	}
}

fn tableWalk_pmd(pmd_paddr: u64) {
	for i in 0..512 {
		let mut pmd_e: u64;
		READ_KERN_PA!(((pmd_paddr) + 8*i), pmd_e);
		if pmd_e != 0 {
			if (pmd_e & 0b11) == 0b01 {
				let pt_paddr = pmd_e & 0xFFFF_FFFF_F000;
				tableWalk_pt(pt_paddr);
			} //else {ymh_log_str("PMD_E->BLOCK\n\0");}
		}
	}
}

fn tableWalk_pud(pud_paddr: u64) {
	for i in 0..512 {
		let mut pud_e: u64;
		READ_KERN_PA!(((pud_paddr) + 8*i), pud_e);
		if pud_e != 0 {
			let pmd_paddr = pud_e & 0xFFFF_FFFF_F000;
			tableWalk_pmd(pmd_paddr);
		}
	}
}

pub fn checkKernelPT() {
	let ttbr1_el1 = getTtbr1_el1() as u64;
	for i in 0..512 {
		let mut pgd_e: u64;
		READ_KERN_PA!(((ttbr1_el1) + 8*i), pgd_e);


		if pgd_e != 0 {
			let pud_paddr = pgd_e & 0xFFFF_FFFF_F000;
			tableWalk_pud(pud_paddr);
		}
	}
}

/*
 * Index functions
 */
fn PUD_IDX(va: u64) -> isize {
	((va >> PUD_SHIFT) & OA_MASK) as isize
}

fn PMD_IDX(va: u64) -> isize {
	((va >> PMD_SHIFT) & OA_MASK) as isize
}

fn PT_IDX(va: u64) -> isize {
	((va >> PT_SHIFT) & OA_MASK) as isize
}
