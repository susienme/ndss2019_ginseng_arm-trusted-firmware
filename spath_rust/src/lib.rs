/*
 * Assumption_0: 	Ginseng assumes that S-Section informaion is already in Monitor. 
 *					The information includes S-Section addr, hash_org, and ...
 * 					Indeed, there are many ways to deliver the info from NW or a developer. 
 *					E.g., one can sign the info and pass to Ginseng.
 *					This assumption is not a big deal.
 *
 * Assumption_100: 	Alignment fault is disalbed by the assembly code,
 * 					before calling any exported functions.
 *					The assembly code is also responsible to enable alignment fault.
 *
 */

#![allow(non_snake_case)]
#![allow(non_camel_case_types)] 
#![feature(lang_items)]
#![feature(global_allocator)]
#![feature(const_fn)]
#![feature(alloc)]
#![feature(drop_types_in_const)]
#![feature(asm)]
#![no_std]

extern crate linked_list_allocator;
#[allow(deprecated)]
extern crate alloc;
extern crate spin;

use linked_list_allocator::LockedHeap;
use alloc::Vec;
use alloc::boxed::Box;
use alloc::String;
use sha1::SHA1;
use aes::AES_ENC;
use aes::AES_DEC;
use debug::*;
use spin::Mutex;

mod sha1;
mod smc;
mod schannel;
mod memutil;
mod debug;
mod aes;
#[macro_use]
mod console;

/*extern {
	// this will not be used. but leave it for now...
	// remove this after moving all from C to Rust
	pub fn ginseng_smc(smc_cmd: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64);
}*/

#[lang = "eh_personality"] extern fn eh_personality() {}
#[lang = "panic_fmt"] #[no_mangle] pub extern fn panic_fmt() -> ! {loop{}}

#[global_allocator]
static GLOBAL: LockedHeap = LockedHeap::empty();
const HEAP_SIZE: usize = 31*4096;
const SHA1_SIZE: usize = 20;
static mut STATIC_HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];
static G_INITED: Mutex<bool> = Mutex::new(false);
static G_EXCEPTION_INITED: Mutex<bool> = Mutex::new(false);
static G_SCB_LIST: Mutex<Option<Vec<SCB>>> = Mutex::new(None);
static G_SS_STORAGE: Mutex<Option<Vec<key_values>>> = Mutex::new(None);
static G_SCB_ID: Mutex<u64> = Mutex::new(10);
static G_SS_APP2READV: Mutex<Option<Vec<app_ssreadV>>> = Mutex::new(None);
// static G_STAT: Mutex<Option<Vec<stat_app>>> = Mutex::new(None);
// static G_STAT_EXCEPT: Mutex<u64> = Mutex::new(0);
// static mut G_STAT_EXCEPT: u64 = 0;
static mut G_STAT_READV: u64 = 0;
// static G_SS_STORAGE_MESAURE: Mutex<key_values> = Mutex::new(); //>> = Mutex::new(None);

/* In a complete system, we should use the secure storage provided by TEE,
 * which is already provided by TEE and beyond the scope of Ginseng work.
 * For this work, we maintain the storage in mem for simplicity.
 */
static G_SS_STORAGE_TEE: Mutex<Option<Vec<key_value>>> = Mutex::new(None);	

const SAVE_CLEAN_CODE_STATUS_DONTCARE: u32 = 0;
const SAVE_CLEAN_CODE_STATUS_CLEAN: u32 = 1;
const SAVE_CLEAN_CODE_STATUS_CLEANMOVE: u32 = 2;
const SAVE_CLEAN_CODE_STATUS_FUNCPTR: u32 = 3;
// static mut G_SS_LIST2: Option<Vec<SS_node>> = None;
const EVAL_ENTRY_EXIT_UUID_TOP: u64 = 0x5b28c1eacea4494f;
const EVAL_ENTRY_EXIT_UUID_BOTTOM: u64 = 0x96f8809be4e130a0;

const EVAL_ENTRY_EXIT_UUID_TOP_NOSHA: u64 = 0xc1eacea4494f;
const EVAL_ENTRY_EXIT_UUID_BOTTOM_NOSHA: u64 = 0x809be4e130a0;

const EVAL_DATA_UUID_TOP: u64 = 0x1111111188888888;
const EVAL_DATA_UUID_BOTTOM: u64 = 0x8888888811111111;

const EVAL_READV_UUID_TOP: u64 = 0x1111111188888888;
const EVAL_READV_UUID_BOTTOM: u64 = 0x8888888811101111;

const EVAL_EXECTRAP_UUID_TOP: u64 = 0xcea4494f;
const EVAL_EXECTRAP_UUID_BOTTOM: u64 = 0xe4e130a0;

const EVAL_EXCEPTRAP_ML_UUID_TOP: u64 		= 0x28C94ABCE7B44DEF;
const EVAL_EXCEPTRAP_ML_UUID_BOTTOM: u64 	= 0x92B23D211730EE52;

const OTP_KEY1_UUID_TOP: u64 = 0x83fedcca14e04311;
const OTP_KEY1_UUID_BOTTOM: u64 = 0x8d62d3834d812cf8;
const OTP_KEY1: u64 = 0xA763506B4D380C72;
const OTP_KEY2_UUID_TOP: u64 = 0x0dfde1e0e1bc4b50;
const OTP_KEY2_UUID_BOTTOM: u64 = 0xa9265ae952a1b3f2;
const OTP_KEY2: u64 = 0x7ED8;

const ML_UUID_TOP: u64 = 0x0D177A015D874471;
const ML_UUID_BOTTOM_3: u64 = 0x840515C1A3A7A5E2; //0x840515c1a3a7a5e6 - 4;
const ML_UUID_BOTTOM_8: u64 = 0x840515C1A3A7A5DD; //0x840515c1a3a7a5e6 - 9;

const USER_KEY: [u64; 2] = [0x0001020304050607, 0x08090a0b0c0d0e0f];

// const CTX_GPREG_SP_EL0:u64 = 0xf8;
macro_rules! CTX_GPREG_SP_EL0 {
	() => (0xf8)
}

macro_rules! PRINT_SLIB {
	($name:expr, $id1:expr, $id2:expr) => {{
		/*ymh_log_str($name);
		ymh_log_hex($id1);
		ymh_log_hex($id2);
		ymh_log_nl();*/
	}};
}

macro_rules! PRINT_SLIB_REAL {
	($name:expr, $id1:expr, $id2:expr) => {{
		ymh_log_str($name);
		ymh_log_hex($id1);
		ymh_log_hex($id2);
		ymh_log_nl();
	}};
}

macro_rules! DISABLE_NX {
	() => {{
		unsafe {
		asm! ("
			mrs x9, sctlr_el3
			mov x10, #0x80000
			bic x9, x9, x10
			msr sctlr_el3, x9
			isb
			"
			::: "x9", "x10"
			);
	}
	}};
}

macro_rules! ENABLE_NX {
	() => {{
		unsafe {
		asm! ("
			mrs x9, sctlr_el3
			mov x10, #0x80000
			orr x9, x9, x10
			msr sctlr_el3, x9
			"
			::: "x9", "x10"
			);
	}
	}};
}

macro_rules! LED2_ON {
	() => {{
		unsafe {
			asm! ("
			ldr	x2, =0xf7020000

			mov	x1, #4
			str	w1, [x2, #16]
			"
			::: "x1", "x2"
			);
		}
	}}
}

macro_rules! LED2_OFF {
	() => {{
		unsafe {
			asm! ("
			ldr	x2, =0xf7020000

			str	wzr, [x2, #16]
			"
			::: "x2"
			);
		}
	}}
}

/*const EVAL_READV_UUID_TOP: u64 = 0x1111111188888888;
const EVAL_READV_UUID_BOTTOM: u64 = 0x8888888811111111;*/


/*struct Context {
	m_gpregs: [u64; 32], // x0-x30, sp_el0 (idx:31)
	// m_spsr_el0: u64,	<- idx 32
	// m_elr_el1: u64	<- idx 33
}

impl Context {
	fn new() -> Context {
		Context {
			m_gpregs_spsrEL0_elrEL0: [0; 34]
			// m_spsr_el0: 0, <- idx 32
			// m_elr_el1: 0   <- idx 33
		}
	}
}*/

// SS_node is per MIN(ENTRY_to_EXIT, function)
// m_start points to SS_ENTRY or function ENTRY_to_EXIT
// 
struct SS_node {
	// m_start: u64,
	// m_end: u64,
	// m_hashOrg: [u8; SHA1_SIZE],
	m_hashCal: [u8; SHA1_SIZE],
}

struct SCB {
	m_scbPKey: u64,
	m_processId: u64,
	m_threadId: u64,

	// Set to true when entering S-Section. Set to false when exiting S-Section. 
	// The entry point uses this info to remove a SCB instance when in need of more memory.
	m_bInUse: bool,
	m_sStoragePaddr: u64,
	m_name: Box<String>,
	m_slist: Vec<SS_node>,
	m_uuidTop: u64,
	m_uuidBottom: u64,
	// m_lr: u64,
	// m_elr1: u64
	m_gpregs: [u64; 32],
	m_gpregs_enc: [[u64;2]; 7],
	m_spsrEL1: u64,
	m_elrEL1: u64,
	m_bEL0ContextValid: bool
}

/*struct stat_app {
	m_processId: u64,
	m_nrExceptions: u64
}

impl stat_app {
	fn new(procID: u64) -> stat_app {
		stat_app {
			m_processId: procID,
			m_nrExceptions: 0
		}
	}
}*/

struct regNo_val {
	m_phyRegNo: u32,
	// m_val: u64
	m_encVal1: u64,
	m_encVal2: u64,
}

struct key_values {
	m_processId: u64,
	m_threadId: u64,
	m_top: u64,
	m_bottom: u64,
	m_vals: Vec<regNo_val>,
	// val: u64
	m_scbPKey: u64
}

struct key_value{
	m_top: u64,
	m_bottom: u64,
	m_val: u64
}

struct app_ssreadV {
	m_processId: u64,
	m_ssReadV: u64
}

impl app_ssreadV {
	fn new(processId: u64, ssReadV: u64) -> app_ssreadV {
		app_ssreadV {
			m_processId: processId,
			m_ssReadV: ssReadV
		}
	}
}

impl regNo_val {
	// fn new(regNo: u32, val: u64) -> regNo_val {
	fn new(regNo: u32, encVal1: u64, encVal2: u64) -> regNo_val {
		regNo_val {
			m_phyRegNo: regNo,
			// m_val: val
			m_encVal1: encVal1,
			m_encVal2: encVal2
		}
	}
}


impl key_values {
	fn new(id1: u64, id2: u64, token_top: u64, token_bottom: u64) -> key_values {
		key_values {
			m_processId: id1,
			m_threadId: id2,
			m_top: token_top,
			m_bottom: token_bottom,
			m_vals: Vec::new(),
			m_scbPKey: 0
		}
	}
}

impl key_value {
	fn new(token_top: u64, token_bottom: u64, val: u64) -> key_value {
		key_value {
			m_top: token_top,
			m_bottom: token_bottom,
			m_val: val
		}
	}
}

// to check whether we really drop objs
/*impl Drop for SS_node {
	fn drop(&mut self) {
		ymh_log_str("DROP - SS_node\n\0");
	}
}*/

impl SS_node {
	fn new() -> SS_node {
		SS_node {
			// m_start: 0,
			// m_end: 0,
			// m_hashOrg: [0; SHA1_SIZE],
			m_hashCal: [0; SHA1_SIZE]
		}
	}
}

// to check whether we really drop objs
impl Drop for SCB {
	fn drop(&mut self) {
		ymh_log_str("DROP - SCB\n\0");
	}
}

impl SCB {
	fn new() -> SCB {
		SCB {
			m_scbPKey: 0,
			m_processId: 0,
			m_threadId: 0,
			m_bInUse: false,
			m_sStoragePaddr: 0,
			m_name: Box::new(String::from("00000000\0")),
			m_slist: Vec::new(),
			m_uuidTop: 0,
			m_uuidBottom: 0,
			// m_lr: 0,
			// m_elr1: 0
			// m_gpregs_spsrEL0_elrEL0: [0; 34]
			m_gpregs: [0; 32],
			m_gpregs_enc: [[0,0]; 7],
			m_spsrEL1: 0,
			m_elrEL1: 0,
			m_bEL0ContextValid: false
		}
	}
}


#[no_mangle]
pub extern fn rsPing(k: i64) -> i64 {k + 1}

fn getSCBPKey() -> u64 {
	let mut id_lock = G_SCB_ID.lock();
	let cur = *id_lock;
	*id_lock = cur + 1;

	cur

	/*let cur = unsafe{G_SCB_ID};
	unsafe{G_SCB_ID = G_SCB_ID + 1}

	cur*/
}
fn initTEEStorage() {
	let mut storageLock = G_SS_STORAGE_TEE.lock();
	*storageLock = Some(Vec::new());
	if let Some(ref mut storage) = *storageLock {
		// for measurement
		storage.push(key_value::new(EVAL_DATA_UUID_TOP, EVAL_DATA_UUID_BOTTOM, 0x1234567812345678));
		/*storage.push(key_value::new(0x2222222288888888, 0x8888888822222222, 0x1234567812345678));
		storage.push(key_value::new(0x3333333388888888, 0x8888888833333333, 0x1234567812345678));
		storage.push(key_value::new(0x4444444488888888, 0x8888888844444444, 0x1234567812345678));
		storage.push(key_value::new(0x5555555588888888, 0x8888888855555555, 0x1234567812345678));
		storage.push(key_value::new(0x6666666688888888, 0x8888888866666666, 0x1234567812345678));
		storage.push(key_value::new(0x7777777788888888, 0x8888888877777777, 0x1234567812345678));
		storage.push(key_value::new(0x8888888888888888, 0x8888888888888888, 0x1234567812345678));*/

		// for OTP
		storage.push(key_value::new(OTP_KEY1_UUID_TOP, OTP_KEY1_UUID_BOTTOM, OTP_KEY1));
		storage.push(key_value::new(OTP_KEY2_UUID_TOP, OTP_KEY2_UUID_BOTTOM, OTP_KEY2));

		// for wpa_supplicant
		storage.push(key_value::new(0x0fddf448fbb9449e,	0x88b13bfd61262ca0,	0x7473657467636572));
		storage.push(key_value::new(0x61c95a62cce2430e,	0xa3862b37df7ff3dd, 0x0));

		// for ML
		storage.push(key_value::new(ML_UUID_TOP, ML_UUID_BOTTOM_3, 3));
		storage.push(key_value::new(ML_UUID_TOP, ML_UUID_BOTTOM_8, 8));
	}
}

fn findFromTEEStorage(token_top: u64, token_bottom: u64, bUpdate: bool, newVal: u64, bCreate: bool) -> u64 {
	// no token -> get input from the secure console
	if token_top == 0 && token_bottom == 0 {
		LED2_ON!();

		/*let line: String = console::getLine().into_iter().collect();
		ymh_log_str("You entered: \0");
		ymh_log_str(line.as_str());
		ymh_log_nl();*/

		let line = console::getHexLine();
		LED2_OFF!();

		return line;
	}
	
	if let Some(ref mut storage) = *G_SS_STORAGE_TEE.lock() {
		for kv in storage {
			if 	kv.m_top == token_top &&
				kv.m_bottom == token_bottom {
					if bUpdate {kv.m_val = newVal}
					return kv.m_val;
			}
		}

	} else {
		ymh_log_str("TEE Storage is not initialized\n\0");
		loop{}
	}

	if bCreate {
		if let Some(ref mut storage) = *G_SS_STORAGE_TEE.lock() {
			storage.push(key_value::new(token_top, token_bottom, newVal));
			return newVal;
		}
	}
	ymh_log_str("top:\0");
	ymh_log_hex(token_top);
	ymh_log_nl();
	ymh_log_str("bottom:\0");
	ymh_log_hex(token_bottom);
	ymh_log_str("\nToken is not found in TEE Storage. Returning 0x7531\n\0");
	0x7531
}

fn get_cpuid() -> u64 {
	let mut cpuid: u64;
	unsafe {
		asm! (
			"
			mrs x0, mpidr_el1
			and x1, x0, #0xFF
 			and x0, x0, #0xFF00
 			add $0, x1, x0, LSR #6
			"
			: "=r" (cpuid)
			:
			: "memory", "x0", "x1"
			);
	}

	cpuid
}

fn get_tpidr_el3() -> u64 {
	let mut out: u64;
	unsafe {
		asm! (
			"
			mrs $0, tpidr_el3
			"
			: "=r" (out)
			:
			: "memory"
			);
	}

	out
}

fn initHCR() {
	// 0x4000000 : TVM (TTBR_EL1)
	// 0x8000000 : TGE (Sync Exception from NS-EL0)
	// 0x20000000 : HCD
	// 0xC000000 : TVM | TGE
	unsafe {
		asm! (
			"
			mrs x0, hcr_el2
			orr x0, x0, #0x8000000
			msr hcr_el2, x0
			"
			:
			:
			: "x0"
			);
	}
	// checkHCR();
}

/*fn checkHCR() {
	let mut out_hcr: u64;
	unsafe {
		asm! (
			"mrs $0, hcr_el2"
			: "=r" (out_hcr)
			:
			: "memory"
			);
	}

	let mut out_daif: u64;
	unsafe {
		asm! (
			"mrs $0, daif"
			: "=r" (out_daif)
			:
			: "memory"
			);
	}

	let mut out_elr: u64;
	unsafe {
		asm! (
			"mrs $0, elr_el3"
			: "=r" (out_elr)
			:
			: "memory"
			);
	}

	ymh_log_str("HCR_EL2(\0");
	ymh_log_hex(get_cpuid());
	ymh_log_str("):\0");
	ymh_log_hex(out_hcr);
	ymh_log_str(" DAIF:\0");
	ymh_log_hex(out_daif);
	ymh_log_str("elr:\0");
	ymh_log_hex(out_elr);
	ymh_log_nl();
}*/

/*
 * rtn: 0: Ok; 99: already initialized
 */
#[no_mangle]
pub extern fn rsInit() -> u64{
	let mut gInited = G_INITED.lock();

	// For eval, allow re-init
	if *gInited {
		ymh_log_str("ALREADY INITIALIZED\n\0");
		return 99;
	} else {
		unsafe {
			GLOBAL.lock().init(STATIC_HEAP.as_ptr() as usize, HEAP_SIZE as usize);
		}

		// ymh_log_str("RUST INIT-ing\n\0");

		*G_SCB_LIST.lock() = Some(Vec::new());
		*G_SS_STORAGE.lock() = Some(Vec::new());
		// *G_SS_STORAGE_MESAURE.lock() = Some(key_values::new(0, 0));
		*G_SS_APP2READV.lock() = Some(Vec::new());
		// *G_STAT.lock() = Some(Vec::new());

		// ymh_log_str("RUST INIT DONE\n\0");

		initTEEStorage();
		// initHCR();

		*gInited = true;
	}
	0
}


fn getreadVFromProcID(processId: u64) -> u64 {
	let mut list_lock = G_SS_APP2READV.lock();

	// let Some(list) = *G_SS_APP2READV.lock();
	if let Some(ref mut list) = *list_lock {
		for pair in list {
			if pair.m_processId == processId {
				return pair.m_ssReadV;
			}
		}
	}

	0
}

fn addApp2ReadV(processId: u64, readV: u64) {
	let mut list_lock = G_SS_APP2READV.lock();

	// let Some(list) = *G_SS_APP2READV.lock();
	if let Some(ref mut list) = *list_lock {
		list.push(app_ssreadV::new(processId, readV));
	}
}

/*fn isInited() -> bool{
	*G_INITED.lock()
}*/

fn initRS() {
	let gInited = { *G_INITED.lock() };	// drop the lock and only get the value
	if !gInited {
		rsInit();
	}
}

/*fn userVaddr2Paddr(vaddr: u64) -> u64 {
	let mut out: u64;
	unsafe {
		asm! (
			"
			mov x1, $1
			at s1e0r, x1
			mrs x0, par_el1
			ubfx x0, x0, #12, #36 // extract PA

			// PA | page_offset
			lsl x0, x0, #12
			ubfx x1, x1, #0, #12 // extract PA

			orr $0, x0, x1
			"
			: "=r" (out)
			: "r" (vaddr)
			: "memory", "x0", "x1"
			);
	}
	out
}*/

fn getElr3() -> u64 {
	let mut out: u64;
	unsafe {
		asm! ("mrs $0, elr_el3"
			: "=r" (out)
			:
			: "memory"
			);
	}
	out
}



/*fn getSpsrEL1() -> u64 {
	let mut out: u64;
	unsafe {
		asm! ("mrs $0, spsr_el1"
			: "=r" (out)
			:
			: "memory"
			);
	}
	out
}

fn setSpsrEL1(spsr: u64){
	unsafe {
		asm! ("mrs $0, spsr_el1"
			: 
			: "r" (spsr)
			: "memory"
			);
	}
}*/

macro_rules! GET_SPSR_EL1 {
	($dest:expr) => {{
		unsafe {
		asm! ("mrs $0, spsr_el1"
			: "=r" ($dest)
			:
			: "memory"
			);
	}
	}};
}


fn getElrEl1() -> u64 {
	let mut out: u64;
	unsafe {
		asm! ("mrs $0, elr_el1"
			: "=r" (out)
			:
			: "memory"
			);
	}
	out
}

macro_rules! GET_ELR_EL1 {
	($dest:expr) => {{
		unsafe {
		asm! ("mrs $0, elr_el1"
			: "=r" ($dest)
			:
			: "memory"
			);
	}
	}};
}

macro_rules! GET_ELR_EL3 {
	($dest:expr) => {{
		unsafe {
		asm! ("mrs $0, elr_el3"
			: "=r" ($dest)
			:
			: "memory"
			);
	}
	}};
}

macro_rules! GET_ELR_EL1_WITHOFFSET {
	($dest:expr) => {{
		unsafe {
		asm! (
			"
			mrs $0, elr_el1
			sub $0, $0, #4
			"
			: "=r" ($dest)
			:
			: "memory"
			);
	}
	}};
}

macro_rules! GET_ESR_EL1_EC {
	($dest:expr) => {{
		unsafe {
		asm! ("
			mrs $0, esr_el1
			lsr $0, $0, #26    // ESR_ELx_EC_SHIFT
			"
			: "=r" ($dest)
			:
			: "memory"
			);
	}
	}};
}

fn setElr1(elr1: u64) {
	unsafe {
		asm! ("msr elr_el1, $0"
			: 
			: "r" (elr1)
			: "memory"
			);
	}
}

fn setSpsrEl1(spsr: u64) {
	unsafe {
		asm! ("msr spsr_el1, $0"
			: 
			: "r" (spsr)
			: "memory"
			);
	}
}

fn getTtbr0_el1() -> u64 {
	let mut out: u64;
	unsafe {
		asm! ("mrs $0, ttbr0_el1"
			: "=r" (out)
			:
			: "memory"
			);
	}
	out
}

fn getHcr_el2() -> u64 {
	let mut out: u64;
	unsafe {
		asm! ("mrs $0, hcr_el2"
			: "=r" (out)
			:
			: "memory"
			);
	}
	out
}

// fn g


/*fn getMdcr_el3() -> u64{
	let mut out: u64;
	unsafe {
		asm! ("mrs $0, mdcr_el3"
			: "=r" (out)
			:
			: "memory"
			);
	}
	out
}*/

/*fn setPMCR() -> u64 {
	let mut out: u64;
	unsafe {
		asm! (
			"
			mov x0, 0b101
			msr pmuserenr_el0, x0
			mrs $0, pmuserenr_el0
			"
			: "=r" (out)
			:
			: "memory", "x0"
			);
	}
	out
}

fn getPMCR() -> u64 {
	let mut out: u64;
	unsafe {
		asm! (
			"
			mrs $0, pmcr_el0
			"
			: "=r" (out)
			:
			: "memory", "x0"
			);
	}
	out
}

fn getPMUSERENR() -> u64 {
	let mut out: u64;
	unsafe {
		asm! (
			"
			mrs $0, PMUSERENR_el0
			"
			: "=r" (out)
			:
			: "memory", "x0"
			);
	}
	out
}

fn getPMCCFILTR() -> u64 {
	let mut out: u64;
	unsafe {
		asm! (
			"
			mrs $0, PMCCFILTR_el0
			"
			: "=r" (out)
			:
			: "memory", "x0"
			);
	}
	out
}

fn getPMCCNTR() -> u64 {
	let mut out: u64;
	unsafe {
		asm! (
			"
			mrs $0, PMCCNTR_el0
			"
			: "=r" (out)
			:
			: "memory", "x0"
			);
	}
	out
}*/

fn dci(dest_pa: u64) {
	unsafe {
		asm! (
			"dc ivac, $0
			dmb sy
			isb sy"
			:
			: "r" (dest_pa)
			: "memory"
			);
	}
}

fn dcci(dest_pa: u64) {
	unsafe {
		asm! (
			"dc civac, $0
			dmb sy
			isb sy"
			:
			: "r" (dest_pa)
			: "memory"
			);
	}
}

/*fn isKernelAddr(vaddr: u64) -> bool {
	return vaddr > 0xFFFF_0000_0000_0000;
}*/

macro_rules! IS_KERN_ADDR {
	($vaddr:expr) => {{
		$vaddr > 0xFFFF_0000_0000_0000
	}};
}

static VA_BITS: u64 = 0x30;
static PAGE_OFFSET: u64 	= 0xFFFF_8000_0000_0000;

/*#[cfg(feature = "qemu")]
static KIMAGE_VOFFSET: u64 	= 0xFFFE_FFFF_C800_0000;
#[cfg(feature = "qemu")]
static PHYS_OFFSET: u64 	= 0x4000_0000;*/

#[cfg(not(feature = "qemu"))]
static KIMAGE_VOFFSET: u64 	= 0xFFFF000008000000;
#[cfg(not(feature = "qemu"))]
static PHYS_OFFSET: u64 	= 0x0;

fn BIT(nr: u64)	-> u64 {(1 as u64) << nr}
fn __pa(x: u64)	-> u64 { 
	if (x & BIT(VA_BITS - 1)) == 0 {
		(x - KIMAGE_VOFFSET)
	} else {
		(x & !PAGE_OFFSET) + PHYS_OFFSET
	} 
}

/*struct paddr_node {
	m_paddr_start: u64,
	m_len: u64
}

fn getNextPageAddr(cur_paddr: u64) -> u64 { ((cur_paddr >> 0x10) + 1) << 0x10 }
fn getRemaingSizeInPage(cur_paddr: u64) -> u64 { ((cur_paddr >> 0x10) + 1) << 0x10 - cur_paddr }

fn getSSectionPaddrs(starting_vaddr: u64, len: usize) -> Vec<paddr_node> {
	let mut v = Vec::new();
	let mut paddr = userVaddr2Paddr(starting_vaddr);
	let mut bStop = false;
	let mut len = len;

	while bStop {
		if (paddr + len as u64) < getNextPageAddr(paddr) {bStop = true;}	// Now, we can go out. Time to go out!
		
		let lenUntilPageEnd = getRemaingSizeInPage(paddr);
		if lenUntilPageEnd > len as u64 {len = 0;} else {len -= lenUntilPageEnd as usize;}

	}
	v
}*/

// for debugging...
/*#[no_mangle]
pub extern fn checkTtbr() {
	let mut sctlr_el3: u64 = 0;
	let mut ttbr0_el3: u64 = 0;
	unsafe {
		asm! (
			"
			mrs x0, sctlr_el3
			mov $0, x0

			mrs x0, ttbr0_el3
			mov $1, x0
			"
			: "=r" (sctlr_el3), "=r" (ttbr0_el3)
			:
			: "memory", "x0"
			);
	}

	// ymh_log(&format!("sctlr_el3(0x{:X})\n\0", sctlr_el3));
	// ymh_log_str("sctlr_el3:\0");	ymh_log_hex(sctlr_el3);	ymh_log_nl();
	// ymh_log(&format!("ttbr0_el3(0x{:X})\n\0", ttbr0_el3));
	// ymh_log_str("ttbr0_el3:\0");	ymh_log_hex(ttbr0_el3);	ymh_log_nl();
} */

/*fn read20test_whenUserAddr(vaddr: u64) {
	// let p: *const u64 = vaddr as *const u64;

	if vaddr < 0xFFFF_FFFF_FFFF {
		ymh_log(&format!("from USER vaddr(0x{:X})\n\0", vaddr));
	}
}*/

// for debugging,..
/*fn printSCBList() {
	let slist_lock = G_SCB_LIST.lock();
	if let Some(ref vSCB) = *slist_lock {
		for scb in vSCB {
			// ymh_log_str("NAME: \0");
			// ymh_log_str(&*scb.m_name);
			// ymh_log_str("\nID:\0");
			// ymh_log_hex(scb.m_processId);
			// ymh_log_nl();
			for node in &scb.m_slist {
				// sha1Dump(node.m_hashCal);
			}
			ymh_log_nl();
		}
	} else {
		ymh_log_str("ERROR - printSCBList()\n\0");
		loop {}
	}
}*/

/*
 * measureSSection() is called on every S-Section
 * e.g., if a S-Section contains a function call,
 *		measureSSection() is called two times: one for the root S-Section; the other for the function
 * Each time measureSSection() is called, measureSSection() adds a new SS_note instance containing starting and ending addresses and SHA1
 * With the Assumption_0, we assume that we know how manay SS_nodes should be added and their internal values (addresses and SHA1).
 *
 * 1. Does code measurement 
 * 2. Saves the value in an arbitrary location in sStoragePaddr_page
 * 3. Points the location using scb.sStoragePaddr
 */
fn measureSSection(elr: u64, sStoragePaddr_page: u64, scb: &mut SCB) {
	// elr points to a user space memory (vaddr)
	let elr_paddr = memutil::userVaddr2PaddrEx(elr, false /*not a page addr*/);
	// ymh_log(&format!("USER VADDR(0x{:X}) PADDR(0x{:X})\n\0", elr, elr_paddr));
	/*ymh_log_str("USER VADDR PADDR:\0");
	ymh_log_hex(elr);
	ymh_log_hex(elr_paddr);
	ymh_log_nl();*/

	let tempAddr = memutil::tempMap(elr);
	/*ymh_log_str("TEMPMAP() is done. Occupied temp-table count:\0");
	ymh_log_hex( memutil::getOccupiedTableCount());
	ymh_log_nl();*/

	// do the measurement!
	/*let k = unsafe {*(tempAddr as *const u32)};
	ymh_log_str("CODE_MEASURING:\0");
	ymh_log_hex( k as u64);
	ymh_log_nl();*/
	let mut node = SS_node::new();
	SHA1(tempAddr as *const u8, 20, &mut node.m_hashCal);
	// SHA1(tempAddr as *const u8, 4096, &mut node.m_hashCal);
	// rsHexdump(node.m_hashCal.as_ptr(), 20);
	scb.m_slist.push(node);

	memutil::tempUnmap(tempAddr);
	/*ymh_log_str("measurement is done. Occupied temp-table count:\0");
	ymh_log_hex( memutil::getOccupiedTableCount());
	ymh_log_nl();*/
}

/*fn checkPM() {
	ymh_log_str("PMCR_EL0:\0");
	ymh_log_hex(getPMCR());
	ymh_log_str("\nPMUSERENR_EL0:\0");
	ymh_log_hex(getPMUSERENR());
	ymh_log_str("\nPMCCFILTR_EL0:\0");
	ymh_log_hex(getPMCCFILTR());
	ymh_log_str("\nPMCCNTR_EL0:\0");
	ymh_log_hex(getPMCCNTR());
	ymh_log_nl();
}

fn pmEnableReset() {
	unsafe {
		asm! (
			"
			mov x15, 0x80000000
			msr PMCNTENSET_EL0, x15

			mov x15, 5
			mrs x14, pmcr_el0
			orr x14, x14, x15
			msr pmcr_el0, x14
			"
			::: "x15", "x14"
			);
	}
}*/

// Use this only for evaluation
// This does SHA1 on 4096 bytes
fn measureSSection_forEval(elr: u64, sStoragePaddr_page: u64, scb: &mut SCB) {
	// let elr_paddr = memutil::userVaddr2PaddrEx(elr, false /*not a page addr*/);

	let tempAddr = memutil::tempMap(elr);
	let tempAddr2 = unsafe {STATIC_HEAP.as_ptr()};

	// do the measurement!
	// let k = unsafe {*(tempAddr as *const u32)};
	// let k = unsafe {STATIC_HEAP.as_ptr()};
	/*ymh_log_str("CODE_MEASURING_FOR_EVAL:\0");
	ymh_log_hex( tempAddr2 as u64);
	ymh_log_nl();*/
	// checkPM();
	let mut node = SS_node::new();

	/*let mut t_start: u64;
	let mut t_end: u64;
	pmEnableReset();

	unsafe { asm! ("mrs $0, pmccntr_el0" : "=r" (t_start) :: "memory"); }

	for i in 0..1000 {
		SHA1(tempAddr2 as *const u8, 4096, &mut node.m_hashCal);
	}
	unsafe { asm! ("mrs $0, pmccntr_el0" : "=r" (t_end) :: "memory"); }
	ymh_log_str("SHA1 latency (4096 bytes) avg:\0");
	ymh_log_dec( (t_end-t_start)/1000 );
	ymh_log_nl();*/
	// SHA1(tempAddr2 as *const u8, 4096, &mut node.m_hashCal);
	SHA1(tempAddr2 as *const u8, 2048, &mut node.m_hashCal);
	// SHA1(tempAddr2 as *const u8, 1024, &mut node.m_hashCal);
	// SHA1(tempAddr2 as *const u8, 512, &mut node.m_hashCal);
	// SHA1(tempAddr2 as *const u8, 256, &mut node.m_hashCal);
	// SHA1(tempAddr2 as *const u8, 128, &mut node.m_hashCal);
	// SHA1(tempAddr2 as *const u8, 64, &mut node.m_hashCal);
	// scb.m_slist.push(node);

	memutil::tempUnmap(tempAddr);
}


fn getMonotonic() -> u64 {
	getSCBPKey() // why not?
}

/*
 * Retrieve ID for an S-Section
 */
fn getID() -> u64 {
	getTtbr0_el1()
}

macro_rules! GET_PROCID {
	($dest:expr) => {{
		unsafe {
			asm! ("mrs $0, ttbr0_el1"
				: "=r" ($dest)
				:
				: "memory"
				);
		}
	}};
}

macro_rules! GET_THREADID {
	($dest:expr) => {{
		unsafe {
			asm! ("mrs $0, tpidr_el0"
				: "=r" ($dest)
				:
				: "memory"
				);
		}
	}};
}

/*macro_rules! GET_SP {
	($dest:expr, $sp1:expr) => {{
		unsafe { asm! ( "ldr $0, [$1, #0xf8]" : "=r" ($dest) : "r" ($sp1) : "memory");}
	}};
}*/


/*macro_rules! GET_X {
	($sp1:expr, $regNo:expr, $dest:expr) => {{
		unsafe {
			asm! ( concat!("ldr $0, [$1, #", stringify!($regNo), "]")
				// "ldr $0, [$1, #0xf8]" 
				: "=r" ($dest) 
				: "r" ($sp1) 
				: "memory");
		}
	}};
}*/

/*fn getASID() -> u64 {
	(getTtbr0_el1() >> 48)
}*/

/* Find a SCB instnace with id, uuid_top, and uuid_bottom
 * [OLD] Returns None if not found
 * [OLD] Returns the SCB's LR if found
 * Returns false if not found
 * Returns true  if found
 *
 * @lr: ignored when bUse is false
 */
fn checkID_setUseOrNotuse(id1: u64, id2: u64,
	uuid_top: u64, uuid_bottom: u64, bUse: bool,/* lr: u64, bEntryEval: bool*/) -> bool/*Option<u64> */{
	let mut slist_lock = G_SCB_LIST.lock();

	if let Some(ref mut vSCB) = *slist_lock {
		for scb in vSCB {
			if scb.m_processId == id1 && scb.m_threadId == id2 &&
				scb.m_uuidTop == uuid_top && scb.m_uuidBottom == uuid_bottom {
				scb.m_bInUse = bUse;
				// if bUse { scb.m_lr = lr; }
				// return Some(scb.m_lr);
				return true;
			}
		}
	} else {
		ymh_log_str("ERROR - checkID_setUseOrNotuse()\n\0");
		loop {}
	}

	// None
	return false;
}

/*fn popSCB(id: u64, uuid_top: u64, uuid_bottom: u64) {
	let mut slist_lock = G_SCB_LIST.lock();
	let mut found: usize = 99;
	if let Some(ref mut vSCB) = *slist_lock {
		let mut idx: usize = 0;
		for scb in vSCB {
			if scb.m_processId == id && scb.m_uuidTop == uuid_top && scb.m_uuidBottom == uuid_bottom {
				found = idx;
				break;
			}
			idx = idx + 1;
		}
	} else {
		ymh_log_str("ERROR - checkID_setUseOrNotuse()\n\0");
		loop {}
	}

	if found == 99 {
		ymh_log_str("CANNOT POP\n\0");
		loop{}
	} else if let Some(ref mut vSCB) = *slist_lock {
		vSCB.remove(found);
	}
	// None
	// return false;
}*/


fn setSCB_noUse_withProcID(id1: u64, id2: u64, uuid_top: u64, uuid_bottom: u64) {
	let mut slist_lock = G_SCB_LIST.lock();
	if let Some(ref mut vSCB) = *slist_lock {
		for scb in vSCB {
			if scb.m_processId == id1 && scb.m_threadId == id2 &&
				(uuid_top == 0 || scb.m_uuidTop == uuid_top) && 
				(uuid_bottom == 0 || scb.m_uuidBottom == uuid_bottom) &&
				scb.m_bInUse {
					scb.m_bInUse = false;
					/*ymh_log_str("Making SCB no use pkey\0");
					ymh_log_dec(scb.m_scbPKey);
					ymh_log_nl();*/
					return;
			}
		}
	}

	ymh_log_str("Cannot find ID\0");
	ymh_log_hex(id1);
	ymh_log_hex(id2);
	ymh_log_str(" in use");
	loop {}
}

fn setSCB_withSCBPKey(pkey: u64, bUse: bool) {
	let mut slist_lock = G_SCB_LIST.lock();
	if let Some(ref mut vSCB) = *slist_lock {
		for scb in vSCB {
			if scb.m_scbPKey == pkey{
				scb.m_bInUse = bUse;
				return;
			}
		}
	}

	ymh_log_str("MUST NOT HAPPEN - CANNOT FIND SCB PKey\n\0");
	loop{};
}


/*fn checkID_inUse(scbList: &Option<Vec<SCB>>, id: u64, uuid_top: u64, uuid_bottom: u64) -> Option<&SCB> {
	// let mut slist_lock = G_SCB_LIST.lock();

	ymh_log_str("Finding inUse SCB PKey \0");
	ymh_log_dec(id);
	ymh_log_nl();

	if let Some(ref vSCB) = *scbList {
		for scb in vSCB {

			ymh_log_str("SCB PKey \0");
			ymh_log_dec(scb.m_scbPKey);
			ymh_log_str(" procID\0");
			ymh_log_hex(scb.m_processId);
			if scb.m_bInUse {
				ymh_log_str(" in use\n\0");
			} else {
				ymh_log_str(" NO use\n\0");
			}

			if scb.m_processId == id && 
				(uuid_top == 0 || scb.m_uuidTop == uuid_top) && 
				(uuid_bottom == 0 || scb.m_uuidBottom == uuid_bottom) &&
				scb.m_bInUse {

				return Some(&scb);
			}
		}
	}

	None
}*/


/*fn getSCB_elr1_inUse(procID: u64) -> u64 {
	let mut slist_lock = G_SCB_LIST.lock();

	if let Some(ref mut vSCB) = *slist_lock {
		for scb in vSCB {
			if scb.m_processId == procID && scb.m_bInUse {
				let elr1 = scb.m_elr1;
				scb.m_elr1 = 0;
				return elr1;
			}
		}
	}

	0
}

fn setSCB_elr1_inUse(procID: u64, elr1: u64) -> u64 {
	let mut slist_lock = G_SCB_LIST.lock();

	if let Some(ref mut vSCB) = *slist_lock {
		for scb in vSCB {
			if scb.m_processId == procID && scb.m_bInUse {
				scb.m_elr1 = elr1;
				return scb.m_scbPKey;
			}
		}
	}

	0
}*/

fn debug_checkContextDiff(sp1: usize, scb: &SCB) {
	for i in 1..32 as usize {
		if i == 4 {
			continue;
		}
		let newReg = unsafe {*((sp1 + i*8) as *mut u64)};
		let oldReg = scb.m_gpregs[i];
		if newReg != oldReg {
			ymh_log_str("REG_\0");
			ymh_log_dec(i as u64);
			ymh_log_hex(oldReg);
			ymh_log_str("->\0");
			ymh_log_hex(newReg);
			ymh_log_nl();
		}
	}
}

// const START_REG: usize = 9;		// 7
// const START_REG: usize = 10;		// 6
// const START_REG: usize = 11;		// 5
// const START_REG: usize = 12;		// 4
// const START_REG: usize = 13;		// 3
// const START_REG: usize = 14;		// 2
// const START_REG: usize = 15;		// 1
const START_REG: usize = 16;		// 0
fn setSCB_saveContext_inUse(sp1: usize, procID: u64/*, bSVC: bool*/) -> u64 {
	let mut slist_lock = G_SCB_LIST.lock();
	if let Some(ref mut vSCB) = *slist_lock {
		for scb in vSCB {
			if scb.m_processId == procID && scb.m_bInUse /*&& scb.m_bEL0ContextValid*/ {
				if scb.m_bEL0ContextValid {
					ymh_log_str("It should be invalid\n\0");
					loop{}
				}
				// scb.m_elr1 = elr1;
				for i in 0..32 as usize { // x0-30 / SP_EL0 : idx[0-31] count[32]
					/*ymh_log_str("Accessing[\0");
					ymh_log_dec(i as u64);
					ymh_log_str("]...\0");
					ymh_log_hex( (sp1 + i*8 ) as u64 );*/
					let val = unsafe {*((sp1 + i*8) as *const u64)};
					if i <= 15 && i >= START_REG {
						let plaintext = [0, val];
						let mut ciphertext = [0 as u64; 2];
						AES_ENC(&plaintext, &mut ciphertext, &USER_KEY);
						scb.m_gpregs_enc[15-i] = ciphertext;
					}
					scb.m_gpregs[i] = val;
					// ymh_log_str("Done\n\0");
				}
				// SPSR_EL1 / ELR_EL1
				// scb.m_spsrEL1 = getSpsrEL1();
				GET_SPSR_EL1!(scb.m_spsrEL1);
				// scb.m_elrEL1 = getElrEl1() - 4;
				GET_ELR_EL1_WITHOFFSET!(scb.m_elrEL1);
				/*if bSVC {	
					// DABT | IABT -> should return to the same address to retry
					// SVC -> return to the next address in ELR
					// scb.m_elrEL1 = scb.m_elrEL1 - 4;
				}*/
				scb.m_bEL0ContextValid = true;
				return scb.m_scbPKey;
			}
		}
	}

	0
}

fn setSCB_restoreContext_inUse(sp1: usize) -> bool {
	let mut slist_lock = G_SCB_LIST.lock();
	let procID = getID();

	if let Some(ref mut vSCB) = *slist_lock {
		for scb in vSCB {
			if scb.m_processId == procID && scb.m_bInUse && scb.m_bEL0ContextValid {

				debug_checkContextDiff(sp1, scb);

				// scb.m_elr1 = elr1;
				for i in 1..32 as usize { // x0-30 / SP_EL0 : idx[0-31] count[32]
					if i <= 15 && i >= START_REG {
						let ciphertext = scb.m_gpregs_enc[15-i];
						let mut decrypted = [0 as u64; 2];
						AES_DEC(&ciphertext, &mut decrypted, &USER_KEY);

						/*if decrypted[1] != scb.m_gpregs[i] {
							ymh_log_str("ENC/DEC Error: \0");
							ymh_log_dec(i as u64);
							ymh_log_nl();
							loop {}
						}*/
					}
					unsafe {*((sp1 + i*8) as *mut u64) = scb.m_gpregs[i]};
				}
				// unsafe {*((sp1 + 0x20) as *mut u64) = scb.m_gpregs[4]};

				// SPSR_EL1 / ELR_EL1
				// ymh_log_str("Set ELR_EL3 to\0");
				// ymh_log_hex(scb.m_elrEL1);
				// ymh_log_nl();
				// ymh_log_str("Set SPSR_EL3 to\0");
				// ymh_log_hex(scb.m_spsrEL1);
				// ymh_log_nl();
				unsafe {
					*((sp1 + 0x118) as *mut u64) = scb.m_elrEL1;
					*((sp1 + 0x110) as *mut u64) = scb.m_spsrEL1;
				}

				// setElr1(scb.m_elrEL1);
				// setSpsrEl1(scb.m_spsrEL1);

				scb.m_bEL0ContextValid = false;
				return true;
			}
		}
	}

	false
}

fn getSCBPKey_inUSE(id1: u64, id2: u64, uuid_top: u64, uuid_bottom: u64) -> u64 {
	let slist_lock = G_SCB_LIST.lock();

	if let Some(ref vSCB) = *slist_lock {
		for scb in vSCB {
			if scb.m_processId == id1 && scb.m_threadId == id2 &&
				(uuid_top == 0 || scb.m_uuidTop == uuid_top) && 
				(uuid_bottom == 0 || scb.m_uuidBottom == uuid_bottom) &&
				scb.m_bInUse {

				return scb.m_scbPKey;
			}
		}
	}

	ymh_log_str("Cannot find in USE pkey\0");
	ymh_log_hex(id1);
	ymh_log_nl();
	loop {}
}
/*fn checkID_setUseOrNotuse(id: u64, uuid_top: u64, uuid_bottom: u64, bUse: bool, lr: u64) -> bool {
	let mut slist_lock = G_SCB_LIST.lock();

	if let Some(ref mut vSCB) = *slist_lock {
		for scb in vSCB {
			if scb.m_processId == id && scb.m_uuidTop == uuid_top && scb.m_uuidBottom == uuid_bottom {
				scb.m_bInUse = bUse;
				if bUse {scb.m_lr = lr;}
				return true;
			}
		}
	} else {
		ymh_log_str("ERROR - checkID_setUseOrNotuse()\n\0");
		loop {}
	}

	false
}*/

/* Make some room by deleting unused SCB instances
 * Returns true if any instance is removed.
 * Returns false if any instance is not removed because all of them are in use.
 *
 * @bOne: if true, delete one. Otherwise, delete SCB instances not in use.
 *
 * TODO: LRU style. Currently, I just remove the first unused one from the vector.
 */
/*fn gcSCBList(bOne: bool) -> bool {
	let mut slist_lock = G_SCB_LIST.lock();
	let mut removeList: Vec<usize> = Vec::new();
	let mut i: usize = 0;

	if let Some(ref mut vSCB) = *slist_lock {
		for scb in &*vSCB {
			if !scb.m_bInUse {
				removeList.push(i);
				if bOne { break; }
			}

			i = i + 1;
		}

		for i in (0..removeList.len()).rev() {
			vSCB.remove(i);
		}

	} else {
		ymh_log_str("ERROR - gcSCBList\n\0");
		loop {}
	}

	(removeList.len() != 0)
}*/


/*fn setAsidAsName(buf: *mut u8, len: usize) {
	let mut idx = len-1;
	let mut asid = getASID();
	let mut digit: u8;//= 0;

	// ymh_log_str("ASID:\0");
	// ymh_log_hex(asid);
	// ymh_log_nl();

	loop {
		digit = (asid % 10) as u8;
		unsafe{ *buf.offset(idx as isize) = digit + b'0'; }

		asid = asid/10;
		if asid == 0 || idx == 0 { break; }

		idx = idx - 1;
	}
}*/


/*const EVAL_OTP_UUID1_TOP: u64 = 0x6f90a549e7ff4209;
const EVAL_OTP_UUID1_BOTTOM: u64 = 0xb407b6cb0c86882e;
const EVAL_OTP_UUID2_TOP: u64 = 0x3cb61b844c944c77;
const EVAL_OTP_UUID2_BOTTOM: u64 = 0x8ae6f122eaaa9d26;
const EVAL_OTP_UUID3_TOP: u64 = 0x8384d856b4a64abc;
const EVAL_OTP_UUID3_BOTTOM: u64 = 0x82399c2e8e794227;
const EVAL_OTP_UUID4_TOP: u64 = 0x96716a46dfd14ecf;
const EVAL_OTP_UUID4_BOTTOM: u64 = 0xa7e70fe94e5f6d43;

const B_EVAL_OTP: bool = true;*/
const EVAL_OTP_FIRST_FUNC_UUID_TOP: u64 = 0x2a8a7869d01b4a6d;
const EVAL_OTP_FIRST_FUNC_UUID_BOTTOM: u64 = 0x8845d6e397c4f151;
/*
 * @sStoragePaddr: 	physical address of sStorage in NW.
 *					This points to a starting address of a page, 
 *					and Rust is free to choose an arbitrary portion of a page to save private (encrypted) data.
 *					Mostly, Ginseng uses sStorage to store encrypted regs
 *					sStorage is per SSection, thus it has to be passed at every S-Section entery point
 * => Rtn:	0: Ok; 99: Error
 */
fn rsEnterSSection(sStoragePaddr: u64, sp1: u64 /*, uuid: u64*/) -> u64{
	// let id = getID();
	let id1: u64;
	let id2: u64;
	GET_PROCID!(id1);
	// GET_THREADID!(id2, sp1);
	GET_THREADID!(id2);

	// ymh_log_str("ENTER:\0");
	// ymh_log_hex(id1);
	// ymh_log_hex(id2);
	// ymh_log_nl();
	// PRINT_SLIB_REAL!("ENTER-S:\0", id1, id2);

	/*ymh_log_str("ID2:\0");
	ymh_log_hex(id2);
	ymh_log_nl();	*/
	let uuid_top: u64 = getX(sp1, 13);
	let uuid_bottom: u64 = getX(sp1, 14);
	// let lr: u64 = getX(sp1, 15);
	let bExitEval = uuid_top == EVAL_ENTRY_EXIT_UUID_TOP && uuid_bottom == EVAL_ENTRY_EXIT_UUID_BOTTOM;
	/*let bSetExeceptionTrap = uuid_top == EVAL_EXECTRAP_UUID_TOP && uuid_bottom == EVAL_EXECTRAP_UUID_BOTTOM;
	let bOTP = B_EVAL_OTP && (
				(uuid_top == EVAL_OTP_UUID1_TOP && uuid_bottom == EVAL_OTP_UUID1_BOTTOM) ||
				(uuid_top == EVAL_OTP_UUID2_TOP && uuid_bottom == EVAL_OTP_UUID2_BOTTOM) ||
				(uuid_top == EVAL_OTP_UUID3_TOP && uuid_bottom == EVAL_OTP_UUID3_BOTTOM) ||
				(uuid_top == EVAL_OTP_UUID4_TOP && uuid_bottom == EVAL_OTP_UUID4_BOTTOM)
				);*/
	let bDebugExcep = 	(uuid_top == EVAL_EXCEPTRAP_ML_UUID_TOP && uuid_bottom == EVAL_EXCEPTRAP_ML_UUID_BOTTOM) ||
						(uuid_top == EVAL_EXECTRAP_UUID_TOP 		&& uuid_bottom == EVAL_EXECTRAP_UUID_BOTTOM) ||
						(uuid_top == EVAL_OTP_FIRST_FUNC_UUID_TOP 	&& uuid_bottom == EVAL_OTP_FIRST_FUNC_UUID_BOTTOM);
	//bSetExeceptionTrap || bOTP;

	if bDebugExcep {
		// initHCR();
		*G_EXCEPTION_INITED.lock() = true;

		// ymh_log_str("EXCEPTION\n\0");
		/*ymh_log_str("SS_ENTRY for EXCEPTION\nuuid_top:\0");
		ymh_log_hex(uuid_top);
		ymh_log_nl();

		ymh_log_str("uuid_bottom:\0");
		ymh_log_hex(uuid_bottom);
		ymh_log_nl();*/
		/*ymh_log_str("\nSS_ENTRY for EXCEPTION\nprocID:\0");
		ymh_log_hex(id);
		ymh_log_nl();*/
	}

	/*{
		if *G_EXCEPTION_INITED.lock() {
			ymh_log_str("G_EXECPTION inited:\n\0");
		}
	}*/


	/*ymh_log_str("SS_ENTRY\0");
	// ymh_log_dec(getMonotonic());
	ymh_log_str("\nuuid_top:\0");
	ymh_log_hex(uuid_top);
	ymh_log_nl();

	ymh_log_str("uuid_bottom:\0");
	ymh_log_hex(uuid_bottom);
	ymh_log_nl();*/

	/*ymh_log_str("lr:\0");
	ymh_log_hex(lr);
	ymh_log_nl();*/

	// check if we already have a corresponding SCB instance.
	// If so, set the instance bInUse and return.
	// LR should be updated because a ssection can be called in different places
	// if checkID_setUseOrNotuse(id, uuid_top, uuid_bottom, true,/* lr,*/ bExitEval) /*!= None*/ { return 0; }
	if checkID_setUseOrNotuse(id1, id2, uuid_top, uuid_bottom, true,/* lr, bExitEval*/) {
		// if bSetExeceptionTrap {ymh_log_str("SCB found - return\n\0");}
		if !bExitEval {
			// ymh_log_str("SCB found - return\n\0");
			return 0; 
		}
	}

	// debugpoint
	// return 0;

	/*ymh_log_str("SS_ENTRY-newSCB\0");
	ymh_log_str("\nuuid_top:\0");
	ymh_log_hex(uuid_top);
	ymh_log_nl();

	ymh_log_str("uuid_bottom:\0");
	ymh_log_hex(uuid_bottom);
	ymh_log_nl();*/

	/*let mut t_start: u64;
	let mut t_end: u64;
	pmEnableReset();

	ymh_log_str("Kernel PT walk latency...\n\0");
	unsafe { asm! ("mrs $0, pmccntr_el0" : "=r" (t_start) :: "memory"); }

	for i in 0..1000 {
		memutil::checkKernelPT();
	}
	unsafe { asm! ("mrs $0, pmccntr_el0" : "=r" (t_end) :: "memory"); }
	ymh_log_str("PT walk latency avg:\0");
	ymh_log_dec( (t_end-t_start)/1000 );
	ymh_log_nl();*/

	// if bSetExeceptionTrap {ymh_log_str("EXCEP-CHECK-1\n\0");}
	// ymh_log_str("checkKernelPT\n\0");
	memutil::checkKernelPT(); // ################### TODO: RESTORE AFTER DEBUGGING!!
	// if bSetExeceptionTrap {ymh_log_str("EXCEP-CHECK-2\n\0");}

	// TEST AES
	/*if bExitEval {
		let plaintext = [0, lr];
		let mut ciphertext = [0 as u64; 2];
		let user_key = [0x0001020304050607, 0x08090a0b0c0d0e0f];
		AES_ENC(&plaintext, &mut ciphertext, &user_key);

		ymh_log_str("lr:\0");
		ymh_log_hex(lr);
		ymh_log_nl();

		ymh_log_str("ciphertext[0]:\0");
		ymh_log_hex(ciphertext[0]);
		ymh_log_nl();
		ymh_log_str("ciphertext[1]:\0");
		ymh_log_hex(ciphertext[1]);
		ymh_log_nl();

		let mut decrypted = [0 as u64; 2];
		AES_DEC(&ciphertext, &mut decrypted, &user_key);

		ymh_log_str("decrypted[0]:\0");
		ymh_log_hex(decrypted[0]);
		ymh_log_nl();
		ymh_log_str("decrypted[1]:\0");
		ymh_log_hex(decrypted[1]);
		ymh_log_nl();
	}*/

	// For QEMU and debugging purpose
	// For release, don't use the if-statement but the commented line
	// let elr = if sStoragePaddr == smc::GINSENG_UUID_QEMU_TEST {getElrEl1()} else {getElr3()};

	let elr: u64;
	GET_ELR_EL3!(elr);
	// let elr = ||->u64 {if uuid == smc::GINSENG_UUID_QEMU_TEST {getElrEl1()} else {getElr3()}}();

	// TODO: 	check code measurement.
	// 			For now, we assume we have the measurement passed by the vendor.
	// 			So, we just calculate the measurement and save it.
	// ymh_log_str("rsEnterSSection() is called\n\0");
	// ymh_log(&format!("sStoragePaddr(0x{:X})\n\0", sStoragePaddr));
	// ymh_log_str("sStoragePaddr:\0");
	// ymh_log_hex(sStoragePaddr);
	// ymh_log_nl();


	/*ymh_log(&format!("S-Section StartPAddr(0x{:X}) elr(0x{:X})\n\0", userVaddr2Paddr(elr), elr) );
	ymh_log(&format!("S-Section StartPAddr(0x{:X}) StartPAddr_page(0x{:X}) elr(0x{:X})\n\0", memutil::userVaddr2PaddrEx(elr, false /*not a page addr*/), memutil::userVaddr2PaddrEx(elr, true /*page addr*/), elr) );*/

	// TODO: Currently, I assume there exists a single SS_node for each SSection.
	let mut scb = SCB::new();
	scb.m_scbPKey = getSCBPKey();
	scb.m_processId = id1;
	scb.m_threadId = id2;
	scb.m_uuidTop = uuid_top;
	scb.m_uuidBottom = uuid_bottom;
	// scb.m_lr = lr;
	scb.m_bInUse = true;

	// I originally wanted to use the format!() macro, but I cannot use it due to a bug in that macro.
	// Instead, I resort to an unsafe function.
	// But, this can be reverted to using the format!() macro when its bug is fixed.
	// scb.m_name = Box::new(format!("HAHAHOHO\0"));
	// scb.m_name = Box::new(format!("{:08}\0", getASID()));
	// setAsidAsName(scb.m_name.as_ptr() as *mut _, scb.m_name.len() - 1);
	

	// let mut ss_node = SS_node::new();
	// scb.m_slist.push(ss_node);
	// scb.m_slist.push(SS_node::new());
	// if bDebugExcep {ymh_log_str("EXCEP-CHECK-3\n\0");}
	// checkTtbr();
	//read20test_whenUserAddr(getElr3());


	// assume that we already know S-Section info (Assumption_0)
	// TODO: Currently, we assume S-Setion belongs to a single page
	//		 But, we HAVE the facility to map multiple physical pages to a contiguous virtual address region!!

	// CHECK EVAL!
	if elr < 0xFFFF_FFFF_FFFFu64 { 
		// ymh_log_str("messure coode\n\0"); 
		// loop{}
		measureSSection(elr, sStoragePaddr, &mut scb);	
	}
	/*if uuid_top == EVAL_ENTRY_EXIT_UUID_TOP_NOSHA 
		&& uuid_bottom == EVAL_ENTRY_EXIT_UUID_BOTTOM_NOSHA {
		ymh_log_str("NO CHECK FOR EVAL\n\0");
			
	} else*/ /*if elr < 0xFFFFFFFFFFFFu64 { 
			// ymh_log_str("CODE CHECK FOR EVAL\n\0");
			// if bDebugExcep {ymh_log_str("EXCEP-CHECK-4\n\0");}
			measureSSection_forEval(elr, sStoragePaddr, &mut scb);	
			// if bDebugExcep {ymh_log_str("EXCEP-CHECK-5\n\0");}
	}*/
	
	{ // lock scope
		let mut gScbList_lock = G_SCB_LIST.lock();
		if let Some(ref mut v) = *gScbList_lock {
			/*ymh_log_str("New SCB PKey \0");
			ymh_log_dec(scb.m_scbPKey);
			ymh_log_str(" procID\0");
			ymh_log_hex(scb.m_processId);
			ymh_log_nl();*/
			v.push(scb)
		} else {
			ymh_log_str("ERROR MUST NOT HAPPEN - G_SCB_LIST is NONE\n\0");
			loop{}
		}
	}
	/*let mut gl = &*gScbList_lock;
	*gl.unwrap().push(scb);*/

	/*let dog = "The quick brown fox jumps over the lazy dog";
	let cog = "The quick brown fox jumps over the lazy cog";
	let mut out: [u8; 20] = [0; 20];
	SHA1("".as_ptr() as *const u8, 0, &mut out);
	rsHexdump(out.as_ptr(), 20);

	SHA1(dog.as_ptr() as *const u8, dog.len() as u32, &mut out);
	rsHexdump(out.as_ptr(), 20);

	SHA1(cog.as_ptr() as *const u8, cog.len() as u32, &mut out);
	rsHexdump(out.as_ptr(), 20);*/

	// printSCBList();
	// ymh_log_str("rsEnterSSection() returning\n\0");
	PRINT_SLIB!("ENTER-E:\0", id1, id2);
	0
}

/*fn getSCB() -> Option<&SCB> {

	None
}*/


/*
 * => Rtn:	0: Ok; 99: Error
 */
fn rsExitSSection(/*code: u64,*/ sp1: u64) -> u64{
	let id1: u64;// = getID();
	let id2: u64;
	let uuid_top: u64 = getX(sp1, 13);
	let uuid_bottom: u64 = getX(sp1, 14);

	GET_PROCID!(id1);
	// GET_THREADID!(id2, sp1);
	GET_THREADID!(id2);
	PRINT_SLIB!("EXIT-S:\0", id1, id2);
	/*let bSetExeceptionTrap = uuid_top == EVAL_EXECTRAP_UUID_TOP && uuid_bottom == EVAL_EXECTRAP_UUID_BOTTOM;
	let bOTP = B_EVAL_OTP && (
				(uuid_top == EVAL_OTP_UUID1_TOP && uuid_bottom == EVAL_OTP_UUID1_BOTTOM) ||
				(uuid_top == EVAL_OTP_UUID2_TOP && uuid_bottom == EVAL_OTP_UUID2_BOTTOM) ||
				(uuid_top == EVAL_OTP_UUID3_TOP && uuid_bottom == EVAL_OTP_UUID3_BOTTOM) ||
				(uuid_top == EVAL_OTP_UUID4_TOP && uuid_bottom == EVAL_OTP_UUID4_BOTTOM)
				);*/
	// let bDebugExcep = true; //bSetExeceptionTrap || bOTP;
	let bDebugExcep = 	(uuid_top == EVAL_EXCEPTRAP_ML_UUID_TOP && uuid_bottom == EVAL_EXCEPTRAP_ML_UUID_BOTTOM) ||
						(uuid_top == EVAL_EXECTRAP_UUID_TOP 		&& uuid_bottom == EVAL_EXECTRAP_UUID_BOTTOM) ||
						(uuid_top == EVAL_OTP_FIRST_FUNC_UUID_TOP 	&& uuid_bottom == EVAL_OTP_FIRST_FUNC_UUID_BOTTOM);

	if bDebugExcep {
		*G_EXCEPTION_INITED.lock() = false;

		/*ymh_log_str("SS_EXIT for EXCEPTION\nuuid_top:\0");
		ymh_log_hex(uuid_top);
		ymh_log_nl();

		ymh_log_str("uuid_bottom:\0");
		ymh_log_hex(uuid_bottom);
		ymh_log_nl();*/

		// ymh_log_str("SS_EXIT for EXCEPTION\n\0");
	}

	/*ymh_log_str("SS_EXIT\nuuid_top:\0");
	ymh_log_hex(uuid_top);
	ymh_log_nl();

	ymh_log_str("uuid_bottom:\0");
	ymh_log_hex(uuid_bottom);
	ymh_log_nl();*/

	// ymh_log_str("rsExit() is called\n\0");

	/*ymh_log_str("code:\0");
	ymh_log_hex(code);
	ymh_log_nl();*/

	/*{
		let slist_lock = G_SCB_LIST.lock();
		let foundSCB = checkID_inUse(&*slist_lock, id, 0, 0);
		if let Some(scb) = foundSCB {
			/*ymh_log_str("Found an SCB: uuid_top \0");
			ymh_log_hex((*scb).m_uuidTop);
			ymh_log_str("  bottom \0");
			ymh_log_hex((*scb).m_uuidBottom);
			ymh_log_nl();*/
			// ymh_log_str("Found an SCB\n\0");
		} else {
			ymh_log_str("No SCB-1\n\0");
			loop{}
		}
	}*/

	// only for microbenchmark
	// if uuid_top == 0x1111111188888888 && uuid_bottom == 0x8888888811111111 {
	if uuid_top == EVAL_ENTRY_EXIT_UUID_TOP && uuid_bottom == EVAL_ENTRY_EXIT_UUID_BOTTOM {
		// ymh_log_str("EVAL_ENTRY\n\0");
		checkID_setUseOrNotuse(id1, id2, uuid_top, uuid_bottom, false, /*0, false bEntryEval*/);
		moveX(sp1, 0x1234567812345678, 30);
		return 0;
	}

	checkID_setUseOrNotuse(id1, id2, uuid_top, uuid_bottom, false, /*0, false bEntryEval*/);

	// CHECK EVAL!
	// force pop
	// popSCB(id, uuid_top, uuid_bottom);

	/*match checkID_setUseOrNotuse(id, uuid_top, uuid_bottom, false, 0, false /*bEntryEval*/) {
		Some(lr) => {
			// ymh_log_str("uuid_top:\0");
			// ymh_log_hex(uuid_top);
			// ymh_log_nl();

			// ymh_log_str("uuid_bottom:\0");
			// ymh_log_hex(uuid_bottom);
			// ymh_log_nl();

			// ymh_log_str("lr:\0");
			// ymh_log_hex(lr);
			// ymh_log_nl();

			// ymh_log_str("sp1:\0");
			// ymh_log_hex(sp1);
			// ymh_log_nl();
			moveX(sp1, lr, 30);
		},
		None => {
			ymh_log_str("ERROR - cannot find my SCB\n\0");
			ymh_log_hex(id);
			ymh_log_nl();
		}
	}*/

	/*{
		let slist_lock = G_SCB_LIST.lock();
		let foundSCB = checkID_inUse(&*slist_lock, id, 0, 0);
		if let Some(scb) = foundSCB {
			ymh_log_str("Found an SCB\n\0");
			loop{}
		} else {
			// ymh_log_str("No SCB- OK\n\0");
		}
	}*/

	// gcSCBList(false); // for testing remove all

	// ymh_log_str("rsExit() is returning\n\0");	
	PRINT_SLIB!("EXIT-E:\0", id1, id2);
	0 // debug code
	// 0
}

// debugging fucntion
/*fn checkStack(sp1: u64, regNo: u32) {
	let out: u64;
	match regNo {
		2 => { unsafe { asm! ( "ldr $0, [$1, #0x10]" : "=r" (out) : "r" (sp1) : "memory");} },
		15 => { unsafe { asm! ( "ldr $0, [$1, #0x78]" : "=r" (out) : "r" (sp1) : "memory");} },
		_ => {
			/* need more ...*/
			ymh_log_str("Need to include more code for checkStack()\n\0");
		loop{}
		}
	}

	ymh_log_str("sp[X\0");
	ymh_log_dec(regNo as u64);
	ymh_log_str("] =");
	ymh_log_hex(out);
	ymh_log_nl();

}*/

fn rsRead(token_top: u64, token_bottom: u64, regNo: u32, sp1: u64) -> u64 {
	/*ymh_log_str("token_top:\0");
	ymh_log_hex(token_top);
	ymh_log_nl();

	ymh_log_str("token_bottom:\0");
	ymh_log_hex(token_bottom);
	ymh_log_nl();*/

	/*checkStack(sp1, 15);
	checkStack(sp1, 2);*/

	let id1: u64;
	let id2: u64;
	GET_PROCID!(id1);
	GET_THREADID!(id2);
	PRINT_SLIB!("READ-S:\0", id1, id2);

	let val = findFromTEEStorage(token_top, token_bottom, false /*bUpdate*/, 0 /*newVal*/, false /*bCreate*/);
	/*ymh_log_str("Copying\0");
	ymh_log_hex(val);
	ymh_log_str("-> X\0");
	ymh_log_dec(regNo as u64);
	ymh_log_nl();*/

	moveX(sp1, val, regNo);

	/*match regNo {
		15 => { 
			// ymh_log_str("Coying to X15:\n\0");
			setReg15(0x1234);
			ymh_log_hex(getReg15());
			ymh_log_nl();
			moveX(sp1, val, regNo);
		},
		14 => { 
			// ymh_log_str("Coying to X14:\n\0");
			setReg14(0x4321);
			ymh_log_hex(getReg14());
			ymh_log_nl();
			moveX(sp1, val, regNo);
		},
		_ => {
			// need more...
			ymh_log_str("Need to include more code for rsRead()\n\0");
			loop{}
		}
	}*/

	/*checkStack(sp1, 15);
	checkStack(sp1, 2);*/

	PRINT_SLIB!("READ-E:\0", id1, id2);

	0 //regNo
}

fn rsSave(token_top: u64, token_bottom: u64, regNo: u32, sp1: u64) -> u64 {
	/*let val = findFromTEEStorage(token_top, token_bottom);
	moveX(sp1, val, regNo);*/
	let val = getX(sp1, regNo);
	findFromTEEStorage(token_top, token_bottom, true /*bUpdate*/, val /*newVal*/, true /*bCreate*/);
	0 //regNo
}

// debug code
/*fn printCode(codes: u64) {
	for i in 0..8 {
		let code: u32 = ((codes & (0xFF << (i*8))) >> (i*8)) as u32;
		let status: u32 = (code & 0xF0) >> 4;
		let dest: u32 = (code & 0xF);
		
		ymh_log_hex(code as u64);
		ymh_log_str(" means \0");
		match status {
			SAVE_CLEAN_CODE_STATUS_DONTCARE => {
				ymh_log_str("ignores X\0");
				ymh_log_dec(i+8);
				ymh_log_nl();
			},
			SAVE_CLEAN_CODE_STATUS_CLEAN => {
				ymh_log_str("clean X\0");
				ymh_log_dec(i+8);
				ymh_log_nl();
			},
			SAVE_CLEAN_CODE_STATUS_CLEANMOVE => {
				ymh_log_str("clean & move X\0");
				ymh_log_dec(i+8);
				ymh_log_str(" to X\0");
				ymh_log_dec(dest as u64);
				ymh_log_nl();
			}
			_ => {
				ymh_log_str("Unknown STATUS:\0");
				ymh_log_hex(status as u64);
				ymh_log_nl();
			}
		}
	}
}*/

// add (register number, value) to the given storage
fn addRegNoVal(storage: &mut key_values, phyRegNo: u32, val: u64) -> bool {
	// first check whether phyRegNo is allready saved
	for each in &storage.m_vals {
		if each.m_phyRegNo == phyRegNo {return false;}
	}

	/*ymh_log_str("ADD X\0");
	ymh_log_dec(phyRegNo as u64);
	ymh_log_hex(val);
	ymh_log_nl();*/

	let plaintext = [0, val];
	let mut ciphertext = [0 as u64; 2];
	AES_ENC(&plaintext, &mut ciphertext, &USER_KEY);

	// storage.m_vals.push(regNo_val::new(phyRegNo, val));
	storage.m_vals.push(regNo_val::new(phyRegNo, ciphertext[0], ciphertext[1]));
	true
}



/*fn cleanX(sp1: u64, regNo: u32) -> u64{ 
	let mut out: u64 = 0;
	match regNo {
		15 => {
			unsafe { asm! ( "ldr $0, [$1, #0x78] 
							str xzr, [$1, #0x78]"
							: "=&r" (out) : "r" (sp1) : "memory");}	// YMH_NOTE Don't forget "&" for early-clobber
		},
		14 => {
			unsafe { asm! ( "ldr $0, [$1, #0x70]
 						    str xzr, [$1, #0x70]" 
							 : "=&r" (out) : "r" (sp1) : "memory");} // YMH_NOTE Don't forget "&" for early-clobber
		},
		13 => {
			unsafe { asm! ( "ldr $0, [$1, #0x68]
							 str xzr, [$1,#0x68]" 
							 : "=&r" (out) : "r" (sp1) : "memory");} // YMH_NOTE Don't forget "&" for early-clobber
		},
		12 => {
			unsafe { asm! ( "ldr $0, [$1, #0x60]
							 str xzr, [$1,#0x60]" 
							 : "=&r" (out) : "r" (sp1) : "memory");} // YMH_NOTE Don't forget "&" for early-clobber
		},
		11 => {
			unsafe { asm! ( "ldr $0, [$1, #0x58]
							 str xzr, [$1,#0x58]" 
							 : "=&r" (out) : "r" (sp1) : "memory");} // YMH_NOTE Don't forget "&" for early-clobber
		},
		10 => {
			unsafe { asm! ( "ldr $0, [$1, #0x50]
							 str xzr, [$1,#0x50]" 
							 : "=&r" (out) : "r" (sp1) : "memory");} // YMH_NOTE Don't forget "&" for early-clobber
		},
		9 => {
			unsafe { asm! ( "ldr $0, [$1, #0x48]
							 str xzr, [$1,#0x48]" 
							 : "=&r" (out) : "r" (sp1) : "memory");} // YMH_NOTE Don't forget "&" for early-clobber
		},
		_ => { 
			/* will be added more*/ 
			ymh_log_str("Add more to cleanX() for X\0");
			ymh_log_dec(regNo as u64);
			ymh_log_nl();
			loop {}
		}
	}
	
	// ymh_log_str("Cleaning done\n\0");
	out
}*/

fn cleanX(_sp1: u64, regNo: u32) -> u64{ 
	let mut out: u64 = 0;
	match regNo {
		15 => {
			unsafe { asm! ( "mov $0, v15.d[0] 
							 mov v15.d[0], xzr"
							: "=r" (out) : : "memory");}
		},
		14 => {
			unsafe { asm! ( "mov $0, v14.d[0] 
							 mov v14.d[0], xzr"
							: "=r" (out) : : "memory");}
		},
		13 => {
			unsafe { asm! ( "mov $0, v13.d[0] 
							 mov v13.d[0], xzr"
							: "=r" (out) : : "memory");}
		},
		12 => {
			unsafe { asm! ( "mov $0, v12.d[0] 
							 mov v12.d[0], xzr"
							: "=r" (out) : : "memory");}
		},
		11 => {
			unsafe { asm! ( "mov $0, v11.d[0] 
							 mov v11.d[0], xzr"
							: "=r" (out) : : "memory");}
		},
		10 => {
			unsafe { asm! ( "mov $0, v10.d[0] 
							 mov v10.d[0], xzr"
							: "=r" (out) : : "memory");}
		},
		9 => {
			unsafe { asm! ( "mov $0, v9.d[0] 
							 mov v9.d[0], xzr"
							: "=r" (out) : : "memory");}
		},
		_ => { 
			/* will be added more*/ 
			ymh_log_str("Add more to cleanX() for X\0");
			ymh_log_dec(regNo as u64);
			ymh_log_nl();
			loop {}
		}
	}
	
	// ymh_log_str("Cleaning done\n\0");
	out
}

/*fn getX(sp1: u64, regNo: u32) -> u64{ 
	let mut out: u64 = 0;
	match regNo {
		31 => { unsafe { asm! ( "ldr $0, [$1, #0xf8]" : "=r" (out) : "r" (sp1) : "memory");} },	// SP

		15 => { unsafe { asm! ( "ldr $0, [$1, #0x78]" : "=r" (out) : "r" (sp1) : "memory");} },
		14 => { unsafe { asm! ( "ldr $0, [$1, #0x70]" : "=r" (out) : "r" (sp1) : "memory");} },
		13 => { unsafe { asm! ( "ldr $0, [$1, #0x68]" : "=r" (out) : "r" (sp1) : "memory");} },
		12 => { unsafe { asm! ( "ldr $0, [$1, #0x60]" : "=r" (out) : "r" (sp1) : "memory");} },

		3 => { unsafe { asm! ( "ldr $0, [$1, #0x18]" : "=r" (out) : "r" (sp1) : "memory");} },
		_ => { 
			/* will be added more*/ 
			ymh_log_str("Add more to getX() for X\0");
			ymh_log_dec(regNo as u64);
			ymh_log_nl();
			loop {}
		}
	}
	out
}*/
fn getX(sp1: u64, regNo: u32) -> u64{ 
	let mut out: u64 = 0;
	match regNo {
		31 => { unsafe { asm! ( "ldr $0, [$1, #0xf8]" : "=r" (out) : "r" (sp1) : "memory");} },

		15 => { unsafe { asm! ( "mov $0, v15.d[0]" : "=r" (out) :: "memory");} },
		14 => { unsafe { asm! ( "mov $0, v14.d[0]" : "=r" (out) :: "memory");} },
		13 => { unsafe { asm! ( "mov $0, v13.d[0]" : "=r" (out) :: "memory");} },
		12 => { unsafe { asm! ( "mov $0, v12.d[0]" : "=r" (out) :: "memory");} },

		3 => { unsafe { asm! ( "ldr $0, [$1, #0x18]" : "=r" (out) : "r" (sp1) : "memory");} },
		_ => { 
			/* will be added more*/ 
			ymh_log_str("Add more to getX() for X\0");
			ymh_log_dec(regNo as u64);
			ymh_log_nl();
			loop {}
		}
	}
	out
}

/*fn moveX(sp1: u64, val: u64, regNo: u32) {
	match regNo {
		0 => { unsafe { asm! ("str $0, [$1, #0x0]" :: "r" (val), "r" (sp1)); } },
		1 => { unsafe { asm! ("str $0, [$1, #0x8]" :: "r" (val), "r" (sp1)); } },
		2 => { unsafe { asm! ("str $0, [$1, #0x10]" :: "r" (val), "r" (sp1)); } },
		3 => { unsafe { asm! ("str $0, [$1, #0x18]" :: "r" (val), "r" (sp1)); } },
		4 => { unsafe { asm! ("str $0, [$1, #0x20]" :: "r" (val), "r" (sp1)); } },
		
		9 => { unsafe { asm! ("str $0, [$1, #0x48]" :: "r" (val), "r" (sp1)); } },
		10 => { unsafe { asm! ("str $0, [$1, #0x50]" :: "r" (val), "r" (sp1)); } },
		11 => { unsafe { asm! ("str $0, [$1, #0x58]" :: "r" (val), "r" (sp1)); } },
		12 => { unsafe { asm! ("str $0, [$1, #0x60]" :: "r" (val), "r" (sp1)); } },
		13 => { unsafe { asm! ("str $0, [$1, #0x68]" :: "r" (val), "r" (sp1)); } },
		14 => { unsafe { asm! ("str $0, [$1, #0x70]" :: "r" (val), "r" (sp1)); } },
		15 => { unsafe { asm! ("str $0, [$1, #0x78]" :: "r" (val), "r" (sp1)); } },

		30 => { unsafe { asm! ("str $0, [$1, #0xf0]" :: "r" (val), "r" (sp1)); } },
		_ => {
			/* will be added more*/ 
			ymh_log_str("Add more to moveX() for X\0");
			ymh_log_dec(regNo as u64);
			ymh_log_nl();
		}
	}
}*/

fn moveX(sp1: u64, val: u64, regNo: u32) {
	match regNo {
		// 0 => { unsafe { asm! ("str $0, [$1, #0x0]" :: "r" (val), "r" (sp1)); } },
		0 => { unsafe { asm! ("	movi v23.16b, #1
								mov v23.d[0], $0" :: "r" (val)); } },
		1 => { unsafe { asm! ("	movi v24.16b, #1
								mov v24.d[0], $0" :: "r" (val)); } },
		2 => { unsafe { asm! ("	movi v25.16b, #1
								mov v25.d[0], $0" :: "r" (val)); } },
		3 => { unsafe { asm! ("	movi v26.16b, #1
								mov v26.d[0], $0" :: "r" (val)); } },
		4 => { unsafe { asm! ("	movi v27.16b, #1
								mov v27.d[0], $0" :: "r" (val)); } },
		
		9 => { unsafe { asm! ("mov v9.d[0], $0" :: "r" (val)); } },
		10 => { unsafe { asm! ("mov v10.d[0], $0" :: "r" (val)); } },
		11 => { unsafe { asm! ("mov v11.d[0], $0" :: "r" (val)); } },
		12 => { unsafe { asm! ("mov v12.d[0], $0" :: "r" (val)); } },
		13 => { unsafe { asm! ("mov v13.d[0], $0" :: "r" (val)); } },
		14 => { unsafe { asm! ("mov v14.d[0], $0" :: "r" (val)); } },
		15 => { unsafe { asm! ("mov v15.d[0], $0" :: "r" (val)); } },

		30 => { unsafe { asm! ("str $0, [$1, #0xf0]" :: "r" (val), "r" (sp1)); } },
		_ => {
			/* will be added more*/ 
			ymh_log_str("Add more to moveX() for X\0");
			ymh_log_dec(regNo as u64);
			ymh_log_nl();
		}
	}
}

fn cleanMoveX(sp1: u64, srcRegNo: u32, destRegNo: u32) -> u64 {
	let val = cleanX(sp1, srcRegNo);
	// ymh_log_str("MOVEing..to\0");
	// ymh_log_hex(val);
	moveX(sp1, val, destRegNo);
	// ymh_log_str("MOVEing..done\n\0");

	val
}

fn rsSaveCleanV(token_top: u64, token_bottom: u64, codes: u64, bFuncPtr: u64, sp1: u64) -> u64 {
	
	/////////////////////////////////////////////////
	// only for evaluation (micro) --- rsSaveCleanV() CHECK EVAL!
	// let me comment out when evaluation is done...
	/*if token_top == EVAL_DATA_UUID_TOP && token_bottom == EVAL_DATA_UUID_BOTTOM {
		let mut storage = key_values::new(token_top, token_bottom);
		let mut bAdded = false;
		for i in 0..8 {
			let code: u32 = ((codes & (0xFF << (i*8))) >> (i*8)) as u32;
			let status: u32 = (code & 0xF0) >> 4;
			let dest: u32 = (code & 0xF);
			let src: u32 = i+8;
			
			match status {
				SAVE_CLEAN_CODE_STATUS_DONTCARE => {},
				SAVE_CLEAN_CODE_STATUS_CLEAN => {
					// ymh_log_str("CLEAN\n\0");
					// storage = key_values::new(token_top, token_bottom);
					// let mut kv = key_values::new(token_top, token_bottom);
					// addRegNoVal(&mut kv, src, cleanX(sp1, src));
					addRegNoVal(&mut storage, src, cleanX(sp1, src));
					// storage = Some(kv);
					// ymh_log_str("CLEAN-DONE\n\0");
					bAdded = true;
					// ymh_log_str("CLEAN-DONE\n\0");
				},
				SAVE_CLEAN_CODE_STATUS_CLEANMOVE => {
					// ymh_log_str("MOVE\n\0");
					// storage = key_values::new(token_top, token_bottom);
					// let mut kv = key_values::new(token_top, token_bottom);
					let regVal = cleanMoveX(sp1, src, dest);
					// addRegNoVal(&mut kv, src, regVal);
					addRegNoVal(&mut storage, src, regVal);
					// storage = Some(kv);
					// ymh_log_str("CLEAN-MOVE-DONE\n\0");
					bAdded = true;

				}
				_ => {
					ymh_log_str("Unknown STATUS:\0");
					ymh_log_hex(status as u64);
					ymh_log_nl();
				}
			}
		}

		if bAdded { // lock only when needed
			let mut lock = G_SS_STORAGE.lock();
			if let Some(ref mut v) = *lock {
				v.push(storage);
			} else {
				ymh_log_str("ERROR MUST NOT HAPPEN - G_SS_STORAGE is NONE\n\0");
				loop{}
			}
		}

		return 0;
	}*/

	let mut bEval = false;
	if token_top == EVAL_READV_UUID_TOP && token_bottom == EVAL_READV_UUID_BOTTOM {
		bEval = true;
	}

	////////////////////////////////////////////////
	let id1: u64;
	let id2: u64;
	GET_PROCID!(id1);
	// GET_THREADID!(id2, sp1);
	GET_THREADID!(id2);
	// PRINT_SLIB!("SAVEV-S:\0", id1, id2);
	// ymh_log_str("saveCleanV()\n\0");

	// debugging point
	// return 0;

	let mut storage = key_values::new(id1, id2, token_top, token_bottom);
	let mut bAdded = false;

	/*ymh_log_str("saveCleanV() uuid_top:\0");
	ymh_log_hex(token_top);
	ymh_log_nl();

	ymh_log_str("saveCleanV() uuid_bottom:\0");
	ymh_log_hex(token_bottom);
	ymh_log_nl();*/

	// find SCB
	// let id: u64 = getID();

	if !bEval { // remove after eval... CHECK EVAL!
	let pkey = getSCBPKey_inUSE(id1, id2, 0, 0);
	storage.m_scbPKey = pkey;
	}

	// ymh_log_str("bFuncPtr: \0");
	// ymh_log_dec(bFuncPtr);
	// ymh_log_nl();

	// ymh_log_str("codes: \0");
	// ymh_log_hex(codes);
	// ymh_log_nl();
	
	for i in 0..8 {
		let code: u32 = ((codes & (0xFF << (i*8))) >> (i*8)) as u32;
		let status: u32 = (code & 0xF0) >> 4;
		let dest: u32 = (code & 0xF);
		let src: u32 = i+8;
		
		match status {
			SAVE_CLEAN_CODE_STATUS_DONTCARE => {},
			SAVE_CLEAN_CODE_STATUS_CLEAN => {
				addRegNoVal(&mut storage, src, cleanX(sp1, src));
				bAdded = true;
			},
			SAVE_CLEAN_CODE_STATUS_CLEANMOVE => {

				let regVal = cleanMoveX(sp1, src, dest);
				/*ymh_log_str("CLEANMOVE: x\0");
				ymh_log_dec(src as u64);
				ymh_log_str("-> x\0");
				ymh_log_dec(dest as u64);
				ymh_log_str(": \0");
				ymh_log_hex(regVal);
				ymh_log_nl();*/
				addRegNoVal(&mut storage, src, regVal);

				bAdded = true;

			}
			SAVE_CLEAN_CODE_STATUS_FUNCPTR => {
				if bFuncPtr != 1 {
					ymh_log_str("We have a function pointer, but not expected!\n\0");
					loop {}
				}
				ymh_log_str("OKOK SAVE_CLEAN_CODE_STATUS_FUNCPTR\n\0");
			}
			_ => {
				ymh_log_str("Unknown STATUS:\0");
				ymh_log_hex(status as u64);
				ymh_log_nl();
			}
		}
	}

	if bAdded { // lock only when needed
		let mut lock = G_SS_STORAGE.lock();
		if let Some(ref mut v) = *lock {
			/*ymh_log_str("Created a storage pointing pkey\0");
			ymh_log_dec(pkey);
			ymh_log_nl();*/
			v.push(storage);
		} else {
			ymh_log_str("ERROR MUST NOT HAPPEN - G_SS_STORAGE is NONE\n\0");
			loop{}
		}
	}

	// use -> no use
	if !bEval { // remove after eval...
	setSCB_noUse_withProcID(id1, id2, 0, 0);
	}

	PRINT_SLIB!("SAVEV-E:\0", id1, id2);
	0
}

fn getValFromStor(storage: &Vec<regNo_val>, phyRegNo: u32) -> u64 {
	for kv in storage {
		if kv.m_phyRegNo == phyRegNo {
			// return kv.m_val;

			let ciphertext = [kv.m_encVal1, kv.m_encVal2];
			let mut decrypted = [0 as u64; 2];
			AES_DEC(&ciphertext, &mut decrypted, &USER_KEY);
			return decrypted[1];
		}
	}

	ymh_log_str("ERROR MUST NOT HAPPEN - cannot find reg\n\0");
	loop{}
}


/*
 * rsSaveM() does NOT clean old reg
 * used for debugging functions
 */
fn rsSaveM(token_top: u64, token_bottom: u64, nrRegs: u64, sp1: u64) -> u64 {
	// ymh_log_str("Save \0");
	/*ymh_log_hex(token_top);
	ymh_log_hex(token_bottom);
	ymh_log_dec(nrRegs);*/
	// ymh_log_hex(sp1);
	// loop {}
	let id1: u64;
	let id2: u64;
	GET_PROCID!(id1);
	GET_THREADID!(id2);

	let mut storage = key_values::new(id1, id2, token_top, token_bottom);
	for i in 0..nrRegs as u32{
		/*let regNo = 15-i;
		let regVal = getX(sp1, regNo);
		ymh_log_str("Save X\0");
		ymh_log_dec(regNo as u64);
		ymh_log_str(":\0");
		ymh_log_hex(regVal);
		ymh_log_nl();*/
		
		addRegNoVal(&mut storage, 15-i, getX(sp1, 15-i));
	}

	// we don't need a new scope to drop the lock
	// because we're going to return soon.
	let mut lock = G_SS_STORAGE.lock();
	if let Some(ref mut v) = *lock {
		v.push(storage);
	} else {
		ymh_log_str("ERROR MUST NOT HAPPEN - G_SS_STORAGE is NONE\n\0");
		loop{}
	}

	// ymh_log_str("saveRETURNING...\n\0");
	0
}

fn rsReadM(token_top: u64, token_bottom: u64, nrRegs: u64, sp1: u64) -> u64 {
	/*ymh_log_str("Read \0");
	ymh_log_dec(nrRegs);
	ymh_log_str("regs\n\0");*/
	let mut lock = G_SS_STORAGE.lock();
	if let Some(ref mut storages) = *lock {
		let mut found: usize = 99;
		let id1: u64;
		let id2: u64;
		GET_PROCID!(id1);
		GET_THREADID!(id2);
		{ // scope to drop storage

			//find storage with token
			let mut storage: Option<&Vec<regNo_val>> = None;
			for i in 0..storages.len() {
				if storages[i].m_processId == id1 && storages[i].m_threadId == id2 &&
					storages[i].m_top == token_top && storages[i].m_bottom == token_bottom {
					storage = Some(&storages[i].m_vals);
					found = i;
					break;
				}
			}

			// restore data
			if let Some(ref vals) = storage {
				for i in 0..nrRegs as u32 {
					moveX(sp1, getValFromStor(vals, 15-i), 15-i);
				}

			} else {
				ymh_log_str("ERROR MUST NOT HAPPEN - CANNOT FIND TOKEN 1\n\0");
				loop{}
			}

		}
		
		if found == 99 { 
			ymh_log_str("ERROR MUST NOT HAPPEN - CANNOT FIND TOKEN 2\n\0");
			loop{}
		} else {storages.remove(found); }

	} else {
		ymh_log_str("ERROR MUST NOT HAPPEN - G_SS_STORAGE is NONE\n\0");
		loop{}
	}

	// ymh_log_str("readRETURNING...\n\0");
	0
}


fn rsReadV(token_top: u64, token_bottom: u64, codes: u64, sp1: u64) -> u64 {
	let mut lock = G_SS_STORAGE.lock();
	/*ymh_log_str("readV() uuid_top:\0");
	ymh_log_hex(token_top);
	ymh_log_nl();

	ymh_log_str("readV() uuid_bottom:\0");
	ymh_log_hex(token_bottom);
	ymh_log_nl();*/
	let id1: u64;
	let id2: u64;
	GET_PROCID!(id1);
	GET_THREADID!(id2);
	PRINT_SLIB!("READV-S:\0", id1, id2);
	unsafe{G_STAT_READV = G_STAT_READV + 1;}

	// TODO: DELETE AFTER ML EVAL
	{*G_EXCEPTION_INITED.lock() = true;}

	if let Some(ref mut storages) = *lock {
		let mut found: usize = 99;
		let mut scbPKey = 0;
		{ // scope to drop storage
			let mut storage: Option<&Vec<regNo_val>> = None;
			for i in 0..storages.len() {
				if storages[i].m_processId == id1 && storages[i].m_threadId == id2 &&
					storages[i].m_top == token_top && storages[i].m_bottom == token_bottom {
					storage = Some(&storages[i].m_vals);
					found = i;
					scbPKey = storages[i].m_scbPKey;
					break;
				}
			}

			// found my storage with matching token
			if let Some(ref vals) = storage {
				for i in 0..8 {
					let code: u32 = ((codes & (0xFF << (i*8))) >> (i*8)) as u32;
					let status: u32 = (code & 0xF0) >> 4;
					// let dest: u32 = (code & 0xF);
					let src: u32 = i+8;
					
					match status {
						SAVE_CLEAN_CODE_STATUS_DONTCARE => {},
						SAVE_CLEAN_CODE_STATUS_CLEAN | SAVE_CLEAN_CODE_STATUS_CLEANMOVE => {
							let regVal = getValFromStor(vals, src);
							/*if status == SAVE_CLEAN_CODE_STATUS_CLEANMOVE {
								ymh_log_str("restoring from X\0");
								ymh_log_dec(dest as u64);
								ymh_log_str("-> X\0");
								ymh_log_dec(src as u64);
								ymh_log_str(" (\0");
								ymh_log_hex(regVal);
								ymh_log_str(")\n\0");

							}*/
							moveX(sp1, regVal, src);
							/*if status == SAVE_CLEAN_CODE_STATUS_CLEANMOVE && src == 14 {
								ymh_log_str("X14: (\0");
								ymh_log_hex( getX(sp1, 14) );
								ymh_log_str(")\n\0");
							}*/
						}
						_ => {
							ymh_log_str("Unknown STATUS:\0");
							ymh_log_hex(status as u64);
							ymh_log_nl();
						}
					}
				}

			} else {
				// from an exception
				// let procID = getID();
				// ymh_log_str("DEBUGGING POINT!!\n\0");
				// loop{}
				if setSCB_restoreContext_inUse(sp1 as usize) {
					// ymh_log_str("Handled!!\n\0");
					return 0
				}

				ymh_log_str("ERROR MUST NOT HAPPEN - CANNOT FIND RESTORE CONTEXT\n\0");
				loop{}
			}
		}
		
		if found == 99 { 
			ymh_log_str("ERROR MUST NOT HAPPEN - CANNOT FIND TOKEN 3\n\0");
			loop{}
		} else {
			if (token_top == EVAL_READV_UUID_TOP && token_bottom == EVAL_READV_UUID_BOTTOM) {
				// ymh_log_str("EVAL: NO REMOVE\n\0");
			} else { 
				// no use -> use
				/*ymh_log_str("Making\0");
				ymh_log_hex(scbPKey);
				ymh_log_str("in use\n\0");*/
				setSCB_withSCBPKey(scbPKey, true);
				storages.remove(found); 
			}
			
		}

	} else {
		ymh_log_str("ERROR MUST NOT HAPPEN - G_SS_STORAGE is NONE\n\0");
		loop{}
	}

	PRINT_SLIB!("READV-E:\0", id1, id2);
	0
}

// CTX: x0-x30, sp_el0 (idx:31) spsr_el0(idx:32) elr_el0(idx:33) : 34 regs (0-33)
/*fn copyContext(sp1: u64) {
	// let mut ctx = Context::new();
	// let's do `unsafe' memcopy
	let sp1 = sp1 as usize;
	let mut ctx = [0 as u64; 34];
	for i in 0..35 {
		ctx[i] = unsafe {*((sp1 + i*8) as *const u64)};
	}
}*/

/*fn rsAsyncException(sp1: u64) -> u64 {
	if !{ *G_EXCEPTION_INITED.lock() } {
		return 0;
	}

	let elr1: u64;
	GET_ELR_EL1!(elr1);

	let esr1_ec: u64;
	GET_ESR_EL1_EC!(esr1_ec);
	if IS_KERN_ADDR!(elr1) {
		ymh_log_str("ASYNC EC in K:\0");
		ymh_log_hex(esr1_ec);
		ymh_log_nl();
		return 0;
	}

	ymh_log_str("ASYNC1 EC in u:\0");
	ymh_log_hex(esr1_ec);
	ymh_log_nl();

	let procID: u64;//= getID();
	GET_PROCID!(procID);

	let pkey = setSCB_saveContext_inUse(sp1 as usize, procID/*, esr1_ec == 0x15 /*bSVC*/*/);

	if pkey != 0 {
		ymh_log_str("ASYNC2 EC in u:\0");
		ymh_log_hex(esr1_ec);
		ymh_log_nl();
		loop{}
	}

	0
}*/

fn rsException(sp1: u64) -> u64{
	/*ymh_log_str("rsException\n\0");
	loop {}*/
	// let exceptionID: u64; // = getMonotonic();

	/*let gInited = { *G_EXCEPTION_INITED.lock() };	// drop the lock and only get the value
	if gInited {
		// exceptionID = getMonotonic();
		// ymh_log_str("CHECK 1 [\0");
		// ymh_log_dec(exceptionID);
		// ymh_log_str("]\n\0");
	} else {
		return 0;
	}*/
	// loop{}

	if !{ *G_EXCEPTION_INITED.lock() } {
		return 0;
	}

	// ymh_log_str("rsException\n\0");

	// let nrRegsToSave = 2;
	// let elr1 = getElrEl1();
	let elr1: u64;
	GET_ELR_EL1!(elr1);

	// let esr1_ec: u64;
	// GET_ESR_EL1_EC!(esr1_ec);

	if IS_KERN_ADDR!(elr1) {
		/*ymh_log_str("EC in K:\0");
		ymh_log_hex(esr1_ec);
		ymh_log_nl();*/
		return 0;
	}

	/*ymh_log_str("EC in u:\0");
	ymh_log_hex(esr1_ec);
	ymh_log_nl();*/

	let procID: u64;//= getID();
	GET_PROCID!(procID);

	let pkey = setSCB_saveContext_inUse(sp1 as usize, procID/*, esr1_ec == 0x15 /*bSVC*/*/);
	
	if pkey != 0 {
		// ymh_log_str("Found an SCB in USE: pkey\0");
		// ymh_log_dec(pkey);
		// ymh_log_str(" procID\0");
		// ymh_log_hex(procID);
		// ymh_log_str(" elr1\0");
		// ymh_log_hex(elr1);
		// ymh_log_nl();
		/*let esr1_ec: u64;
		GET_ESR_EL1_EC!(esr1_ec);

		match(esr1_ec) {
			0x15 => {	// SVC
				// ymh_log_str("Exception due to SVC\n\0");
				let scno = unsafe {*((sp1 + 0x40) as *const u64)};
				ymh_log_str("EXCEPT SCNO:\0");
				ymh_log_dec(scno);
				// ymh_log_hex(procID);
				ymh_log_nl();

				// if scno == 64 { // write
				// 	let count = unsafe {*((sp1 + 0x10) as *const u64)};
				// 	ymh_log_str("SYS_WRITE count:\0");
				// 	ymh_log_dec(count);
				// 	ymh_log_nl();
				// }

				// let lr = unsafe {*((sp1 + 0xf0) as *const u64)};
				// ymh_log_str("LR:\0");
				// ymh_log_hex(lr);
				// ymh_log_nl();
			},
			0x24 => {
				ymh_log_str("EXCEPT DABT\n\0");
			},		// DABT | IABT
			0x20 => {
				ymh_log_str("EXCEPT IABT\n\0");
			},
			_ => {
				ymh_log_str("Exception class:\0");
				ymh_log_hex(esr1_ec);
				ymh_log_nl();
			}

		}*/
		/*if let Some(ref mut stat_except) = *G_STAT_EXCEPT.lock() {
			stat_except = stat_except + 1;
		}*/
		/*unsafe {
			G_STAT_EXCEPT = G_STAT_EXCEPT + 1;
		}*/

		let pReadV = getreadVFromProcID(procID);
		if pReadV != 0 {
			setElr1(pReadV);
			setSpsrEl1(0);
			/*ymh_log_str("CPU[\0");
			ymh_log_dec(get_cpuid());
			ymh_log_str("] ELR1\0");
			ymh_log_hex(elr1);
			ymh_log_str("->\0");
			ymh_log_hex(getElrEl1());
			ymh_log_nl();*/

		}
	}

	0
}

/*fn sha1Dump(sig: [u8; SHA1_SIZE]) {
	rsHexdump(sig.as_ptr() as *const u8, 20);
}*/

/*pub fn rsHexdump(a: *const u8, len: u32) {
	let mut sha = a; // a.as_bytes();
	// ymh_log(&format!("HEXDUMP START\n\0"));
	ymh_log_str("SIG: \0");
	for _ in 0..len {
		// print!("{:02x}", unsafe{*sha} as u8);
		// ymh_log(&format!("{:02x}", unsafe{*sha} as u8));
		// ymh_log_hex(&format!("{:02x}", unsafe{*sha} as u8));
		ymh_log_hex_len2(unsafe{*sha});
		sha = unsafe{sha.offset(1)};
	}

	// ymh_log_str("HEXDUMP DONE\n\0");
	ymh_log_nl();
}*/

fn smcHandler_ping(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) {
	// ymh_log_str(&format!("GINSENG_SMC_CMD_PING {:}{:}{:}{:}{:}=12340\n\0", a1, a2, a3, a4, a5));
	// ymh_log_str("RUST-PING\n\0");


	let mut hcr_el2 = getHcr_el2();
	if hcr_el2 & 0x4000000 == 0 {
		hcr_el2 = hcr_el2 | 0x4000000 as u64;
	} else {
		hcr_el2 = hcr_el2 & !0x4000000 as u64;
	}

	ymh_log_str("CPU[\0");
	ymh_log_dec(get_cpuid());
	ymh_log_str("]\0");
	ymh_log_hex(hcr_el2);
	ymh_log_nl();
	// 0x4000000 : TVM (TTBR_EL1)
	// 0x8000000 : TGE (Sync Exception from NS-EL0)
	// 0x20000000 : HCD
	// 0xC000000 : TVM | TGE
	unsafe {
		asm! (
			"
			msr hcr_el2, $0
			"
			:
			: "r" (hcr_el2)
			: "memory"
			);
	}
}

fn _set64bit(dest_va: u64, src_val: u64, bDCI: bool) {
	let dest_pa: u64 = __pa(dest_va);
	if bDCI { dci(dest_pa); }

	unsafe {
		asm! ("
			mrs x15, sctlr_el3 		// x15 preserves SCTLR
			bic x15, x15, #1

			mov x9, $0	// dest_pa
			mov x10, $1	// src_val

			msr sctlr_el3, x15 		// no MMU ----------------- NO MEM ACCESS BELOW -----------
			isb sy

			str x10, [x9]			// COPY

			dmb sy
			orr x15, x15, #1
			msr sctlr_el3, x15 		// yes MMU ----------------- NO MEM ACCESS ABOVE -----------
			isb sy
			"
			:
			: "r" (dest_pa), "r" (src_val)
			: "memory", 
			"x15", 	// sctrl save
			"x9", 	// dest_pa
			"x10"	// src_Val
			);
	}

	if bDCI { dcci(dest_pa); }
}

fn set64bit_dci(dest_va: u64, src_val: u64) {
	#[cfg(feature = "qemu")]
	_set64bit(dest_va, src_val, false);

	#[cfg(not(feature = "qemu"))]
	_set64bit(dest_va, src_val, true);	// <-- for HiKey

	/*#[cfg(not(feature = "qemu"))]
	ymh_log("NOT QEMU!!!\n\0")*/
}

fn set64bit(dest_va: u64, src_val: u64) {
	_set64bit(dest_va, src_val, false);
}

/*fn setReg15(val: u64) { unsafe { asm! ("mov x15, x0") } }
fn setReg14(val: u64) { unsafe { asm! ("mov x14, x0") } }*/

/*fn getReg15() -> u64 {
	let mut rtn: u64 = 0;
	unsafe { asm! ("mov $0, x15":"=r" (rtn)::"memory") } 
	rtn
}
fn getReg14() -> u64 { 
	let mut rtn: u64 = 0;
	unsafe { asm! ("mov $0, x14":"=r" (rtn)::"memory") } 
	rtn
}*/

fn clearPage(dest_va: u64) {
	// let mut counter: u64 = 0xff;
	let dest_pa: u64 = __pa(dest_va);
	unsafe{
		asm! ("
			mrs x15, sctlr_el3 		// x15 preserves
			bic x15, x15, #1

			mov x14, #0x1000		// x14 counter
			mov x8, $0				// dest_pa

			msr sctlr_el3, x15 		// no MMU ----------------- NO MEM ACCESS BELOW -----------
			isb sy

		1: 					// LOOP START
			stp xzr, xzr, [x8], #16

			sub x14, x14, #16
			cbz x14, 99f
			b 1b			// LOOP END

		99:	// EXIT
			dmb sy
			orr x15, x15, #1
			msr sctlr_el3, x15 		// yes MMU ----------------- NO MEM ACCESS ABOVE -----------
			isb sy"

			//"mov %[counter], x14\n"
			: //[counter] "=r" (counter)
			: "r" (dest_pa)
			: "memory", "x15", "x14", "x8"
			);
	}
}

fn copyPage(dest_va: u64, src_va: u64) {
	let dest_pa: u64 = __pa(dest_va);
	let src_pa: u64 = __pa(src_va);

	unsafe {
		asm! ("
			mrs x19, sctlr_el3 		// x19 preserves
			bic x19, x19, #1
			mov x0, $0
			mov x1, $1
			isb sy
			dmb sy

			msr sctlr_el3, x19 		// no MMU ----------------- NO MEM ACCESS BELOW -----------
			isb sy

			// the following lines that copy mem in 128-byte chunk came from Linux's copy_page.S
			ldp	x2, x3, [x1]
			ldp	x4, x5, [x1, #16]
			ldp	x6, x7, [x1, #32]
			ldp	x8, x9, [x1, #48]
			ldp	x10, x11, [x1, #64]
			ldp	x12, x13, [x1, #80]
			ldp	x14, x15, [x1, #96]
			ldp	x16, x17, [x1, #112]

			mov	x18, #(0x1000 - 128)		// 0x1000 is PAGE_OFFSET
			add	x1, x1, #128
		1:
			subs	x18, x18, #128

			stnp	x2, x3, [x0]
			ldp	x2, x3, [x1]
			stnp	x4, x5, [x0, #16]
			ldp	x4, x5, [x1, #16]
			stnp	x6, x7, [x0, #32]
			ldp	x6, x7, [x1, #32]
			stnp	x8, x9, [x0, #48]
			ldp	x8, x9, [x1, #48]
			stnp	x10, x11, [x0, #64]
			ldp	x10, x11, [x1, #64]
			stnp	x12, x13, [x0, #80]
			ldp	x12, x13, [x1, #80]
			stnp	x14, x15, [x0, #96]
			ldp	x14, x15, [x1, #96]
			stnp	x16, x17, [x0, #112]
			ldp	x16, x17, [x1, #112]

			add	x0, x0, #128
			add	x1, x1, #128

			b.gt	1b

			stnp	x2, x3, [x0]
			stnp	x4, x5, [x0, #16]
			stnp	x6, x7, [x0, #32]
			stnp	x8, x9, [x0, #48]
			stnp	x10, x11, [x0, #64]
			stnp	x12, x13, [x0, #80]
			stnp	x14, x15, [x0, #96]
			stnp	x16, x17, [x0, #112]


			99:
			dmb sy
			isb sy
			orr x19, x19, #1
			msr sctlr_el3, x19 		// yes MMU ----------------- NO MEM ACCESS ABOVE -----------
			isb sy"
			:
			: "r" (dest_pa), "r" (src_pa)
			: "memory", "x19",// "x20",
				"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18"
			);
	}
}

fn rsTellme(pReadV: u64) -> u64 {
	addApp2ReadV(getID(), pReadV);

	0
}

/*
 * Rust entry point
 * Called by asm (runtime_exceptions.S)
 */
#[no_mangle]
pub extern fn rsGinseng_smc(smc_cmd: u64, 
	a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, sp1: u64) -> u64{ 
	// DISABLE_NX!();

	if smc_cmd != schannel::HANDLE_SCHANNEL_RETURN_NEED_TO_CALL_EXCEPTION {
		initRS();
	}
	// checkHCR();

	match smc_cmd {
		schannel::HANDLE_SCHANNEL_RETURN_NEED_TO_CALL_SENTRY => { return rsEnterSSection(a1, sp1); },
		schannel::HANDLE_SCHANNEL_RETURN_NEED_TO_CALL_SEXIT => { return rsExitSSection(sp1); },
		schannel::HANDLE_SCHANNEL_RETURN_NEED_TO_CALL_READ => { return rsRead(a1, a2, a3 as u32, sp1); },
		schannel::HANDLE_SCHANNEL_RETURN_NEED_TO_CALL_SAVE => { return rsSave(a1, a2, a3 as u32, sp1); },
		schannel::HANDLE_SCHANNEL_RETURN_NEED_TO_CALL_SAVE_CLEAN_V => { return rsSaveCleanV(a1, a2, a3, a4, sp1); },
		schannel::HANDLE_SCHANNEL_RETURN_NEED_TO_CALL_READ_V => { return rsReadV(a1, a2, a3, sp1); },
		schannel::HANDLE_SCHANNEL_RETURN_NEED_TO_CALL_SAVE_M => { return rsSaveM(a1, a2, a3, sp1); },
		schannel::HANDLE_SCHANNEL_RETURN_NEED_TO_CALL_READ_M => { return rsReadM(a1, a2, a3, sp1); },
		schannel::HANDLE_SCHANNEL_RETURN_NEED_TO_CALL_EXCEPTION => {return rsException(sp1); },
		schannel::HANDLE_SCHANNEL_RETURN_NEED_TO_CALL_HCR => {
			unsafe {
				asm! (
					"
					mrs x0, hcr_el2
					bic x0, x0, #0x4000000
					msr hcr_el2, x0
					"
					::: "x0"
					);
			}
			return 0;
		}

		schannel::HANDLE_SCHANNEL_RETURN_NEED_TO_CALL_TELL => { return rsTellme(a1); },
		smc::GINSENG_SMC_CMD_RS_NULL => {ymh_log_str(&String::from("RS_NULL\n\0"))},
		smc::GINSENG_SMC_CMD_PING => { smcHandler_ping(a1, a2, a3, a4, a5); },
		smc::GINSENG_SMC_CMD_SET_64BIT => {set64bit(a1, a2); },
		smc::GINSENG_SMC_CMD_SET_64BIT_DCI => { set64bit_dci(a1, a2); },
		smc::GINSENG_SMC_CMD_CLEAR_PAGE | 
		smc::GINSENG_SMC_CMD_CLEAR_PAGE_TEST_CLEAR_IN_EL3_CHECK_IN_EL1 => { clearPage(a1); },
		smc::GINSENG_SMC_CMD_COPY_PAGE => { copyPage(a1, a2); }
		_ => {
			ymh_log_str("UNKNOWN CMD: \0");
			ymh_log_hex(smc_cmd);
			ymh_log_nl();
			// unsafe{ginseng_smc(smc_cmd, a1, a2, a3, a4, a5);}
			loop {}
		},
	}

	0
}