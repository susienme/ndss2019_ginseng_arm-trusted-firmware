use alloc::String;
use alloc::Vec;
use debug::*;

const CONSOLE_BASE: u64 = 0xF711_2000;
const CONSOLE_FR: u64 = 0x018;
const CONSOLE_FLAG_RXFIFO_EMPTY: u32 = (1 << 4);
const CONSOLE_FLAG_TXFIFO_FULL: u32 = (1 << 6);

const CONSOLE_DATA: u64 = CONSOLE_BASE;
const CONSOLE_FLAGS: u64 = CONSOLE_BASE + CONSOLE_FR;

const CHAR_BS: u8 = 8;
const CHAR_CR: u8 = 13;
const CHAR_NAK: u8 = 21;

macro_rules! DRAIN {
	($dest:expr) => {{
	unsafe {
		asm!("
			mov x2, xzr
			mov x0, #0x2000
			movk x0, #0xF711, lsl #16
		1:
			ldr w1, [x0, #0x18]
			tbnz w1, 4, 2f
			ldr w1, [x0]
			add x2, x2, #1
			b 1b
		2:
			mov $0, x2
			"
		: "=r" ($dest)
		:: "memory", "x0", "x1", "x2");
	}
	}};
}

// #[macro_export]
macro_rules! GETC {
	($dest:expr) => {{
	unsafe {
		asm!("
			mov x0, #0x2000
			movk x0, #0xF711, lsl #16
		1:
			ldr w1, [x0, #0x18]
			tbnz w1, 4, 1b

			ldr $0, [x0]
			"
		: "=r" ($dest)
		:: "memory", "x0", "x1");
	}
	}};
}

// #[macro_export]
macro_rules! PUTC {
	($char:expr) => {{
	unsafe {
			asm!("
			mov x0, #0x2000
			movk x0, #0xF711, lsl #16
		1:
			ldr w1, [x0, #0x18]
			tbnz w1, 6, 1b

			str $0, [x0]
			"
		::
		"r" ($char)
		: "x0", "x1");
	}
	}};
}

// #[macro_export]
macro_rules! GETC_ECHO {
	($dest:expr) => {{
		GETC!($dest);
		PUTC!($dest);
	}};
}

pub fn getLine() -> Vec<char> {
	let mut strV : Vec<char>= Vec::new();

	puts("[SEC CONSOLE] \0");

	loop {
		let c: u8;
		GETC_ECHO!(c);
		if ' ' as u8 <= c && c <= '~' as u8	{
			strV.push(c as char);
		} else {
			match c {
				CHAR_BS => {
					PUTC!(' ');
					PUTC!(CHAR_BS);
					strV.pop();
				} // backspace
				CHAR_CR => {
					PUTC!('\n');
					break;
				}	// carriage ret /r
				CHAR_NAK => {
					PUTC!(CHAR_CR);
					for _ in 0..strV.len() {
						PUTC!(' ');
					}
					PUTC!(CHAR_CR);
					strV.clear();
				}	// ctrl+u
				_ => {
					ymh_log_str("[You entered: \0");
					ymh_log_dec(c as u64);
					ymh_log_str("]\n\0");
				}
			}
		}
	}
	strV
}

pub fn getHexLine() -> u64 {
	let mut strV : Vec<char>= Vec::new();

	let mut drained: u64 = 0;
	DRAIN!(drained);
	puts("[SEC CONSOLE] \0");

	loop {
		let c: u8;
		GETC_ECHO!(c);
		if ' ' as u8 <= c && c <= '~' as u8	{
			strV.push(c as char);
		} else {
			match c {
				CHAR_BS => {
					PUTC!(' ');
					PUTC!(CHAR_BS);
					strV.pop();
				} // backspace
				CHAR_CR => {
					PUTC!('\n');
					break;
				}	// carriage ret /r
				CHAR_NAK => {
					PUTC!(CHAR_CR);
					for _ in 0..strV.len() {
						PUTC!(' ');
					}
					PUTC!(CHAR_CR);
					strV.clear();
				}	// ctrl+u
				_ => {
					ymh_log_str("[You entered: \0");
					ymh_log_dec(c as u64);
					ymh_log_str("]\n\0");
				}
			}
		}
	}

	let line: String = strV.into_iter().collect();
	if let Ok(k) = u64::from_str_radix(line.as_str(), 16) {
        return k;
    }

	0
}

pub fn puts(s: &str) {
	for c in s.chars() {
		if c == '\0' {break;}
		PUTC!(c);
	}
}