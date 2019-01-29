extern {
	pub fn printStr_native(s: *const u8);
	pub fn printHex_native(h: u64);
	pub fn printDec_native(h: u64);
	pub fn print_nl();
}

pub fn ymh_log_str(s: &str) {
	unsafe {
		printStr_native(s.as_ptr());
	}
}

pub fn ymh_log_hex(h: u64) {
	unsafe {
		printHex_native(h);
	}
}

pub fn ymh_log_dec(d: u64) {
	unsafe {
		printDec_native(d);
	}
}

pub fn ymh_log_nl() {
	unsafe{
		print_nl();
	}
}