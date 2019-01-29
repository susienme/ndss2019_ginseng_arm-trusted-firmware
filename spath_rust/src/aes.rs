extern {
	pub fn aes_hw_set_encrypt_key(user_key: *const u64, bits: u32, key: *mut u32) -> i32;
	pub fn aes_hw_encrypt(plaintext: *const u64, ciphertext: *mut u64, key: *const u32);

	pub fn aes_hw_set_decrypt_key(user_key: *const u64, bits: u32, key: *mut u32) -> i32;
	pub fn aes_hw_decrypt(plaintext: *const u64, ciphertext: *mut u64, key: *const u32);
}

pub fn AES_ENC(plaintext: &[u64; 2], ciphertext: &mut [u64; 2], user_key: &[u64; 2]) {
	let mut key = [0 as u32; 61];
	unsafe{
		// aes_hw_set_encrypt_key(plaintext.as_ptr(), ciphertext.as_ptr(), )
		aes_hw_set_encrypt_key(user_key.as_ptr(), 128, key.as_mut_ptr());
		aes_hw_encrypt(plaintext.as_ptr(), ciphertext.as_mut_ptr(), key.as_ptr());
	} 
}



pub fn AES_DEC(ciphertext: &[u64; 2], plaintext: &mut [u64; 2], user_key: &[u64; 2]) {
	let mut key = [0 as u32; 61];
	unsafe{
		// aes_hw_set_encrypt_key(plaintext.as_ptr(), ciphertext.as_ptr(), )
		aes_hw_set_decrypt_key(user_key.as_ptr(), 128, key.as_mut_ptr());
		aes_hw_decrypt(ciphertext.as_ptr(), plaintext.as_mut_ptr(), key.as_ptr());
	} 
}