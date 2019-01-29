extern {
	pub fn sha1_block_data_order(state: *mut u32, data: *const u8, num: u32);
	pub fn memset(s: *mut u8, c: i32, n: usize) -> *const u8;
    pub fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *const u8;
}

const SHA_CBLOCK: usize = 64;

struct SHA_CTX {
	h: [u32; 5],
	Nl: u32, 
	Nh: u32,
	data: [u8; SHA_CBLOCK],
	num: u32
}

impl SHA_CTX {
	fn new() -> SHA_CTX {
		SHA_CTX {
			h: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
			Nl: 0,
			Nh: 0,
			data: [0; SHA_CBLOCK],
			num: 0
		}
	}
}

fn SHA1_Update(c: &mut SHA_CTX, data: *const u8, len: u32) {
	let mut data = data;
	let mut len = len;
	// println!("RUST: {:?}", data);

	if len == 0 { return; }

	let l = c.Nl + (len << 3);
	if l < c.Nl {
		/* Handle carries. */
		c.Nh = c.Nh + 1;
	}
	c.Nh = c.Nh + (len >> 29);
	c.Nl = l;

	let mut n = c.num;
	if n != 0 {
		if len >= SHA_CBLOCK as u32 || len + n >= SHA_CBLOCK as u32 {
			unsafe {
				memcpy(c.data[(n as usize)..SHA_CBLOCK].as_mut_ptr(), data, SHA_CBLOCK - n as usize);
				sha1_block_data_order(c.h.as_mut_ptr(), c.data.as_ptr(), 1);
			}
			n = SHA_CBLOCK as u32 - n;
			data = unsafe{data.offset(n as isize)};
			len -= n;
			c.num = 0;
			// Keep |c->data| zeroed when unused.
			unsafe { memset(c.data.as_mut_ptr(), 0, SHA_CBLOCK); }
		} else {
			unsafe { memcpy( c.data[(n as usize)..SHA_CBLOCK].as_mut_ptr(), data, len as usize); }
			c.num += len;
			return;
		}
	}

	n = len / SHA_CBLOCK as u32;
	if n > 0 {
		unsafe { sha1_block_data_order(c.h.as_mut_ptr(), data, n); }
		n *= SHA_CBLOCK as u32;
		data = unsafe{data.offset(n as isize)};
		len -= n;
	}

	if len != 0 {
		c.num = len;
		unsafe { memcpy(c.data.as_mut_ptr(), data, len as usize); }
	}
}

fn HOST_l2c(l: u32, c: &mut [u8]) {
	c[0] = (((l) >> 24) & 0xff) as u8;
	c[1] = (((l) >> 16) & 0xff) as u8;
	c[2] = (((l) >> 8) & 0xff) as u8;
	c[3] = (((l)) & 0xff) as u8;
}

fn HASH_MAKE_STRING(c: &mut SHA_CTX, s: &mut [u8; 20]) {
    {
    	let outSlice = &mut s[0..20];
    	HOST_l2c(c.h[0], outSlice);
    }

    {
    	let outSlice = &mut s[4..20];
    	HOST_l2c(c.h[1], outSlice);
    }

    {
    	let outSlice = &mut s[8..20];
    	HOST_l2c(c.h[2], outSlice);
    }

    {
    	let outSlice = &mut s[12..20];
    	HOST_l2c(c.h[3], outSlice);
    }

    {
    	let outSlice = &mut s[16..20];
    	HOST_l2c(c.h[4], outSlice);
    }
}

fn SHA1_Final(md: &mut [u8; 20], c: &mut SHA_CTX) {
	let mut n = c.num as usize;
	assert!(n < SHA_CBLOCK);
	c.data[n] = 0x80;
	n += 1;

	if n > (SHA_CBLOCK - 8) {
		unsafe { memset(c.data[n..SHA_CBLOCK].as_mut_ptr(), 0, SHA_CBLOCK - n); }
		n = 0;
		unsafe { sha1_block_data_order(c.h.as_mut_ptr(), c.data.as_ptr(), 1); }
	}
	unsafe { memset(c.data[n..SHA_CBLOCK].as_mut_ptr(), 0, SHA_CBLOCK - 8 - n); }

	{
		let data_slice = &mut c.data[(SHA_CBLOCK - 8)..SHA_CBLOCK];
		HOST_l2c(c.Nh, data_slice);
	}
	{
		let data_slice = &mut c.data[(SHA_CBLOCK - 4)..SHA_CBLOCK];
		HOST_l2c(c.Nl, data_slice);
	}

	unsafe {
		sha1_block_data_order(c.h.as_mut_ptr(), c.data.as_ptr(), 1);
		c.num = 0;
		memset(c.data.as_mut_ptr(), 0, SHA_CBLOCK);
	}

	HASH_MAKE_STRING(c, md);
}

pub fn SHA1(data: *const u8, len: u32, out: &mut [u8; 20] /*, ctxOut: *mut u8*/ ) {
	let mut ctx = SHA_CTX::new();
	SHA1_Update(&mut ctx, data, len);
	SHA1_Final(out, &mut ctx);
}