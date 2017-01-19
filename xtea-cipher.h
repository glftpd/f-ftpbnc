/* XTEA - New Tiny Encryption Algorithm - Public Domain C Source */
/* based on http://www.simonshepherd.supanet.com/source.htm */
/* $Rev: 421 $ $Date: 2008-01-30 22:56:40 +0100 (Wed, 30 Jan 2008) $ */

#ifndef _XTEA_CIPHER_H
#define _XTEA_CIPHER_H

void xtea_encipher(const uint32_t *const v, uint32_t *const w,
		   const uint32_t *const k)
{
    register uint32_t y=v[0], z=v[1], sum=0,
	delta=0x9E3779B9, n=32;

    while(n-- > 0)
    {
	y += ((z << 4) ^ (z >> 5)) + (z ^ sum) + k[sum&3];
	sum += delta;
	z += ((y << 4) ^ (y >> 5)) + (y ^ sum) + k[sum>>11 & 3];
    }

    w[0]=y; w[1]=z;
}

void xtea_decipher(const uint32_t *const v, uint32_t *const w,
		   const uint32_t *const k)
{
    register uint32_t y=v[0], z=v[1], sum=0xC6EF3720,
	delta=0x9E3779B9, n=32;

    /* sum = delta<<5, in general sum = delta * n */

    while(n-- > 0)
    {
	z -= ((y << 4) ^ (y >> 5)) + (y ^ sum) + k[sum>>11 & 3];
	sum -= delta;
	y -= ((z << 4) ^ (z >> 5)) + (z ^ sum) + k[sum&3];
    }
   
    w[0]=y; w[1]=z;
}

void xtea_cbc_copy(unsigned char a[8], const unsigned char b[8]) {
    ((uint32_t*)a)[0] = ((uint32_t*)b)[0];
    ((uint32_t*)a)[1] = ((uint32_t*)b)[1];
}

void xtea_cbc_xor(unsigned char a[8], const unsigned char b[8]) {
    ((uint32_t*)a)[0] ^= ((uint32_t*)b)[0];
    ((uint32_t*)a)[1] ^= ((uint32_t*)b)[1];
}

/* please check that vl has 8 as divisor */
void xtea_cbc_encipher(unsigned char *v, unsigned int vl, const uint32_t *const k,
		       const unsigned char *const incbciv)
{
    unsigned vc = 0;
    unsigned char cbciv[8];

    xtea_cbc_copy(cbciv, incbciv);

    for(vc = 0; vc < vl; vc+=8) {
	xtea_cbc_xor(v+vc, cbciv);
	xtea_encipher((uint32_t*)(v+vc), (uint32_t*)(v+vc), k);
	xtea_cbc_copy(cbciv, v+vc);
    }
}

void xtea_cbc_decipher(unsigned char *v, unsigned int vl, const uint32_t *const k,
		       const unsigned char *const incbciv)
{
    unsigned vc = 0;
    unsigned char cbciv[8], cbcivnext[8];

    xtea_cbc_copy(cbciv, incbciv);

    for(vc = 0; vc < vl; vc+=8) {
	xtea_cbc_copy(cbcivnext, v+vc);
	xtea_decipher((uint32_t*)(v+vc), (uint32_t*)(v+vc), k);
	xtea_cbc_xor(v+vc, cbciv);
	xtea_cbc_copy(cbciv, cbcivnext);
    }
}

#ifdef _SHA256_H

void string_to_teakey(const char *str, unsigned char *teakey) {
    sha256_context shactx;
    unsigned char shakey[32];
    int n;
	       
    sha256_starts(&shactx);
    sha256_update(&shactx, (const unsigned char *)str, strlen(str));
    sha256_finish(&shactx, shakey);

    for(n = 0; n < 16; n++) {
	teakey[n] = shakey[n];
    }
    for(n = 16; n < 32; n++) {
	teakey[n-16] ^= shakey[n];
    }
}

#endif

#endif /* _XTEA_CIPHER_H */
