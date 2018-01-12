
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <openssl/sha.h>
#include <openssl/aes.h>

#define FALSE 0
#define TRUE  1

#define SHA256_DIGEST_LENGTH 32
#define SALT_LENGTH          16

//////////////////////////////////////////////////////////////////////////////
//      KEY     GEN
//

// Needed structure to 'stretch' a password
typedef struct {
	uint8_t updated_hash[SHA256_DIGEST_LENGTH];
	uint8_t password_hash[SHA256_DIGEST_LENGTH];
	uint8_t salt[SALT_LENGTH];
	uint64_t hash_count;
} bitlocker_chain_hash_t;

void asciitoutf16(const uint8_t* ascii, uint16_t* utf16)
{
	size_t len = strlen((char*)ascii);
	memset(utf16, 0, (len+1)*2);

	size_t loop = 0;
	for(loop = 0; loop < len; loop++)
		utf16[loop] = ascii[loop];
}

void stretch_user_key(const uint8_t *user_hash,
                     const uint8_t *salt,
                     uint8_t *result)
{
	bitlocker_chain_hash_t ch;
    size_t size = sizeof(bitlocker_chain_hash_t);
    size_t loop = 0;

    memset(&ch, 0, size);

	memcpy(ch.password_hash, user_hash, SHA256_DIGEST_LENGTH);
	memcpy(ch.salt,          salt,      SALT_LENGTH);

    for (loop = 0; loop < 0x100000; ++loop)
    {
        SHA256((const char *)&ch, size, ch.updated_hash);

        ch.hash_count++;
    }

    memcpy(result, ch.updated_hash, SHA256_DIGEST_LENGTH);
}

void user_key(const uint8_t *user_password,
             const uint8_t *salt,
             uint8_t *result_key)
{
	uint16_t* utf16_password = NULL;
	size_t    utf16_length   = 0;
	uint8_t   user_hash[32]  = {0,};

	/*
	 * We first get the SHA256(SHA256(to_UTF16(user_password)))
	 */
	utf16_length   = (strlen((char*) user_password)+1) * sizeof(uint16_t);
	utf16_password = malloc(utf16_length);

    memset(utf16_password, 0,  utf16_length);

	asciitoutf16(user_password, utf16_password);

	/* We're not taking the '\0\0' end of the UTF-16 string */
	SHA256((unsigned char *) utf16_password, utf16_length-2, user_hash);
	SHA256((unsigned char *) user_hash,      32,             user_hash);

	/*
	 * We then pass it to the key stretching manipulation
	 */
	stretch_user_key(user_hash, (uint8_t *) salt, result_key);

    free(utf16_password);
}

// Specifications of the recovery password
#define NB_RP_BLOCS   8
#define NB_DIGIT_BLOC 6

#define INTERMEDIATE_KEY_LENGTH 32

int valid_block(uint8_t* digits, int block_nb, uint16_t* short_password)
{
	// Check the parameters
	if(!digits)
		return FALSE;

	/* Convert chars into int */
	errno = 0;
	long int block = strtol((char *) digits, (char **) NULL, 10);
	if(errno == ERANGE)
		return FALSE;

	/* 1st check --  Checking if the bloc is divisible by eleven */
	if((block % 11) != 0)
		return FALSE;

	/* 2nd check -- Checking if the bloc is less than 2**16 * 11 */
	if(block >= 720896)
		return FALSE;

	/* 3rd check -- Checking if the checksum is correct */
	int8_t check_digit = (int8_t)(digits[0] - digits[1] + digits[2] - digits[3] + digits[4]
									- 48) % 11; /* Convert chars into digits */

	/* Some kind of bug the c modulo has: -2 % 11 yields -2 instead of 9 */
	while(check_digit < 0)
		check_digit = (int8_t)(check_digit + 11);

	if(check_digit != (digits[5] - 48))
		return FALSE;

	/*
	 * The bloc has a good look, store a short version of it
	 * We already have checked the size (see 2nd check), a uint16_t can contain
	 * the result
	 */
	if(short_password)
		*short_password = (uint16_t) (block / 11);

	return TRUE;
}

int is_valid_key(const uint8_t *recovery_password, uint16_t *short_password)
{
	// Check the parameters
	if(recovery_password == NULL)
		return FALSE;

	if(short_password == NULL)
		return FALSE;

	/* Begin by checking the length of the password */
	if(strlen((char*)recovery_password) != 48+7)
		return FALSE;

	const uint8_t *rp = recovery_password;
	uint16_t *sp = short_password;
	uint8_t digits[NB_DIGIT_BLOC + 1];

	int loop = 0;

	for(loop = 0; loop < NB_RP_BLOCS; ++loop)
	{
		memcpy(digits, rp, NB_DIGIT_BLOC);
		digits[NB_DIGIT_BLOC] = 0;

		/* Check block validity */
		if(!valid_block(digits, loop+1, sp))
			return FALSE;

		sp++;
		rp += 7;
	}

	// All of the recovery password seems to be good

	return TRUE;
}

void stretch_recovery_key(const uint8_t *recovery_key,
                         const uint8_t *salt,
                         uint8_t *result)
{
	size_t size = sizeof(bitlocker_chain_hash_t);
	bitlocker_chain_hash_t * ch = NULL;
	uint64_t loop = 0;

	ch = (bitlocker_chain_hash_t *) malloc(size);

	memset(ch, 0, size);

	/* 16 is the size of the recovery_key, in bytes (see doc above) */
	SHA256(recovery_key, 16, ch->password_hash);

	memcpy(ch->salt, salt, SALT_LENGTH);

	for(loop = 0; loop < 0x100000; ++loop)
	{
		SHA256((unsigned char *)ch, size, ch->updated_hash);

		ch->hash_count++;
	}

	memcpy(result, ch->updated_hash, SHA256_DIGEST_LENGTH);

    free(ch);
}

void intermediate_key(const uint8_t *recovery_password,
                     const uint8_t *salt,
                     uint8_t *result_key)
{
	uint16_t passwd[NB_RP_BLOCS];
	uint8_t *iresult = malloc(INTERMEDIATE_KEY_LENGTH * sizeof(uint8_t));
	uint8_t *iresult_save = iresult;
	int loop = 0;

	memset(passwd,  0, NB_RP_BLOCS * sizeof(uint16_t));
	memset(iresult, 0, INTERMEDIATE_KEY_LENGTH * sizeof(uint8_t));

	/* Check if the recovery_password has a good smile */
	if(!is_valid_key(recovery_password, passwd))
	{
        free(iresult);
        exit(-1);
	}

	// passwd now contains the blocs divided by 11 in a uint16_t tab
	// Convert each one of the blocs in little endian and make it one buffer
	for(loop = 0; loop < NB_RP_BLOCS; ++loop)
	{
		*iresult = (uint8_t)(passwd[loop] & 0x00ff);
		iresult++;
		*iresult = (uint8_t)((passwd[loop] & 0xff00) >> 8);
		iresult++;
	}

	iresult = iresult_save;

	stretch_recovery_key(iresult, salt, result_key);

    free(iresult);
}

//////////////////////////////////////////////////////////////////////////////
//   AES-CCM    DEC

typedef uint16_t dis_datums_entry_type_t;
typedef uint16_t dis_datums_value_type_t;

#include <assert.h>

#ifndef static_assert
#define static_assert(x, s) extern int static_assertion[2*!!(x)-1]
#endif

#pragma pack (1)

typedef struct _header_safe
{
	uint16_t datum_size;
	dis_datums_entry_type_t entry_type;
	dis_datums_value_type_t value_type;
	uint16_t error_status;
} datum_header_safe_t;

static_assert(
	sizeof(struct _header_safe) == 8,
	"Datum header structure's size isn't equal to 8"
);

typedef struct _datum_aes_ccm
{
	datum_header_safe_t header;
	uint8_t nonce[12];
	uint8_t mac[16];
} datum_aes_ccm_t;

typedef uint16_t cipher_t;

typedef struct _datum_key
{
	datum_header_safe_t header;
	cipher_t algo;
	uint16_t padd;
} datum_key_t;

#pragma pack ()

#define NB_DATUMS_VALUE_TYPES 20

typedef struct _datum_value_types_properties
{
	/*
	 * The header size of the datum, this is including the datum_header_safe_t
	 * structure which is beginning each one of them
	 */
	uint16_t size_header;

	/*
	 * A flag which tells us if the datum has one or more nested datum
	 * 0 = No nested datum
	 * 1 = One or more nested datum
	 */
	uint8_t has_nested_datum;

	/* Always equal to 0, maybe for padding */
	uint8_t zero;
} value_types_properties_t;

static const value_types_properties_t datum_value_types_prop[] =
{
	{ 8,    0, 0 },  // ERASED
	{ 0xc,  0, 0 },  // KEY
	{ 8,    0, 0 },  // UNICODE
	{ 0x1c, 1, 0 },  // STRETCH
	{ 0xc,  1, 0 },  // USE KEY
	{ 0x24, 0, 0 },  // AES CCM
	{ 0xc,  0, 0 },  // TPM ENCODED
	{ 8,    0, 0 },  // VALIDATION
	{ 0x24, 1, 0 },  // VMK
	{ 0x20, 1, 0 },  // EXTERNAL KEY
	{ 0x2c, 1, 0 },  // UPDATE
	{ 0x34, 0, 0 },  // ERROR

	/* These ones below were added for Seven */
	{ 8,    0, 0 },  // ASYM ENC
	{ 8,    0, 0 },  // EXPORTED KEY
	{ 8,    0, 0 },  // PUBLIC KEY
	{ 0x18, 0, 0 },  // VIRTUALIZATION INFO
	{ 0xc,  0, 0 },  // SIMPLE
	{ 0xc,  0, 0 },  // SIMPLE
	{ 0x1c, 0, 0 },  // CONCAT HASH KEY
	{ 0xc,  0, 0 }   // SIMPLE
};

#define AUTHENTICATOR_LENGTH 16

void xor_buffer(unsigned char* buf1, const unsigned char* buf2, unsigned char* output, size_t size)
{
	size_t loop;
	unsigned char* tmp = NULL;

	if(output)
		tmp = output;
	else
		tmp = buf1;

	for(loop = 0; loop < size; ++loop, ++buf1, ++buf2, ++tmp)
		*tmp = *buf1 ^ *buf2;
}

void aes_ccm_encrypt_decrypt(
					 AES_KEY* ctx,
					 unsigned char* nonce, unsigned char nonce_length,
					 unsigned char* input, unsigned int  input_length,
					 unsigned char* mac,   unsigned int  mac_length,
					 unsigned char* output)
{
	unsigned char iv[16];
	unsigned int loop = 0;
	unsigned char tmp_buf[16] = {0,};
	unsigned char* failsafe = NULL;

	memset(iv, 0, sizeof(iv));
	memcpy(iv + 1, nonce, (nonce_length % sizeof(iv)));

	if(15 - nonce_length - 1 < 0)
    {
        printf("Nonce Length too large.\n");
        exit(-1);
    }

	*iv = (unsigned char)(15 - nonce_length - 1);

	AES_ecb_encrypt(iv, tmp_buf, ctx, AES_ENCRYPT);

	xor_buffer(mac, tmp_buf, NULL, mac_length);

	/* Increment the internal iv counter */
	iv[15] = 1;

	if(input_length > sizeof(iv))
	{
		loop = input_length >> 4;

		do
		{
			AES_ecb_encrypt(iv, tmp_buf, ctx, AES_ENCRYPT);

			xor_buffer(input, tmp_buf, output, sizeof(iv));

			iv[15]++;

			/* A failsafe to not have the same iv twice */
			if(!iv[15])
			{
				failsafe = &iv[15];

				do
				{
					failsafe--;
					(*failsafe)++;
				} while(*failsafe == 0 && failsafe >= &iv[0]);
			}

			input += sizeof(iv);
			output += sizeof(iv);
			input_length = (unsigned int)(input_length - sizeof(iv));

		} while(--loop);
	}

	/*
	 * Last block
	 */
	if(input_length)
	{
		AES_ecb_encrypt(iv, tmp_buf, ctx, AES_ENCRYPT);

		xor_buffer(input, tmp_buf, output, input_length);
	}
}

void aes_ccm_compute_unencrypted_tag(
									AES_KEY* ctx,
									unsigned char* nonce, unsigned char nonce_length,
									unsigned char* buffer, unsigned int buffer_length,
									unsigned char* mac)
{
	unsigned char iv[AUTHENTICATOR_LENGTH];
	unsigned int loop = 0;
	unsigned int tmp_size = buffer_length;

	/*
	 * Construct the IV
	 */
	memset(iv, 0, AUTHENTICATOR_LENGTH);
	iv[0] = ((unsigned char)(0xe - nonce_length)) | ((AUTHENTICATOR_LENGTH - 2) & 0xfe) << 2;
	memcpy(iv + 1, nonce, (nonce_length % AUTHENTICATOR_LENGTH));
	for(loop = 15; loop > nonce_length; --loop)
	{
		*(iv + loop) = tmp_size & 0xff;
		tmp_size = tmp_size >> 8;
	}

	/*
	 * Compute algorithm
	 */
	AES_ecb_encrypt(iv, iv, ctx, AES_ENCRYPT);


	if(buffer_length > 16)
	{
		loop = buffer_length >> 4;

		do
		{
			xor_buffer(iv, buffer, NULL, AUTHENTICATOR_LENGTH);

			AES_ecb_encrypt(iv, iv, ctx, AES_ENCRYPT);

			buffer += AUTHENTICATOR_LENGTH;
			buffer_length -= AUTHENTICATOR_LENGTH;

		} while(--loop);
	}

	/*
	 * Last block
	 */
	if(buffer_length)
	{
		xor_buffer(iv, buffer, NULL, buffer_length);
		AES_ecb_encrypt(iv, iv, ctx, AES_ENCRYPT);
	}

	memcpy(mac, iv, AUTHENTICATOR_LENGTH);
}

void decrypt_key(
	unsigned char* input,
	unsigned int   input_size,
	unsigned char* mac,
	unsigned char* nonce,
	unsigned char* key,
	unsigned int   keybits,
	void** output)
{
	AES_KEY ctx;

	uint8_t mac_first [AUTHENTICATOR_LENGTH];
	uint8_t mac_second[AUTHENTICATOR_LENGTH];

    *output = malloc(input_size);
    memset(*output, 0, input_size);

	memcpy(mac_first, mac, AUTHENTICATOR_LENGTH);

	AES_set_encrypt_key(key, keybits, &ctx);

	aes_ccm_encrypt_decrypt(
		&ctx,
		nonce,
		0xc,
		input,
		input_size,
		mac_first,
		AUTHENTICATOR_LENGTH,
		(unsigned char*) *output
	);

	memset(mac_second, 0, AUTHENTICATOR_LENGTH);
	aes_ccm_compute_unencrypted_tag(
		&ctx,
		nonce,
		0xc,
		(unsigned char*) *output,
		input_size,
		mac_second
	);

	if(memcmp(mac_first, mac_second, AUTHENTICATOR_LENGTH) != 0)
    {
        printf("MAC NOT Match!\n");
        exit(-1);
    }
}

void get_vmk(datum_aes_ccm_t* vmk_datum, uint8_t* recovery_key, size_t key_size,
        datum_key_t** vmk)
{
	unsigned int vmk_size = 0;
	unsigned int header_size = 0;

	header_size = datum_value_types_prop[vmk_datum->header.value_type].size_header;
	vmk_size = vmk_datum->header.datum_size - header_size;

	decrypt_key(
			(unsigned char*) vmk_datum + header_size,
			vmk_size,
			vmk_datum->mac,
			vmk_datum->nonce,
			recovery_key,
			(unsigned int)key_size * 8,
			(void**) vmk
	);
}

void get_header_safe(void* data, datum_header_safe_t* header)
{
	/* Too easy, boring */
	memcpy(header, data, sizeof(datum_header_safe_t));

	/* Now check if the header is good */
	if(header->datum_size < sizeof(datum_header_safe_t) ||
	   header->value_type > NB_DATUMS_VALUE_TYPES)
    {
        printf("Bad Header\n");
        exit(-1);
    }
}

void get_payload_safe(void* data, void** payload, size_t* size_payload)
{
	datum_header_safe_t header;
	uint16_t size_header = 0;

	get_header_safe(data, &header);

	size_header = datum_value_types_prop[header.value_type].size_header;

	if(header.datum_size <= size_header)
    {
        printf("Datum Error\n");
        exit(-1);
    }

	*size_payload = (size_t)(header.datum_size - size_header);

	*payload = malloc(*size_payload);

	memset(*payload, 0, *size_payload);
	memcpy(*payload, data + size_header, *size_payload);
}

void get_fvek(void *efvek, void* vmk_datum, void** fvek_datum)
{
	unsigned int fvek_size = 0;
	unsigned int header_size = 0;
	void* vmk_key = NULL;
	size_t vmk_key_size = 0;
	datum_aes_ccm_t* fvek = efvek;

	header_size = datum_value_types_prop[fvek->header.value_type].size_header;
	fvek_size = fvek->header.datum_size - header_size;

	get_payload_safe(vmk_datum, &vmk_key, &vmk_key_size);

	decrypt_key(
			(unsigned char*) fvek + header_size,
			fvek_size,
			fvek->mac,
			fvek->nonce,
			vmk_key,
			(unsigned int)vmk_key_size * 8,
			fvek_datum
	);

    free(vmk_key);
}


//////////////////////////////////////////////////////////////////////////////
//   EXPORT    API

void get_fvek_from_user_pass(uint8_t *user_pass, uint8_t salt[16], void *evmk, void *efvek, void **result)
{
    uint8_t user_hash[32] = {0,};
    void *vmk_datum = NULL;
    void *fvek_datum = NULL;

    // Calc User Hash
    user_key(user_pass, salt, user_hash);

    get_vmk(evmk, user_hash, 32, (datum_key_t**)&vmk_datum);

    get_fvek(efvek, vmk_datum, &fvek_datum);

    free(vmk_datum);
    *result = fvek_datum;
}

void get_fvek_from_clearkey(uint8_t *clearkey, size_t ck_size, void *evmk, void *efvek, void **result)
{
    void *vmk_datum = NULL;
    void *fvek_datum = NULL;

    get_vmk(evmk, clearkey, ck_size, (datum_key_t**)&vmk_datum);

    get_fvek(efvek, vmk_datum, &fvek_datum);

    free(vmk_datum);
    *result = fvek_datum;
}

void get_fvek_from_recovery_pass(uint8_t *recovery_password, uint8_t salt[16], void *evmk, void *efvek, void **result)
{
    uint8_t *recovery_key = NULL;
    void *vmk_datum = NULL;
    void *fvek_datum = NULL;

    recovery_key = malloc(32 * sizeof(uint8_t));

    intermediate_key(recovery_password, salt, recovery_key);

    get_vmk(evmk, recovery_key, 32, (datum_key_t**)&vmk_datum);

    get_fvek(efvek, vmk_datum, &fvek_datum);

    free(vmk_datum);
    free(recovery_key);
    *result = fvek_datum;
}

// VMK is stored in bek file
// void get_fvek_from_bekfile()

void check_vmk_from_user_pass(uint8_t *user_pass, uint8_t salt[16], void *evmk)
{
    uint8_t user_hash[32] = {0,};
    void *vmk_datum = NULL;

    // Calc User Hash
    user_key(user_pass, salt, user_hash);

    get_vmk(evmk, user_hash, 32, (datum_key_t**)&vmk_datum);

    free(vmk_datum);
}



int main()
{
    uint8_t salt[16] = {0};
    datum_aes_ccm_t *vmk = malloc(0x1000);

    int fd = open("salt.bin", O_RDONLY);
    read(fd, salt, 16);
    close(fd);

    fd = open("vmk.bin", O_RDONLY);
    ssize_t nb_read = read(fd, vmk, 0x1000);
    close(fd);

    if (nb_read != vmk->header.datum_size)
    {
        printf("Read Error\n");
        exit(-1);
    }

    check_vmk_from_user_pass("Password01!", salt, vmk);

    printf("Succeed\n");
    return 0;
}


