
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static unsigned int crc32_tab[] = {
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419,
	0x706af48f, 0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4,
	0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07,
	0x90bf1d91, 0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
	0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7, 0x136c9856,
	0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
	0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4,
	0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
	0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3,
	0x45df5c75, 0xdcd60dcf, 0xabd13d59, 0x26d930ac, 0x51de003a,
	0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599,
	0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
	0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190,
	0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f,
	0x9fbfe4a5, 0xe8b8d433, 0x7807c9a2, 0x0f00f934, 0x9609a88e,
	0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
	0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed,
	0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
	0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3,
	0xfbd44c65, 0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
	0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a,
	0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5,
	0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa, 0xbe0b1010,
	0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17,
	0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6,
	0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615,
	0x73dc1683, 0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
	0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1, 0xf00f9344,
	0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
	0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a,
	0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
	0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1,
	0xa6bc5767, 0x3fb506dd, 0x48b2364b, 0xd80d2bda, 0xaf0a1b4c,
	0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef,
	0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
	0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe,
	0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31,
	0x2cd99e8b, 0x5bdeae1d, 0x9b64c2b0, 0xec63f226, 0x756aa39c,
	0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
	0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b,
	0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
	0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1,
	0x18b74777, 0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
	0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45, 0xa00ae278,
	0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7,
	0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc, 0x40df0b66,
	0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605,
	0xcdd70693, 0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8,
	0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b,
	0x2d02ef8d
};

unsigned int crc32(const unsigned char *s, const unsigned int len)
{
	unsigned int loop;
	unsigned int result;

	result = ~ (unsigned) 0;
	for(loop = 0; loop < len; loop++)
		result = crc32_tab[(result ^ s[loop]) & 0xff] ^ (result >> 8);
	return ~result;
}


#include <assert.h>

/* Convention */
#define TRUE 1
#define FALSE 0

#ifndef static_assert
#define static_assert(x, s) extern int static_assertion[2*!!(x)-1]
#endif

typedef uint8_t guid_t[16];
typedef uint64_t ntfs_time_t;
typedef uint16_t version_t;

#pragma pack (1)
/** First sector of an NTFS or BitLocker volume */
typedef struct _volume_header
{
	/* 512 bytes long */
	uint8_t  jump[3];             //                                                -- offset 0
	uint8_t  signature[8];        // = "-FVE-FS-" (without 0 at the string's end)   -- offset 3
	                              // = "NTFS    " (idem) for NTFS volumes (ORLY?)
	                              // = "MSWIN4.1" for BitLocker-To-Go encrypted volumes

	uint16_t sector_size;         // = 0x0200 = 512 bytes                           -- offset 0xb
	uint8_t  sectors_per_cluster; //                                                -- offset 0xd
	uint16_t reserved_clusters;   //                                                -- offset 0xe
	uint8_t  fat_count;           //                                                -- offset 0x10
	uint16_t root_entries;        //                                                -- offset 0x11
	uint16_t nb_sectors_16b;      //                                                -- offset 0x13
	uint8_t  media_descriptor;    //                                                -- offset 0x15
	uint16_t sectors_per_fat;     //                                                -- offset 0x16
	uint16_t sectors_per_track;   //                                                -- offset 0x18
	uint16_t nb_of_heads;         //                                                -- offset 0x1a
	uint32_t hidden_sectors;      //                                                -- offset 0x1c
	uint32_t nb_sectors_32b;      //                                                -- offset 0x20

	union {                       //                                                -- offset 0x24
		struct { // Classic BitLocker
			uint8_t  unknown2[4];         // NTFS = 0x00800080 (little endian)
			uint64_t nb_sectors_64b;      //                                        -- offset 0x28
			uint64_t mft_start_cluster;   //                                        -- offset 0x30
			union {                       // Metadata LCN or MFT Mirror             -- offset 0x38
				uint64_t metadata_lcn;    //  depending on whether we're talking about a Vista volume
				uint64_t mft_mirror;      //  or an NTFS one
			};
			uint8_t  unknown3[96];        //                                        -- offset 0x40

			guid_t   guid;                //                                        -- offset 0xa0
			uint64_t information_off[3];  // NOT for Vista                          -- offset 0xb0
			uint64_t eow_information_off[2]; // NOT for Vista NOR 7                 -- offset 0xc8

			uint8_t  unknown4[294];       //                                        -- offset 0xd8
		};
		struct { // BitLocker-To-Go
			uint8_t  unknown5[35];

			uint8_t  fs_name[11];         //                                        -- offset 0x47
			uint8_t  fs_signature[8];     //                                        -- offset 0x52

			uint8_t  unknown6[334];       //                                        -- offset 0x5a

			guid_t   bltg_guid;           //                                        -- offset 0x1a8
			uint64_t bltg_header[3];      //                                        -- offset 0x1b8

			uint8_t  Unknown7[46];        //                                        -- offset 0x1d0
		};
	};

	uint16_t boot_partition_identifier; // = 0xaa55                                 -- offset 0x1fe
} volume_header_t; // Size = 512

static_assert(
	sizeof(struct _volume_header) == 512,
	"Volume header structure's size isn't equal to 512"
);

typedef struct _bitlocker_dataset
{
	uint32_t size;         //                      -- offset 0
	uint32_t unknown1;     // = 0x0001 FIXME       -- offset 4
	uint32_t header_size;  // = 0x0030             -- offset 8
	uint32_t copy_size;    // = dataset_size       -- offset 0xc

	guid_t guid;           // dataset GUID         -- offset 0x10
	uint32_t next_counter; //                      -- offset 0x20

	uint16_t algorithm;    //                      -- offset 0x24
	uint16_t trash;        //                      -- offset 0x26
	ntfs_time_t timestamp; //                      -- offset 0x28
} bitlocker_dataset_t; // Size = 0x30

static_assert(
	sizeof(struct _bitlocker_dataset) == 0x30,
	"BitLocker dataset structure's size isn't equal to 0x30"
);

/** Different states BitLocker is in */
enum state_types
{
	METADATA_STATE_NULL                     = 0,
	METADATA_STATE_DECRYPTED                = 1,
	METADATA_STATE_SWITCHING_ENCRYPTION     = 2,
	METADATA_STATE_EOW_ACTIVATED            = 3,
	METADATA_STATE_ENCRYPTED                = 4,
	METADATA_STATE_SWITCH_ENCRYPTION_PAUSED = 5
};
typedef uint16_t dis_metadata_state_t;

typedef struct _bitlocker_information
{
	uint8_t signature[8]; // = "-FVE-FS-"                                                   -- offset 0
	uint16_t size;        // Total size (has to be multiplied by 16 when the version is 2)  -- offset 8
	version_t version;    // = 0x0002 for Windows 7 and 1 for Windows Vista                 -- offset 0xa

	/* Not sure about the next two fields */
	dis_metadata_state_t curr_state;  // Current encryption state                           -- offset 0xc
	dis_metadata_state_t next_state;  // Next encryption state                              -- offset 0xe

	uint64_t encrypted_volume_size; // Size of the encrypted volume                         -- offset 0x10
	/*
	 * The following size describes a virtualized region. This region is only
	 * checked when this->curr_state == 2. It begins at the offset described by
	 * this->encrypted_volume_size
	 */
	uint32_t convert_size;  //                                                              -- offset 0x18
	uint32_t nb_backup_sectors;   //                                                        -- offset 0x1c

	uint64_t information_off[3];  //                                                        -- offset 0x20

	union {
		uint64_t boot_sectors_backup; // Address where the boot sectors have been backed up -- offset 0x38
		uint64_t mftmirror_backup;    // This is the address of the MftMirror for Vista     -- offset 0x38
	};

	struct _bitlocker_dataset dataset; // See above                                         -- offset 0x40
} bitlocker_information_t; // Size = 0x40 + 0x30

static_assert(
	sizeof(struct _bitlocker_information) == (0x40 + 0x30),
	"BitLocker information structure's size isn't equal to 0x70"
);

typedef struct _bitlocker_validations
{
	uint16_t  size;
	version_t version;
	uint32_t  crc32;
} bitlocker_validations_t; // Size = 8

static_assert(
	sizeof(struct _bitlocker_validations) == 8,
	"BitLocker validations structure's size isn't equal to 8"
);

typedef uint16_t dis_datums_entry_type_t;
typedef uint16_t dis_datums_value_type_t;

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

/* Datum type = 8 */
typedef struct _datum_vmk
{
	datum_header_safe_t header;
	guid_t guid;
	uint8_t nonce[12];
} datum_vmk_t;

typedef uint16_t cipher_t;

/* Datum type = 3 */
typedef struct _datum_stretch_key
{
	datum_header_safe_t header;
	cipher_t algo;
	uint16_t padd;
	uint8_t  salt[16];
} datum_stretch_key_t;

/**
 * This structure is new to Windows 8
 * It's the virtualization datum's payload
 */
typedef struct _extended_info {
	uint16_t unknown1;
	uint16_t size;
	uint32_t unknown2;
	uint64_t flags;
	uint64_t convertlog_addr;
	uint32_t convertlog_size;
	uint32_t sector_size1;
	uint32_t sector_size2;
} extended_info_t;

/* Datum type = 15 */
typedef struct _datum_virtualization
{
	datum_header_safe_t header;
	uint64_t ntfs_boot_sectors;
	uint64_t nb_bytes;

	/*
	 * Below is a structure added to this virtualization structure in Windows 8
	 * The header is still 0x18 in size, which means xinfo is a payload
	 */
	extended_info_t xinfo;
} datum_virtualization_t;

#pragma pack ()

/* Here are some specifics entry types (second field of the safe header) */
#define NB_DATUMS_ENTRY_TYPES 12

enum entry_types
{
	DATUMS_ENTRY_UNKNOWN1 = 0x0000,
	DATUMS_ENTRY_UNKNOWN2,
	DATUMS_ENTRY_VMK,
	DATUMS_ENTRY_FVEK,
	DATUMS_ENTRY_UNKNOWN3,
	DATUMS_ENTRY_UNKNOWN4,
	DATUMS_ENTRY_STARTUP_KEY,
	DATUMS_ENTRY_ENCTIME_INFORMATION,
	DATUMS_ENTRY_UNKNOWN7,
	DATUMS_ENTRY_UNKNOWN8,
	DATUMS_ENTRY_UNKNOWN9,
	DATUMS_ENTRY_UNKNOWN10,
	DATUMS_ENTRY_FVEK_2
};

#define NB_DATUMS_VALUE_TYPES 20

enum value_types
{
	/*  0 */ DATUMS_VALUE_ERASED = 0x0000,
	/*  1 */ DATUMS_VALUE_KEY,
	/*  2 */ DATUMS_VALUE_UNICODE,
	/*  3 */ DATUMS_VALUE_STRETCH_KEY,
	/*  4 */ DATUMS_VALUE_USE_KEY,
	/*  5 */ DATUMS_VALUE_AES_CCM,
	/*  6 */ DATUMS_VALUE_TPM_ENCODED,
	/*  7 */ DATUMS_VALUE_VALIDATION,
	/*  8 */ DATUMS_VALUE_VMK,
	/*  9 */ DATUMS_VALUE_EXTERNAL_KEY,
	/* 10 */ DATUMS_VALUE_UPDATE,
	/* 11 */ DATUMS_VALUE_ERROR,

	/* Below is only available on Windows Seven */
	/* 12 */ DATUMS_VALUE_ASYM_ENC,
	/* 13 */ DATUMS_VALUE_EXPORTED_KEY,
	/* 14 */ DATUMS_VALUE_PUBLIC_KEY,
	/* 15 */ DATUMS_VALUE_VIRTUALIZATION_INFO,
	/* 16 */ DATUMS_VALUE_SIMPLE_1,
	/* 17 */ DATUMS_VALUE_SIMPLE_2,
	/* 18 */ DATUMS_VALUE_CONCAT_HASH_KEY,
	/* 19 */ DATUMS_VALUE_SIMPLE_3
};

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

typedef struct _regions
{
	/* Metadata offset */
	uint64_t addr;
	/* Metadata size on disk */
	uint64_t size;
} dis_regions_t;

/** Known BitLocker versions */
enum {
	V_VISTA = 1,
	V_SEVEN = 2  // Same version used by Windows 8
};

/* Signatures of volumes */
#define BITLOCKER_SIGNATURE      "-FVE-FS-"
#define BITLOCKER_SIGNATURE_SIZE strlen(BITLOCKER_SIGNATURE)


#define NTFS_SIGNATURE           "NTFS    "
#define NTFS_SIGNATURE_SIZE      strlen(NTFS_SIGNATURE)


#define BITLOCKER_TO_GO_SIGNATURE "MSWIN4.1"
#define BITLOCKER_TO_GO_SIGNATURE_SIZE strlen(BITLOCKER_TO_GO_SIGNATURE)

/**
 * Some GUIDs found in BitLocker
 */
const guid_t INFORMATION_OFFSET_GUID = {
	0x3b, 0xd6, 0x67, 0x49, 0x29, 0x2e, 0xd8, 0x4a,
	0x83, 0x99, 0xf6, 0xa3, 0x39, 0xe3, 0xd0, 0x01
};

const guid_t EOW_INFORMATION_OFFSET_GUID = {
	0x3b, 0x4d, 0xa8, 0x92, 0x80, 0xdd, 0x0e, 0x4d,
	0x9e, 0x4e, 0xb1, 0xe3, 0x28, 0x4e, 0xae, 0xd8
};



static volume_header_t* volume_header = NULL;
static size_t nb_virt_region = 0;
static dis_regions_t    virt_region[5] = {0};
static bitlocker_information_t* ginformation = NULL;
static bitlocker_dataset_t* gdataset = NULL;
static off_t virtualized_size = 0;
static extended_info_t* xinfo = NULL;


int get_header_safe(void* data, datum_header_safe_t* header)
{
	// Check parameters
	if(!data)
		return FALSE;

	/* Too easy, boring */
	memcpy(header, data, sizeof(datum_header_safe_t));

	/* Now check if the header is good */
	if(header->datum_size < sizeof(datum_header_safe_t) ||
	   header->value_type > NB_DATUMS_VALUE_TYPES)
		return FALSE;

	return TRUE;
}

int get_next_datum(
	dis_datums_entry_type_t entry_type,
	dis_datums_value_type_t value_type,
	void* datum_begin,
	void** datum_result)
{
	// Check parameters
	if(value_type > NB_DATUMS_VALUE_TYPES)
		return FALSE;

	bitlocker_dataset_t* dataset = gdataset;
	void* datum = NULL;
	void* limit = (char*)dataset + dataset->size;
	datum_header_safe_t header;

	*datum_result = NULL;
	memset(&header, 0, sizeof(datum_header_safe_t));
	if(datum_begin)
		datum = datum_begin + *(uint16_t*)datum_begin;
	else
		datum = (char*)dataset + dataset->header_size;

	while(1)
	{
		if(datum + 8 >= limit)
			break;

		if(!get_header_safe(datum, &header))
			break;

		if(value_type == UINT16_MAX && entry_type == UINT16_MAX)
		{
			/*
			 * If the datum types are not in range, assume the caller want each
			 * datum
			 */
			*datum_result = datum;
			break;
		}
		else if((entry_type == header.entry_type || entry_type == UINT16_MAX) &&
		        (value_type == header.value_type || value_type == UINT16_MAX))
		{
			/*
			 * If the entry type and the value type searched match,
			 * then return this datum
			 */
			*datum_result = datum;
			break;
		}

		datum += header.datum_size;

		memset(&header, 0, sizeof(datum_header_safe_t));
	}

	if(!*datum_result)
		return FALSE;

	return TRUE;
}

void get_vmk_datum_from_range(uint16_t min_range,
	uint16_t max_range, void** vmk_datum)
{
	uint16_t datum_range = 0;

	*vmk_datum = NULL;

	while(1)
	{
		if(!get_next_datum(
				DATUMS_ENTRY_VMK,
				DATUMS_VALUE_VMK,
				*vmk_datum,
				vmk_datum
		))
		{
			*vmk_datum = NULL;
            exit(-1);
		}

		/* The last two bytes of the nonce is used as a priority range */
		memcpy(&datum_range, &((*(datum_vmk_t**)vmk_datum)->nonce[10]), 2);

		if(min_range <= datum_range && datum_range <= max_range)
			return;
	}
}

int get_nested_datum(void* datum, void** datum_nested)
{
	// Check parameters
	if(!datum)
		return FALSE;

	datum_header_safe_t header;

	if(!get_header_safe(datum, &header))
		return FALSE;

	if(!datum_value_types_prop[header.value_type].has_nested_datum)
		return FALSE;

	uint16_t size = datum_value_types_prop[header.value_type].size_header;
	*datum_nested = (char*)datum + size;

	return TRUE;
}

void get_nested_datumvaluetype(void* datum, dis_datums_value_type_t value_type, void** datum_nested)
{
	// Check parameters
	if(!datum)
        exit(-1);

	/* Get the first nested datum */
	if(!get_nested_datum(datum, datum_nested))
        exit(-1);

	datum_header_safe_t header;
	datum_header_safe_t nested_header;

	if(!get_header_safe(datum, &header))
        exit(-1);

	if(!get_header_safe(*datum_nested, &nested_header))
        exit(-1);

	/* While we don't have the type we're looking for */
	while(nested_header.value_type != value_type)
	{
		/* Just go to the next datum */
		*datum_nested += nested_header.datum_size;

		/* If we're not into the datum anymore */
		if((char*)datum + header.datum_size <= (char*)*datum_nested)
            exit(-1);

		if(!get_header_safe(*datum_nested, &nested_header))
            exit(-1);
	}
}

static inline int get_version_from_volume_header()
{
	if(memcmp(BITLOCKER_SIGNATURE, volume_header->signature,
	          BITLOCKER_SIGNATURE_SIZE) == 0)
	{
		if(volume_header->metadata_lcn == 0)
			return V_SEVEN;

		return V_VISTA;
	}

	return -1;
}

int check_match_guid(const guid_t guid_1, const guid_t guid_2)
{
	return (
		guid_1[0] == guid_2[0] &&
		guid_1[1] == guid_2[1] &&
		guid_1[2] == guid_2[2] &&
		guid_1[3] == guid_2[3] &&
		guid_1[4] == guid_2[4] &&
		guid_1[5] == guid_2[5] &&
		guid_1[6] == guid_2[6] &&
		guid_1[7] == guid_2[7] &&
		guid_1[8] == guid_2[8] &&
		guid_1[9] == guid_2[9] &&
		guid_1[10] == guid_2[10] &&
		guid_1[11] == guid_2[11] &&
		guid_1[12] == guid_2[12] &&
		guid_1[13] == guid_2[13] &&
		guid_1[14] == guid_2[14] &&
		guid_1[15] == guid_2[15]
	);
}

void check_volume_header()
{
	guid_t volume_guid;

	/* Checking sector size */
	if(volume_header->sector_size == 0)
	{
		printf("The sector size found is null.\n");
        exit(-1);
	}

	/* Check the signature */
	if(memcmp(BITLOCKER_SIGNATURE, volume_header->signature,
	          BITLOCKER_SIGNATURE_SIZE) == 0)
	{
		memcpy(volume_guid, volume_header->guid, sizeof(guid_t));
	}
	else if(memcmp(BITLOCKER_TO_GO_SIGNATURE, volume_header->signature,
	               BITLOCKER_TO_GO_SIGNATURE_SIZE) == 0)
	{
		memcpy(volume_guid, volume_header->bltg_guid, sizeof(guid_t));
	}
	else
	{
		printf( "The signature of the volume (%.8s) doesn't match the "
		        "BitLocker's one. Abort.\n",
		        volume_header->signature
		);
        exit(-1);
	}


	/*
	 * There's no BitLocker GUID in the volume header for volumes encrypted by
	 * Vista
	 */
	if(get_version_from_volume_header() == V_VISTA)
		return;


	/* Check if we're running under EOW mode */

	if(check_match_guid(volume_guid, INFORMATION_OFFSET_GUID))
	{
		//printf("Volume GUID (INFORMATION OFFSET) supported\n");
	}
	else if(check_match_guid(volume_guid, EOW_INFORMATION_OFFSET_GUID))
	{
		printf("EOW volume GUID not supported.\n");
        exit(-1);
	}
	else
	{
		printf("Unknown volume GUID, not supported.\n");
        exit(-1);
	}
}

void get_volume_header(int fd)
{
    if (volume_header || fd < 0)
        exit(-1);

    volume_header = malloc(sizeof(volume_header_t));

    // dis_lseek(fd, offset, SEEK_SET);
    ssize_t nb_read = read(fd, volume_header, sizeof(volume_header_t));

    if (nb_read != sizeof(volume_header_t))
        exit(-1);
}

static int get_metadata(off_t source, void **metadata, int fd)
{
	if(!source || fd < 0 || !metadata)
		return FALSE;

	// Go to the beginning of the BitLocker header
	lseek(fd, source, SEEK_SET);

	bitlocker_information_t information;

	/*
	 * Read and place data into the bitlocker_information_t structure,
	 * this is the metadata's header
	 */
	ssize_t nb_read = read(fd, &information, sizeof(bitlocker_information_t));

	// Check if we read all we wanted
	if(nb_read != sizeof(bitlocker_information_t))
		return FALSE;

	/*
	 * Now that we now the size of the metadata, allocate a buffer and read data
	 * to complete it
	 */
	size_t size = (size_t)(information.version == V_SEVEN ?
	                                  information.size << 4 : information.size);


	if(size <= sizeof(bitlocker_information_t))
		return FALSE;

	size_t rest_size = size - sizeof(bitlocker_information_t);

	*metadata = malloc(size);

	// Copy the header at the begining of the metadata
	memcpy(*metadata, &information, sizeof(bitlocker_information_t));

	// Read the rest, the real data
	nb_read = read(fd, *metadata + sizeof(bitlocker_information_t), rest_size);

	// Check if we read all we wanted
	if((size_t) nb_read != rest_size)
		return FALSE;

	return TRUE;
}

void begin_compute_regions(int fd)
{
	if(memcmp(BITLOCKER_SIGNATURE, volume_header->signature,
	          BITLOCKER_SIGNATURE_SIZE) == 0)
	{
		/* This is when the volume has been encrypted with W$ 7 or 8 */
		if(get_version_from_volume_header() == V_SEVEN)
		{
			virt_region[0].addr = volume_header->information_off[0];
			virt_region[1].addr = volume_header->information_off[1];
			virt_region[2].addr = volume_header->information_off[2];
			return;
		}

		/* And when encrypted with W$ Vista: */

		uint64_t new_offset = volume_header->metadata_lcn * volume_header->sectors_per_cluster * volume_header->sector_size;
		virt_region[0].addr = new_offset;

		/* Now that we have the first offset, go get the others */
		bitlocker_information_t* information = NULL;
		if(!get_metadata(
				(off_t) new_offset,
				(void**) &information, fd
			))
            exit(-1);

		virt_region[1].addr = information->information_off[1];
		virt_region[2].addr = information->information_off[2];

		free(information);
	}
	else if(memcmp(BITLOCKER_TO_GO_SIGNATURE, volume_header->signature,
	               BITLOCKER_TO_GO_SIGNATURE_SIZE) == 0)
	{
		virt_region[0].addr = volume_header->bltg_header[0];
		virt_region[1].addr = volume_header->bltg_header[1];
		virt_region[2].addr = volume_header->bltg_header[2];
	}
	else
	{
		printf("Wtf!? Unknown volume signature not supported.");
        exit(-1);
	}
}

void get_metadata_lazy_checked(int fd, void **metadata)
{
	// Check parameters
	if(fd < 0 || !metadata)
        exit(-1);

	bitlocker_information_t* information = NULL;
	unsigned int  metadata_size = 0;
	unsigned char current = 0;
	unsigned int  metadata_crc32 = 0;
	off_t         validations_offset = 0;
	bitlocker_validations_t validations;

	while(current < 3)
	{
		/* Get the metadata */
		if(!get_metadata((off_t)virt_region[current].addr, metadata, fd))
		{
			printf("Can't get metadata (n°%d)\n", current+1);
            exit(-1);
		}


		/* Check some small things */


		/* Calculate validations offset */
		validations_offset = 0;
		information = *metadata;
		metadata_size = (unsigned int)(information->version == V_SEVEN ?
		            ((unsigned int)information->size) << 4 : information->size);

		validations_offset = (off_t)virt_region[current].addr + metadata_size;

		/* Go to the beginning of the BitLocker validation header */
		lseek(fd, validations_offset, SEEK_SET);

		/* Get the validations metadata */
		memset(&validations, 0, sizeof(bitlocker_validations_t));

		ssize_t nb_read = read(fd, &validations, sizeof(bitlocker_validations_t));
		if(nb_read != sizeof(bitlocker_validations_t))
		{
			printf("Error, can't read all validations data.\n");
            exit(-1);
		}

		/* Check the validity */
		metadata_crc32 = crc32((unsigned char*)*metadata, metadata_size);

		++current;
		if(metadata_crc32 == validations.crc32)
			break;
		else
			free(*metadata);
	}
}

void get_dataset(void* metadata, bitlocker_dataset_t** dataset)
{
	// Check parameters
	if(!metadata)
        exit(-1);

	bitlocker_information_t* information = metadata;
	*dataset = &information->dataset;

	/* Check this dataset validity */
	if(
		(*dataset)->copy_size < (*dataset)->header_size
		|| (*dataset)->size   > (*dataset)->copy_size
		|| (*dataset)->copy_size - (*dataset)->header_size < 8
	)
	{
        exit(-1);
	}
}

void end_compute_regions()
{
	dis_regions_t*           regions       = virt_region;
	bitlocker_information_t* information   = ginformation;

	uint16_t sector_size         = volume_header->sector_size;
	uint8_t  sectors_per_cluster = volume_header->sectors_per_cluster;
	uint32_t cluster_size        = 0;
	uint64_t metafiles_size      = 0;


	/*
	 * Alignment isn't the same for W$ Vista (size-of-a-cluster aligned on
	 * 0x4000) and 7&8 (size-of-a-sector aligned on 0x10000).
	 * This gives the metadata files' sizes in the NTFS layer.
	 */
	if(information->version == V_VISTA)
	{
		cluster_size   = (uint32_t)sector_size * sectors_per_cluster;
		metafiles_size = (uint64_t)(cluster_size+0x3fff) & ~(cluster_size-1);
	}
	else if(information->version == V_SEVEN)
	{
		metafiles_size = (uint64_t)(~(sector_size-1) & (sector_size+0xffff));
	}

	/*
	 * The first 3 regions are for INFORMATION metadata, they have the same size
	 */
	regions[0].size = metafiles_size;
	regions[1].size = metafiles_size;
	regions[2].size = metafiles_size;
	nb_virt_region = 3;


	if(information->version == V_VISTA)
	{
		// Nothing special to do
	}
	else if(information->version == V_SEVEN)
	{
		/*
		 * On BitLocker 7's volumes, there's a virtualized space used to store
		 * firsts NTFS sectors. BitLocker creates a NTFS file to not write on
		 * the area and displays a zeroes-filled file.
		 * A second part, new from Windows 8, follows...
		 */
		datum_virtualization_t* datum = NULL;
		if(!get_next_datum(UINT16_MAX,
		    DATUMS_VALUE_VIRTUALIZATION_INFO, NULL, (void**)&datum))
		{
			printf(
				"Error looking for the VIRTUALIZATION datum type"
				"Internal failure, abort.\n"
			);
            exit(-1);
		}

		nb_virt_region++;
		regions[3].addr = information->boot_sectors_backup;
		regions[3].size = datum->nb_bytes;

		/* Another area to report as filled with zeroes, new to W8 as well */
		if(information->curr_state == METADATA_STATE_SWITCHING_ENCRYPTION)
		{
			nb_virt_region++;
			regions[4].addr = information->encrypted_volume_size;
			regions[4].size = information->convert_size;
		}

		virtualized_size = (off_t)datum->nb_bytes;

		/* Extended info is new to Windows 8 */
		size_t win7_size   = datum_value_types_prop[datum->header.value_type].size_header;
		size_t actual_size = ((size_t)datum->header.datum_size) & 0xffff;
		if(actual_size > win7_size)
		{
			xinfo = &datum->xinfo;
		}
	}
	else
	{
		/* Explicitly mark a BitLocker version as unsupported */
		printf("Unsupported BitLocker version (%hu)\n", information->version);
        exit(-1);
	}
}

int main(int argc, char** argv)
{
    void *metadata = NULL;
    bitlocker_information_t *information = NULL;
    bitlocker_dataset_t *dataset = NULL;
    void *vmk_datum = NULL;
	void *stretch_datum = NULL;
	uint8_t salt[16]      = {0,};
	void *aesccm_datum = NULL;


    if (argc < 2)
        printf("Usage : getvmk IMAGE_PATH\n");

    int fd = open(argv[1], O_RDONLY);

    get_volume_header(fd /*, offset = 0*/);

    check_volume_header();

    begin_compute_regions(fd);

    get_metadata_lazy_checked(fd, &metadata);

    if (!metadata)  exit(-1);

    information = metadata;

    if(information->version > V_SEVEN)  exit(-1);

    ginformation = information;

    get_dataset(metadata, &dataset);

    gdataset = dataset;

    end_compute_regions();

	get_vmk_datum_from_range(0x2000, 0x2000, (void**) &vmk_datum);

    get_nested_datumvaluetype(vmk_datum, DATUMS_VALUE_STRETCH_KEY, &stretch_datum);

    if (!stretch_datum) exit(-1);

	/* The salt is in here, don't forget to keep it somewhere! */
	memcpy(salt, ((datum_stretch_key_t*) stretch_datum)->salt, 16);

    get_nested_datumvaluetype(vmk_datum, DATUMS_VALUE_AES_CCM, &aesccm_datum);

    if (!aesccm_datum)  exit(-1);

    int tmpfd = open("salt.bin", O_RDWR|O_CREAT, S_IRUSR|S_IWUSR);
    write(tmpfd, salt, 16);
    close(tmpfd);
    tmpfd = open("vmk.bin", O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR);
    write(tmpfd, aesccm_datum, ((datum_aes_ccm_t*)aesccm_datum)->header.datum_size);
    close(tmpfd);

    printf("Worked\n");

    close(fd);
    return 0;
}
