/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of Encryption for the Masses 2.02a, which is
 Copyright (c) 1998-2000 Paul Le Roux and which is governed by the 'License
 Agreement for Encryption for the Masses'. Modifications and additions to
 the original source code (contained in this file) and all other portions
 of this file are Copyright (c) 2003-2010 TrueCrypt Developers Association
 and are governed by the TrueCrypt License 3.0 the full text of which is
 contained in the file License.txt included in TrueCrypt binary and source
 code distribution packages. */

#ifndef GST_HEADER_Common_Volumes
#define GST_HEADER_Common_Volumes

#ifdef __cplusplus
extern "C" {
#endif

// Volume header version
#define VOLUME_HEADER_VERSION					0x1300 

// Version number written to volume header during format;
// specifies the minimum program version required to mount the volume
#define GST_VOLUME_MIN_REQUIRED_PROGRAM_VERSION	0x1300

// Version number written (encrypted) to the key data area of an encrypted system partition/drive;
// specifies the minimum program version required to decrypt the system partition/drive
#define GST_SYSENC_KEYSCOPE_MIN_REQ_PROG_VERSION	0x1300

// Current volume format version (created by GostCrypt 6.0+)
#define GST_VOLUME_FORMAT_VERSION				13

// Version number of volume format created by GostCrypt 1.0-5.1a
#define GST_VOLUME_FORMAT_VERSION_PRE_6_0		1

// Volume header sizes
#define GST_VOLUME_HEADER_SIZE					(64 * 1024L)
#define GST_VOLUME_HEADER_EFFECTIVE_SIZE			512
#define GST_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE	512
#define GST_VOLUME_HEADER_SIZE_LEGACY			512

#define GST_VOLUME_HEADER_GROUP_SIZE				(2 * GST_VOLUME_HEADER_SIZE)
#define GST_TOTAL_VOLUME_HEADERS_SIZE			(4 * GST_VOLUME_HEADER_SIZE)

// Volume offsets
#define GST_VOLUME_HEADER_OFFSET					0
#define GST_HIDDEN_VOLUME_HEADER_OFFSET			GST_VOLUME_HEADER_SIZE

// Sector sizes
#define GST_MIN_VOLUME_SECTOR_SIZE				512
#define GST_MAX_VOLUME_SECTOR_SIZE				4096
#define GST_SECTOR_SIZE_FILE_HOSTED_VOLUME		512
#define GST_SECTOR_SIZE_LEGACY					512

// Sector size which can be safely assumed to be supported by all BIOSes
#define GST_SECTOR_SIZE_BIOS						512

#define GST_VOLUME_SMALL_SIZE_THRESHOLD			(2 * BYTES_PER_MB)		// Volume sizes below this threshold are considered small

#define GST_HIDDEN_VOLUME_HOST_FS_RESERVED_END_AREA_SIZE			GST_MAX_VOLUME_SECTOR_SIZE	// FAT file system fills the last sector with zeroes (marked as free; observed when quick format was performed using the OS format tool).
#define	GST_HIDDEN_VOLUME_HOST_FS_RESERVED_END_AREA_SIZE_HIGH	GST_VOLUME_HEADER_GROUP_SIZE	// Reserved area size used for hidden volumes larger than GST_VOLUME_SMALL_SIZE_THRESHOLD

#define GST_VOLUME_DATA_OFFSET					GST_VOLUME_HEADER_GROUP_SIZE

// The offset, in bytes, of the legacy hidden volume header position from the end of the file (a positive value).
#define GST_HIDDEN_VOLUME_HEADER_OFFSET_LEGACY	(GST_VOLUME_HEADER_SIZE_LEGACY + GST_SECTOR_SIZE_LEGACY * 2)

#define GST_MAX_128BIT_BLOCK_VOLUME_SIZE	BYTES_PER_PB			// Security bound (128-bit block XTS mode)

// Filesystem size limits
#define GST_MIN_FAT_FS_SIZE				(9 * GST_MAX_VOLUME_SECTOR_SIZE)
#define GST_MAX_FAT_SECTOR_COUNT			0x100000000ULL
#define GST_MIN_NTFS_FS_SIZE				(884 * GST_MAX_VOLUME_SECTOR_SIZE)
#define GST_MAX_NTFS_FS_SIZE				(128LL * BYTES_PER_TB)	// NTFS volume can theoretically be up to 16 exabytes, but Windows XP and 2003 limit the size to that addressable with 32-bit clusters, i.e. max size is 128 TB (if 64-KB clusters are used).
#define GST_MAX_FAT_CLUSTER_SIZE			(256 * BYTES_PER_KB)	// Windows XP/Vista may crash when writing to a filesystem using clusters larger than 256 KB

// Volume size limits
#define GST_MIN_VOLUME_SIZE				(GST_TOTAL_VOLUME_HEADERS_SIZE + GST_MIN_FAT_FS_SIZE)
#define GST_MIN_VOLUME_SIZE_LEGACY		(37 * GST_SECTOR_SIZE_LEGACY)
#define GST_MAX_VOLUME_SIZE_GENERAL		0x7fffFFFFffffFFFFLL	// Signed 64-bit integer file offset values
#define GST_MAX_VOLUME_SIZE				GST_MAX_128BIT_BLOCK_VOLUME_SIZE

#define GST_MIN_HIDDEN_VOLUME_SIZE		(GST_MIN_FAT_FS_SIZE + GST_HIDDEN_VOLUME_HOST_FS_RESERVED_END_AREA_SIZE)

#define GST_MIN_HIDDEN_VOLUME_HOST_SIZE	(GST_MIN_VOLUME_SIZE + GST_MIN_HIDDEN_VOLUME_SIZE + 2 * GST_MAX_VOLUME_SECTOR_SIZE)
#define GST_MAX_HIDDEN_VOLUME_HOST_SIZE	(GST_MAX_NTFS_FS_SIZE - GST_TOTAL_VOLUME_HEADERS_SIZE)

#ifndef GST_NO_COMPILER_INT64
#	if GST_MAX_VOLUME_SIZE > GST_MAX_VOLUME_SIZE_GENERAL
#		error GST_MAX_VOLUME_SIZE > GST_MAX_VOLUME_SIZE_GENERAL
#	endif
#endif

#define HEADER_ENCRYPTED_DATA_SIZE			(GST_VOLUME_HEADER_EFFECTIVE_SIZE - HEADER_ENCRYPTED_DATA_OFFSET)

// Volume header field offsets
#define	HEADER_SALT_OFFSET					0
#define HEADER_ENCRYPTED_DATA_OFFSET		PKCS5_SALT_SIZE
#define	HEADER_MASTER_KEYDATA_OFFSET		256
	
#define GST_HEADER_OFFSET_MAGIC					64
#define GST_HEADER_OFFSET_VERSION				68
#define GST_HEADER_OFFSET_REQUIRED_VERSION		70
#define GST_HEADER_OFFSET_KEY_AREA_CRC			72
#define GST_HEADER_OFFSET_VOLUME_CREATION_TIME	76
#define GST_HEADER_OFFSET_MODIFICATION_TIME		84
#define GST_HEADER_OFFSET_HIDDEN_VOLUME_SIZE		92
#define GST_HEADER_OFFSET_VOLUME_SIZE			100
#define GST_HEADER_OFFSET_ENCRYPTED_AREA_START	108
#define GST_HEADER_OFFSET_ENCRYPTED_AREA_LENGTH	116
#define GST_HEADER_OFFSET_FLAGS					124
#define GST_HEADER_OFFSET_SECTOR_SIZE			128
#define GST_HEADER_OFFSET_HEADER_CRC				252

// Volume header flags
#define GST_HEADER_FLAG_ENCRYPTED_SYSTEM			0x1
#define GST_HEADER_FLAG_NONSYS_INPLACE_ENC		0x2		// The volume has been created using non-system in-place encryption


#ifndef GST_HEADER_Volume_VolumeHeader

#include "Password.h"

extern BOOL ReadVolumeHeaderRecoveryMode;

uint16 GetHeaderField16 (byte *header, int offset);
uint32 GetHeaderField32 (byte *header, int offset);
UINT64_STRUCT GetHeaderField64 (byte *header, int offset);
int ReadVolumeHeader (BOOL bBoot, char *encryptedHeader, Password *password, PCRYPTO_INFO *retInfo, CRYPTO_INFO *retHeaderCryptoInfo);
#if !defined (DEVICE_DRIVER) && !defined (GST_WINDOWS_BOOT)
int CreateVolumeHeaderInMemory (BOOL bBoot, char *encryptedHeader, int ea, int mode, Password *password, int pkcs5_prf, char *masterKeydata, PCRYPTO_INFO *retInfo, unsigned __int64 volumeSize, unsigned __int64 hiddenVolumeSize, unsigned __int64 encryptedAreaStart, unsigned __int64 encryptedAreaLength, uint16 requiredProgramVersion, uint32 headerFlags, uint32 sectorSize, BOOL bWipeMode);
BOOL ReadEffectiveVolumeHeader (BOOL device, HANDLE fileHandle, byte *header, DWORD *bytesRead);
BOOL WriteEffectiveVolumeHeader (BOOL device, HANDLE fileHandle, byte *header);
int WriteRandomDataToReservedHeaderAreas (HANDLE dev, CRYPTO_INFO *cryptoInfo, uint64 dataAreaSize, BOOL bPrimaryOnly, BOOL bBackupOnly);
#endif

#endif // !GST_HEADER_Volume_VolumeHeader

#ifdef __cplusplus
}
#endif

#endif // GST_HEADER_Common_Volumes
