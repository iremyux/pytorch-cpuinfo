#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <cpuinfo.h>
#include <cpuinfo/internal-api.h>
#include <cpuinfo/log.h>

#include "windows-arm-init.h"

struct cpuinfo_arm_isa cpuinfo_isa;
struct woa_chip_info* cpuinfo;

static void set_cpuinfo_isa_fields(void);

static struct woa_chip_info* get_system_info_from_registry(void);

static struct woa_chip_info woa_chip_unknown = {
	L"Unknown",
	{cpuinfo_vendor_unknown, cpuinfo_uarch_unknown, 0}
};

BOOL CALLBACK cpuinfo_arm_windows_init(PINIT_ONCE init_once, PVOID parameter, PVOID* context) {
	struct woa_chip_info* chip_info = NULL;
	enum cpuinfo_vendor vendor = cpuinfo_vendor_unknown;

	cpuinfo_log_error("irem - 1");

	set_cpuinfo_isa_fields();

	chip_info = get_system_info_from_registry();
	if (chip_info->chip_name_string == NULL) {
		chip_info = &woa_chip_unknown;
	}	

	cpuinfo_is_initialized = cpu_info_init_by_logical_sys_info(chip_info, chip_info->uarch.vendor);

	return true;
}

bool get_core_uarch_for_efficiency(
	struct woa_chip_info* cpuinfo,
	BYTE EfficiencyClass,
	enum cpuinfo_uarch* uarch,
	uint64_t* frequency) {
	/* For currently supported WoA chips, the Efficiency class selects
	 * the pre-defined little and big core.
	 * Any further supported SoC's logic should be implemented here.
	 */
	if (uarch && frequency && EfficiencyClass < MAX_WOA_VALID_EFFICIENCY_CLASSES) {
		*uarch = cpuinfo->uarch.uarch;
		*frequency = cpuinfo->uarch.frequency;
		return true;
	}
	return false;
}

/* Static helper functions */

static wchar_t* read_registry(LPCWSTR subkey, LPCWSTR value) {
	DWORD key_type = 0;
	DWORD data_size = 0;
	const DWORD flags = RRF_RT_REG_SZ; /* Only read strings (REG_SZ) */
	wchar_t* text_buffer = NULL;
	LSTATUS result = 0;
	HANDLE heap = GetProcessHeap();

	result = RegGetValueW(
		HKEY_LOCAL_MACHINE,
		subkey,
		value,
		flags,
		&key_type,
		NULL, /* Request buffer size */
		&data_size);
	if (result != 0 || data_size == 0) {
        cpuinfo_log_error("Registry entry size read error: %ld", result);
		return NULL;
	}

	text_buffer = HeapAlloc(heap, HEAP_ZERO_MEMORY, data_size);
	if (text_buffer == NULL) {
		cpuinfo_log_error("Registry textbuffer allocation error");
		return NULL;
	}

	result = RegGetValueW(
		HKEY_LOCAL_MACHINE,
		subkey,
		value,
		flags,
		NULL,
		text_buffer, /* Write string in this destination buffer */
		&data_size);
	if (result != 0) {
		cpuinfo_log_error("Registry read error");
		HeapFree(heap, 0, text_buffer);
		return NULL;
	}
	return text_buffer;
}

static struct woa_chip_info* get_system_info_from_registry(void) {
	cpuinfo_log_error("irem - 2");
	wchar_t* text_buffer = NULL;
	LPCWSTR cpu0_subkey = L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0";
	LPCWSTR chip_name_value = L"ProcessorNameString";
	LPCWSTR processor_part_value = L"ProcessorPart";
	LPCWSTR frequency_value = L"~MHz";
	HANDLE heap = GetProcessHeap();

	/* Read processor model name from registry  */
	text_buffer = read_registry(cpu0_subkey, chip_name_value);
	if (text_buffer == NULL) {
		cpuinfo_log_error("Registry read error");
		return NULL;
	}

	cpuinfo_log_error("detected chip model name: %ls", text_buffer);

	/* Read processor model processor part from registry  */
	text_buffer = read_registry(cpu0_subkey, frequency_value);
	if (text_buffer == NULL) {
		cpuinfo_log_error("Registry read error");
		return NULL;
	}

	cpuinfo_log_error("detected processor part: %ls", text_buffer);
	
	/* Read processor model frequency from registry  */
	text_buffer = read_registry(cpu0_subkey, processor_part_value);
	if (text_buffer == NULL) {
		cpuinfo_log_error("Registry read error");
		return NULL;
	}

	cpuinfo_log_error("detected frequency: %ls", text_buffer);

	/* Allocate memory for cpuinfo */
	cpuinfo = (struct woa_chip_info*)malloc(sizeof(struct woa_chip_info));
	if (cpuinfo == NULL) {
		cpuinfo_log_error("Memory allocation failed for cpuinfo");
		return NULL;
	}

	/* Initialize CPU info with logical system information */
	cpuinfo->chip_name_string = text_buffer;
	struct core_info_by_chip_name uarch = {cpuinfo_vendor_arm, cpuinfo_uarch_unknown, wcstoull(frequency_value, NULL, 10) * 1000000};
	cpuinfo->uarch = uarch;

	cpuinfo_log_debug("IREMMMMMM cpuinfo: %s", cpuinfo->chip_name_string);
	cpuinfo_log_debug("IREMMMMMM cpuinfo uarch: %d", cpuinfo->uarch.uarch);
	cpuinfo_log_debug("IREMMMMMM cpuinfo freq: %d", cpuinfo->uarch.frequency);
	cpuinfo_log_debug("IREMMMMMM cpuinfo vendor: %d", cpuinfo->uarch.vendor);

	HeapFree(heap, 0, text_buffer);
	return &cpuinfo;
}

static void set_cpuinfo_isa_fields(void) {
	cpuinfo_isa.atomics = IsProcessorFeaturePresent(PF_ARM_V81_ATOMIC_INSTRUCTIONS_AVAILABLE) != 0;

	const bool dotprod = IsProcessorFeaturePresent(PF_ARM_V82_DP_INSTRUCTIONS_AVAILABLE) != 0;
	cpuinfo_isa.dot = dotprod;

	SYSTEM_INFO system_info;
	GetSystemInfo(&system_info);
	switch (system_info.wProcessorLevel) {
		case 0x803: // Kryo 385 Silver (Snapdragon 850)
			cpuinfo_isa.fp16arith = dotprod;
			cpuinfo_isa.rdm = dotprod;
			break;
		default:
			// Assume that Dot Product support implies FP16
			// arithmetics and RDM support. ARM manuals don't
			// guarantee that, but it holds in practice.
			cpuinfo_isa.fp16arith = dotprod;
			cpuinfo_isa.rdm = dotprod;
			break;
	}

	/* Windows API reports all or nothing for cryptographic instructions. */
	const bool crypto = IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE) != 0;
	cpuinfo_isa.aes = crypto;
	cpuinfo_isa.sha1 = crypto;
	cpuinfo_isa.sha2 = crypto;
	cpuinfo_isa.pmull = crypto;

	cpuinfo_isa.crc32 = IsProcessorFeaturePresent(PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE) != 0;
}
