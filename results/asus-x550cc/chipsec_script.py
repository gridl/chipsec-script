import chipsec_main
import chipsec_util

run_modules = {}
all_modules = [
#
#General assessment of firmware UEFI security
#
	"common.secureboot.variables",
	"common.uefi.access_uefispec",
	"tools.uefi.blacklist",
	"tools.uefi.whitelist",
	"common.bios_kbrd_buffer",
	"common.uefi.s3bootscript",
	"common.ia32cfg",
	"tools.smm.rogue_mmio_bar",
#
#Evaluating of SPI flash memory security
#
	"common.bios_wp",
	"common.bios_smi",
	"common.spi_desc",
	"common.spi_fdopss",
	"common.spi_lock",
	"common.bios_ts",
#
#Evaluation of SMM security
#
	"common.smm",
	"remap",
	"common.smrr",
	"tools.smm.smm_ptr",
	"smm_dma"
]

OK                  = 0
BIN_EXIT_CODE_LEN   = 6

ok_modules          = []
skipped_modules     = []
warning_modules     = []
deprecated_modules  = []
fail_modules        = []
error_modules       = []
exception_modules   = []
none_modules        = []


"""Run all modules and save logs to files in current directory"""
def run_test_modules(platform_support):
	platform_arg = ""
	if platform_support is "unsupported":
		platform_arg = "--ignore_platform"

	print("\nGENERAL ASSESSMENT OF FIRMWARE SECURITY")

	print("\n--- common.secureboot.variables:")
	run_modules["common.secureboot.variables"] = chipsec_main.main(["--module", "common.secureboot.variables", "--log", "common.secureboot.variables.txt", platform_arg])
	print("[+] Report in file common.secureboot.variables.txt")

	print("\n--- common.uefi.access_uefispec:")
	run_modules["common.uefi.access_uefispec"] = chipsec_main.main(["--module", "common.uefi.access_uefispec", "--log", "common.uefi.access_uefispec.txt", platform_arg])
	print("[+] Report in file common.uefi.access_uefispec.txt")
	
	print("\n--- tools.uefi.blacklist:")	
	run_modules["--- tools.uefi.blacklist"] = chipsec_main.main(["--module", "tools.uefi.blacklist", "--log", "tools.uefi.blacklist.txt", platform_arg])
	print("[+] Report in file tools.uefi.blacklist.txt")

	print("\n--- tools.uefi.whitelist:")
	run_modules["tools.uefi.whitelist"] = chipsec_main.main(["--module", "tools.uefi.whitelist", "--log", "tools.uefi.whitelist.txt", platform_arg])
	print("[+] Report in file tools.uefi.whitelist.txt")

	print("\n--- common.bios_kbrd_buffer:")	
	run_modules["common.bios_kbrd_buffer"] = chipsec_main.main(["--module", "common.bios_kbrd_buffer", "--log", "common.bios_kbrd_buffer.txt", platform_arg])
	print("[+] Report in file common.bios_kbrd_buffer.txt")

	print("\n--- common.uefi.s3bootscript module:")
	run_modules["common.uefi.s3bootscript"] = chipsec_main.main(["--module", "common.uefi.s3bootscript", "--log", "common.uefi.s3bootscript.txt", platform_arg])
	print("[+] Report in file common.uefi.s3bootscript.txt")

	print("\n--- common.ia32cfg module:")	
	if platform_arg is "":
		run_modules["common.ia32cfg"] = chipsec_main.main(["--module", "common.ia32cfg", "--log", "common.ia32cfg.txt", platform_arg])
		print("[+] Report in file common.ia32cfg.txt")
	else:
		print("[*] Ignored in connection with the unsupported platform")

#	print("\n--- tools.smm.rogue_mmio_bar:")	
#	run_modules["tools.smm.rogue_mmio_bar"] = chipsec_main.main(["--module", "tools.smm.rogue_mmio_bar", "--log", "tools.smm.rogue_mmio_bar.txt", platform_arg])
#	print("[+] Report in file tools.smm.rogue_mmio_bar.txt")

	print("\nEVALUATION OF SPI FLASH MEMORY SECURITY")

	print("\n--- common.bios_wp:")	
	run_modules["common.bios_wp"] = chipsec_main.main(["--module", "common.bios_wp", "--log", "common.bios_wp.txt", platform_arg])
	print("[+] Report in file common.bios_wp.txt")

	print("\n--- common.bios_smi:")
	run_modules["common.bios_smi"] = chipsec_main.main(["--module", "common.bios_smi", "--log", "common.bios_smi.txt", platform_arg])
	print("[+] Report in file common.bios_smi.txt")

	print("\n--- common.spi_desc:")		
	run_modules["common.spi_desc"] = chipsec_main.main(["--module", "common.spi_desc", "--log", "common.spi_desc.txt", platform_arg])
	print("[+] Report in file common.spi_desc.txt")

	print("\n--- common.spi_fdopss:")		
	run_modules["common.spi_fdopss"] = chipsec_main.main(["--module", "common.spi_fdopss", "--log", "common.spi_fdopss.txt", platform_arg])
	print("[+] Report in file common.spi_fdopss.txt")

	print("\n--- common.spi_lock:")	
	run_modules["common.spi_lock"] = chipsec_main.main(["--module", "common.spi_lock", "--log", "common.spi_lock.txt", platform_arg])
	print("[+] Report in file common.spi_lock.txt")

	print("\n--- common.bios_ts:")
	run_modules["common.bios_ts"] = chipsec_main.main(["--module", "common.bios_ts", "--log", "common.bios_ts.txt", platform_arg])
	print("[+] Report in file common.bios_ts.txt")

	print("\nEVALUATION OF SMM")

	print("\n--- common.smm:")			
	run_modules["common.smm"] = chipsec_main.main(["--module", "common.smm", "--log", "common.smm.txt", platform_arg])
	print("[+] Report in file common.smm.txt")

	print("\n--- remap:")	
	run_modules["remap"] = chipsec_main.main(["--module", "remap", "--log", "remap.txt", platform_arg])
	print("[+] Report in file remap.txt")

	print("\n--- common.smrr:")			
	run_modules["common.smrr"] = chipsec_main.main(["--module", "common.smrr", "--log", "common.smrr.txt", platform_arg])
	print("[+] Report in file common.smrr.txt")

	print("\n--- tools.smm.smm_ptr:")			
	run_modules["tools.smm.smm_ptr"] = chipsec_main.main(["--module", "tools.smm.smm_ptr", "--log", "tools.smm.smm_ptr.txt", platform_arg])
	print("[+] Report in file tools.smm.smm_ptr.txt")
	
	print("\n--- smm_dma:")	
	run_modules["smm_dma"] = chipsec_main.main(["--module", "smm_dma", "--log", "smm_dma.txt", platform_arg])
	print("[+] Report in file smm_dma.txt")


"""Check platform support"""
def check_platform_support():
	ERROR = "ERROR: Unsupported Platform"
	chipsec_util.main(["--log", "platform.txt", "platform"])
	file = open("platform.txt", "rb")
	platform_info_log = file.read()
	file.close()
	if platform_info_log.find(ERROR) > -1:
		return "unsupported"
	return "supported"


"""Security evaluation"""
def security_evaluation():
	"""
	- Exit code is 0:       all modules ran successfully and passed
	- Exit code is not 0:   each bit means the following:

	    - Bit 0: SKIPPED    at least one module was skipped
	    - Bit 1: WARNING    at least one module had a warning
	    - Bit 2: DEPRECATED at least one module uses deprecated API
	    - Bit 3: FAIL       at least one module failed
	    - Bit 4: ERROR      at least one module wasn't able to run
	    - Bit 5: EXCEPTION  at least one module thrown an unexpected exception
	"""

	"""Parse exit code"""
	for module in all_modules:
		if run_modules.setdefault(module) != None:
			exit_code = bin(run_modules.setdefault(module)).replace("0b", "")
			exit_code_full = (BIN_EXIT_CODE_LEN - len(exit_code)) * "0" + exit_code
			if run_modules.setdefault(module) is OK:
				ok_modules.append(module)
			if exit_code_full[5] is "1":
				skipped_modules.append(module)
			if exit_code_full[4] is "1":
				warning_modules.append(module)
			if exit_code_full[3] is "1":
				deprecated_modules.append(module)
			if exit_code_full[2] is "1":
				fail_modules.append(module)
			if exit_code_full[1] is "1":
				error_modules.append(module)			
			if exit_code_full[0] is "1":
				exception_modules.append(module)
		else:
			none_modules.append(module)
	
	
	print("\nModules that was skipped:")
	if len(skipped_modules) == 0 and len(none_modules) == 0:
		print("[+] the list is empty")
	else:	
		for module in skipped_modules + none_modules:
			print("[*] " + module)

	print("\nModules that uses deprecated API:")
	if len(deprecated_modules) == 0:
		print("[+] the list is empty")
	else:	
		for module in deprecated_modules:
			print("[*] " + module)

	print("\nModules that wasn't able to run:")
	if len(error_modules) == 0:
		print("[+] the list is empty")
	else:
		for module in error_modules:
			print("[*] " + module)

	print("\nModules that thrown an unexpected exception:")
	if len(exception_modules) == 0:
		print("[+] the list is empty")
	else:
		for module in exception_modules:
			print("[*] " + module)

	print("\nYour UEFI firmware is protected from the following vulnerabilities:")
	if len(ok_modules) == 0:
		print("[!] the list is empty")
	else:	
		for module in ok_modules:
			print("[+] " + module)
	
	print("\nYour UEFI firmware is vulnerable to the following exploits:")
	if len(fail_modules) == 0:
		print("[*] The list is empty")
	else:
		for module in fail_modules:
			print("[-] " + module)

	print("\nYour UEFI firmware can be vulnerable to the following exploits:")
	if len(warning_modules) == 0:
		print("[+] The list is empty")
	else:
		for module in warning_modules:
			print("[!] " + module)


def main():
	print("\nPLATFORM SUPPORTING")
	platform_support = "unsupported"
	try:
		platform_support = check_platform_support()
		print("[*] Platform is " + platform_support)
	except Exception as error_message:
		print("[*] Failed to check platform support: " + str(error_message))
		print("[*] Platform is unsupported")
	
	print("\nUEFI SECURITY TESTS")
	run_test_modules(platform_support)
	
	print("\nSECURITY EVALUATION")
	security_evaluation()


if __name__ == "__main__":
	main()
