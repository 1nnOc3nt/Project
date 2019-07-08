from __future__ import print_function
import sys
import struct

#Import pefile
try:
	import pefile
except:
	sys.exit('[!]Cannot find pefile!\npip install pefile')

#Import Unicorn Engine
try:
	from unicorn import *
	from unicorn.x86_const import *
except:
	sys.exit('[!]Cannot find unicorn!\npip install unicorn')

#Import Capstone Engine
try:
	from capstone import *
except:
	sys.exit('[!]Cannot find capstone!\npip install capstone')

#Initialize Machine Value
IMAGE_FILE_MACHINE_I386 = 0x014c
IMAGE_FILE_MACHINE_IA64 = 0x8664

#Initialize for IAT
HOOK_BASE = 0xff00000
EACH_DLL_PAGE_SIZE = 0x1000
HOOK_BASE_MAX = HOOK_BASE + HOOK_BASE * (0x100)

#IAT dict
win_dict = {}
iat_dict = {}

class analyzer(object):
	@staticmethod
	def hook_code(uc, addr, size, self):
		CODE = uc.mem_read(addr, size)
		if (self.is_x86_machine):
			md = Cs(CS_ARCH_X86, CS_MODE_32)
		else:
			md = Cs(CS_ARCH_X86, CS_MODE_64)
		for i in md.disasm(bytes(CODE), addr):
			if (i.mnemonic == 'ret'):
				print('\n')
			elif (i.mnemonic == 'call'):
				check = False
				for key, value in iat_dict.items():
					if (i.op_str.find(hex(key)) != -1):
						print('0x%x:\t%s %s' % (i.address, i.mnemonic, value))
						check = True
						break
				if check == False:
					print('0x%x:\t%s %s' % (i.address, i.mnemonic, i.op_str))

				#Print arguments
				sp = uc.reg_read(UC_X86_REG_ESP)
				print('\n------------------------Arguments------------------------\n')
				for i in range(4):
					tmp = sp + (i+1)*4
					argv = ''
					args = struct.unpack('<IIIIII', uc.mem_read(sp, 24))
					if ((args[i] > self.stack_base) and (args[i] < self.image_base + self.size_of_image)):
						s = uc.mem_read(args[i], 30)
						for c in s:
							if (c >= 32 and c <= 126):
								argv += chr(c)
							else:
								break
					print('Arg[%d](0x%x) -> (0x%x) = %s' % (i, tmp, args[i], argv))
				print('\n---------------------------------------------------------\n')
			else:
				print('0x%x:\t%s %s' % (i.address, i.mnemonic, i.op_str))


	def __init__(self, file_path):
		try:
			self.pe_data = open(file_path, 'rb').read()
		except:
			sys.exit('[!]Cannot open file!')

		try:
			self.pe = pefile.PE(data = self.pe_data)
		except:
			sys.exit('[!]Invalid file type!')

		#Detect architecture
		if (self.pe.FILE_HEADER.Machine == IMAGE_FILE_MACHINE_I386):
			self.is_x86_machine = True
			self.stack_base = 0x00300000
			self.stack_size = 0x00100000
			print('[*]Detect x86 machine type!')
		elif (self.pe.FILE_HEADER.Machine == IMAGE_FILE_MACHINE_IA64):
			self.is_x86_machine = False
			self.stack_base = 0x130000000
			self.stack_size = 0x010000000
			print('[*]Detect x86_64 machine type!')
		else:
			sys.exit('[!]Unknown machine type!')

		#Basic PE info
		self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
		self.addr_entry = self.image_base + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
		self.size_of_image = self.pe.OPTIONAL_HEADER.SizeOfImage

		print('[*]Ready!')

	def run(self):
		#Initialize Unicorn Engine
		if (self.is_x86_machine):
			self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
		else:
			self.uc = Uc(UC_ARCH_X86, UC_MODE_64)

		#Mapping Image into Memory
		self.uc.mem_map(self.image_base, self.size_of_image)
		mapped_image = self.pe.get_memory_mapped_image(ImageBase=self.image_base)
		self.uc.mem_write(self.image_base, mapped_image)
		print('[*]Mapping Image Finished!')

		#Import Address Table
		print('[*]Listing IAT:')
		for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
			curr_dll_dict = {}
			curr_dll_dict['apiDict'] = {}
			curr_dll_dict['dllName'] = entry.dll
			curr_dll_dict['dllBase'] = HOOK_BASE + len(win_dict) * EACH_DLL_PAGE_SIZE
			curr_dll_dict['dllLimt'] = curr_dll_dict['dllBase'] + EACH_DLL_PAGE_SIZE - 1

			self.uc.mem_map(curr_dll_dict['dllBase'], EACH_DLL_PAGE_SIZE)
			self.uc.mem_write(curr_dll_dict['dllBase'], b'\xC3' * EACH_DLL_PAGE_SIZE) # ret
			print('\t[+]%x - %s' % (curr_dll_dict['dllBase'], curr_dll_dict['dllName']))
			for imp in entry.imports:
				iat_dict[imp.address] = imp.name

				curr_api_name = imp.name
				curr_api_addr = curr_dll_dict['dllBase'] + len(curr_dll_dict['apiDict'])
				self.uc.mem_write(imp.address, struct.pack('<I', curr_api_addr))
				curr_dll_dict['apiDict'][curr_api_addr] = curr_api_name
				print('\t\t[0x%x] -> %s @ %x' % (imp.address, curr_api_name, curr_api_addr))
			win_dict[curr_dll_dict['dllName']] = curr_dll_dict

		#Initialize Stack
		if (self.is_x86_machine):
			self.uc.mem_map(0, 1024 * 1024 * 4) 
			self.uc.reg_write(UC_X86_REG_ESP, self.stack_base + self.stack_size - 4)
			print('\n[*]Allocate stack @ %x' % (self.stack_base + self.stack_size - 4))
		else:
			self.uc.mem_map(0, 1024 * 1024 * 8)
			self.uc.reg_write(UC_X86_REG_RSP, self.stack_base + self.stack_size - 8)
			print('\n[*]Allocate stack @ %x' % (self.stack_base + self.stack_size - 8))

		#Hook code
		self.uc.hook_add(UC_HOOK_CODE, self.hook_code, self)

		#Execute at entry point
		try:
			print('[*]Emulator is executing file ...\n')
			self.uc.emu_start(self.addr_entry, 0)
		except UcError as e:
			sys.exit('[*]Error: %s' % e)
		self.uc.mem_unmap(self.image_base, self.size_of_image)
		sys.exit('[*]Emulating done!')

if __name__ == "__main__":
	if (len(sys.argv) == 2):
		analyzer(sys.argv[1]).run()
	else:
		sys.exit('[!]Usage: python analyzer.py <Path to file>')
