import sys
import pefile

def main():
	if len(sys.argv) != 2:
		print "Usage: %s <PE file>" % sys.argv[0]
		return 1

	pe = pefile.PE(sys.argv[1])
	
	# list IAT
	for entry in pe.DIRECTORY_ENTRY_IMPORT:
		print entry.dll
		for imp in entry.imports:
			print "\t", hex(imp.address), imp.name

if __name__ == '__main__':
	main()