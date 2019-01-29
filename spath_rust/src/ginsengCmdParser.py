#!/usr/bin/env python
import os,sys,filecmp

tempFile = '__temp.rs'

def checkFile(filename):
	if not os.path.exists(filename):
		print('{:s} does not exist!'.format(filename))
		sys.exit(-1);

def convert(fd, line):
	newline = 'pub const {:s}: u64 = {:s};\n'.format(line[1], ' '.join(line[2:]));
	fd.write(newline);

def usage(prog):
	print('{:s} inputfile outputfile'.format(prog))
	sys.exit(-1)

def main():
	if len(sys.argv) != 3:
		usage(sys.argv[0])

	inputfile = sys.argv[1]
	outputfile = sys.argv[2]

	bInside = False

	checkFile(inputfile);
	with open(inputfile, 'r') as fd, open(tempFile, 'w') as fdOut:
		fdOut.write('/*\n')
		fdOut.write(' * Don\'t modify this.\n')
		fdOut.write(' * AUTOGEN FILE from ' + inputfile + '\n')
		fdOut.write(' */\n\n')
		while True:
			line = fd.readline()
			if not line: break
			line = line.strip()

			if line == '// MAGIC_START':
				bInside = True
				continue
			if line == '// MAGIC_END': break

			if bInside:
				line = line.split()
				if len(line) < 3: continue
				if line[-1][-2:] == 'UL': line[-1] = line[-1][:-2]	# this is ugly, but leave it for now...
				convert(fdOut, line)

	if os.path.exists(outputfile) and filecmp.cmp(tempFile, outputfile): 
		os.remove(tempFile)
	else: os.rename(tempFile, outputfile)

if __name__ == "__main__":
	main()