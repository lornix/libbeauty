
#define __STDC_LIMIT_MACROS
#define __STDC_CONSTANT_MACROS

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/Support/TargetSelect.h"

#define MAX_INPUT_LEN 128
#define MAX_TEST_DATA 16

using namespace llvm;

struct dis_info_s {
	MCInst *Inst;
	int offset[16];
	int size[16];
};

struct dis_info_s *LLVMCreateDisInfo(void) {
	int n;
	MCInst *inst = new MCInst;
	struct dis_info_s *dis_info = (struct dis_info_s*) calloc (1, sizeof (struct dis_info_s));
	dis_info->Inst = inst;
	dis_info->Inst->clear();
	for (n = 0; n < 16; n++) {
		dis_info->offset[n] = 0;
		dis_info->size[n] = 0;
	}
	return dis_info;
}

int LLVMDecodeOpInfoCallback(void *DisInfo, uint64_t PC,
                                  uint64_t Offset, uint64_t Size,
                                  int TagType, void *TagBuf) {
	struct dis_info_s *dis_info = (struct dis_info_s *) DisInfo;
	MCInst *Inst = dis_info->Inst;
	int num_operands = Inst->getNumOperands();
	if (num_operands >= 16) {
		outs() << "num_operands >= 16\n";
		exit(1);
	}
	dis_info->offset[num_operands] = Offset;
	dis_info->size[num_operands] = Size;
	outs() << format("NumOperands = 0x%x, ", num_operands) << format("Offset = 0x%x, ", Offset) << format("Size = 0x%x", Size) << "\n";
	return 0;
}

/* getHexToken()
   Get next valid hexadecimal token from str starting at pos
   str is a string of hex tokens separated by 'delimiter'
   *pos is updated to  the position of start of the next valid token before return
*/

uint8_t getHexToken(const char* str, char delimiter, int* pos)
{
	uint8_t hex = 0;
	int start = 0;
	const char* ptr = str + *pos;

	while (*ptr && *ptr != delimiter) {
		if (*ptr == 'x' || *ptr == 'X') {
			start = 1; }
		else if (!start && *ptr == '0') {
		}
		else if (!start) {
			return 0; //TODO: add case for decimal value if needed
		}
		else {
			if (*ptr >= '0' && *ptr <= '9')
				hex = (hex << 4) | (*ptr - '0');
			else if (*ptr >= 'A' && *ptr <= 'F')
				hex = (hex << 4) | (*ptr - 'A' + 0xA);
			else if (*ptr >= 'a' && *ptr <= 'f')
				hex = (hex << 4) | (*ptr - 'a' + 0xa);
			else if (*ptr == 'x' || *ptr == 'X');
			else {
				outs() << "Invalid character!\n";
				exit(0);
			}
		}

		++*pos;
		ptr++;
	}

	if (!*ptr)
		*pos = -1;
	else
		++*pos;

	return hex;
}

/* analyzeLine()
   Get a trimmed version of src in dst without consecutive spaces, tabs and '#'
   Return the number of valid characters in dst without the NULL terminator
*/

int analyzeLine(const char* src, char* dst)
{
	const char* ptr = src;
	int validchar = 0;
	int tokens = 0;
	char lastchar = '\0';

	while (*ptr) {
		if (*ptr == '#' || *ptr == '\n') {
			if (validchar && dst[validchar - 1] == ' ')
				validchar--;
			break;
		}

		if (validchar == 0) {
			if (*ptr == ' ' || *ptr == EOF || *ptr == '\t') {
				ptr++;
				continue;
			}
		}

		if ((*ptr == ' ' || *ptr == '\t') && (lastchar == ' ' || lastchar == '\t')) {
			ptr++;
			continue;
		}

		if (lastchar == '\0' || lastchar == ' ' || lastchar == '\t')
			tokens++;

		if (*ptr == '\t')
			dst[validchar++] = ' ';
		else
			dst[validchar++] = *ptr;

		lastchar = *ptr;
		ptr++;
	}

	dst[validchar] = '\0';

	outs() << "validchar:" << validchar << "   tokens:" << tokens << "\n";

	return tokens;
}

int main(int argc, char *argv[])
{
	int octets = 0;
	int offset = 0;
	LLVMDisasmContextRef DC;
	uint8_t buffer1[1024];
	uint8_t *buffer;
	size_t buffer_size = 0;
	char buf[MAX_INPUT_LEN] = {0};
	char* line = NULL;
	size_t bufsize;
	ssize_t len = 0;
	int pos = 0, i = 0;
	int test_data_size = 0;
	uint8_t test_data[MAX_TEST_DATA] = {0};

	FILE* fin = NULL;
	if (argv[1]) {
		if ((fin = fopen(argv[1], "r")) < 0) {
			outs() << "usage: test_case filename\n" << argv[1];
			exit(0);
		}
	}

	while ((len = getline(&line, &bufsize, fin)) != -1) {
		pos = 0;
		test_data_size = analyzeLine(line, buf);

		if (test_data_size == 0)
			continue;

		while (pos != -1) {
			test_data[i] = getHexToken(buf, ' ', &pos);
			outs() << "Test Data " << i << " [" << test_data[i] << "]\n";
			i++;
		}

		LLVMInitializeAllTargetInfos();
		LLVMInitializeAllTargetMCs();
		LLVMInitializeAllAsmParsers();
		LLVMInitializeAllDisassemblers();

		struct dis_info_s *dis_info = LLVMCreateDisInfo();
		DC = LLVMCreateDisasm("x86_64-pc-linux-gnu", dis_info,
			0, &LLVMDecodeOpInfoCallback,
			NULL);
		if (!DC) {
			outs() << "LLVMCreateDisasm() failed\n";
			exit(1);
		}

		buffer_size = test_data_size;
		buffer = &(test_data[0]);
		octets = LLVMDisasmInstruction(DC, buffer,
			buffer_size, offset,
			(char *)buffer1, 1023);
	}

	return 0;
}
