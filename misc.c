#include <stdio.h>
#include <ctype.h>
#include <inttypes.h>
#include "misc.h"

static int binary_scanf(const char *buf, uint64_t *val)
{
	uint64_t value = 0;

	/* Skip the leading b */
	buf++;

	while (*buf) {
		switch (*buf) {

		case '0':
			value <<= 1;
			break;
		case '1':
			value <<= 1;
			value++;
			break;
		default:
			return 0;
		}
		buf++;
	}

	*val = value;

	return 1;
}

static int base_scanf(const char *buf, int base, uint64_t *value)
{
	int ret = 0;

	switch (base) {
	case 10:
		ret = sscanf(buf, "%" PRIu64, value);
		break;
	case 16:
		ret = sscanf(buf, "%" PRIX64, value);
		break;
	case 8:
		ret = sscanf(buf, "%" PRIo64, value);
		break;
	case 2:
		ret = binary_scanf(buf, value);
		break;
	default:
		fprintf(stderr, "Unknown base\n");
		break;
	}

	if (ret == EOF || !ret) {
		return 1;
	}

	return 0;
}

int parse_input(const char *input, uint64_t *val)
{
	int base;

	if (tolower(input[0]) == 'b')
		base = 2;
	else if (input[0] == '0')
		if (input[1] == 'x' || input[1] == 'X')
			base = 16;
		else
			base = 8;
	else
		base = 10;

	return base_scanf(input, base, val);
}

