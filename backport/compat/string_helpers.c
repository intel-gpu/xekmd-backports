// SPDX-License-Identifier: GPL-2.0-only
/*
 * Helpers for formatting and printing strings
 *
 * Copyright 31 August 2008 James Bottomley
 * Copyright (C) 2013, Intel Corporation
 */
#include <linux/string_helpers.h>
#include <linux/slab.h>

#ifdef BPM_PARSE_INT_ARRAY_USER_NOT_PRESENT

/* Works only for digits and letters, but small and fast */
#define TOLOWER(x) ((x) | 0x20)

static unsigned int simple_guess_base(const char *cp)
{
	if (cp[0] == '0') {
		if (TOLOWER(cp[1]) == 'x' && isxdigit(cp[2]))
			return 16;
		else
			return 8;
	} else {
		return 10;
	}
}

/**
 * simple_strtoull - convert a string to an unsigned long long
 * @cp: The start of the string
 * @endp: A pointer to the end of the parsed string will be placed here
 * @base: The number base to use
 */
unsigned long long simple_strtoull(const char *cp, char **endp, unsigned int base)
{
	unsigned long long result = 0;

	if (!base)
		base = simple_guess_base(cp);

	if (base == 16 && cp[0] == '0' && TOLOWER(cp[1]) == 'x')
		cp += 2;

	while (isxdigit(*cp)) {
		unsigned int value;

		value = isdigit(*cp) ? *cp - '0' : TOLOWER(*cp) - 'a' + 10;
		if (value >= base)
			break;
		result = result * base + value;
		cp++;
	}
	if (endp)
		*endp = (char *)cp;

	return result;
}

long simple_strtol(const char *cp, char **endp, unsigned int base)
{
	if (*cp == '-')
		return -simple_strtoull(cp + 1, endp, base);

	return simple_strtoull(cp, endp, base);
}

/*
 *	If a hyphen was found in get_option, this will handle the
 *	range of numbers, M-N.  This will expand the range and insert
 *	the values[M, M+1, ..., N] into the ints array in get_options.
 */

static int get_range(char **str, int *pint, int n)
{
	int x, inc_counter, upper_range;

	(*str)++;
	upper_range = simple_strtol((*str), NULL, 0);
	inc_counter = upper_range - *pint;
	for (x = *pint; n && x < upper_range; x++, n--)
		*pint++ = x;
	return inc_counter;
}

/**
 *	get_option - Parse integer from an option string
 *	@str: option string
 *	@pint: (optional output) integer value parsed from @str
 *
 *	Read an int from an option string; if available accept a subsequent
 *	comma as well.
 *
 *	When @pint is NULL the function can be used as a validator of
 *	the current option in the string.
 *
 *	Return values:
 *	0 - no int in string
 *	1 - int found, no subsequent comma
 *	2 - int found including a subsequent comma
 *	3 - hyphen found to denote a range
 *
 *	Leading hyphen without integer is no integer case, but we consume it
 *	for the sake of simplification.
 */

int get_option(char **str, int *pint)
{
	char *cur = *str;
	int value;

	if (!cur || !(*cur))
		return 0;
	if (*cur == '-')
		value = -simple_strtoull(++cur, str, 0);
	else
		value = simple_strtoull(cur, str, 0);
	if (pint)
		*pint = value;
	if (cur == *str)
		return 0;
	if (**str == ',') {
		(*str)++;
		return 2;
	}
	if (**str == '-')
		return 3;

	return 1;
}

/**
 *	get_options - Parse a string into a list of integers
 *	@str: String to be parsed
 *	@nints: size of integer array
 *	@ints: integer array (must have room for at least one element)
 *
 *	This function parses a string containing a comma-separated
 *	list of integers, a hyphen-separated range of _positive_ integers,
 *	or a combination of both.  The parse halts when the array is
 *	full, or when no more numbers can be retrieved from the
 *	string.
 *
 *	When @nints is 0, the function just validates the given @str and
 *	returns the amount of parseable integers as described below.
 *
 *	Returns:
 *
 *	The first element is filled by the number of collected integers
 *	in the range. The rest is what was parsed from the @str.
 *
 *	Return value is the character in the string which caused
 *	the parse to end (typically a null terminator, if @str is
 *	completely parseable).
 */

char *get_options(const char *str, int nints, int *ints)
{
	bool validate = (nints == 0);
	int res, i = 1;

	while (i < nints || validate) {
		int *pint = validate ? ints : ints + i;

		res = get_option((char **)&str, pint);
		if (res == 0)
			break;
		if (res == 3) {
			int n = validate ? 0 : nints - i;
			int range_nums;

			range_nums = get_range((char **)&str, pint, n);
			if (range_nums < 0)
				break;
			/*
			 * Decrement the result by one to leave out the
			 * last number in the range.  The next iteration
			 * will handle the upper number in the range
			 */
			i += (range_nums - 1);
		}
		i++;
		if (res == 1)
			break;
	}
	ints[0] = i - 1;
	return (char *)str;
}

int parse_int_array(const char *buf, size_t count, int **array)
{
	int *ints, nints;

	get_options(buf, 0, &nints);
	if (!nints)
		return -ENOENT;

	ints = kzalloc_objs(*ints, nints + 1);
	if (!ints)
		return -ENOMEM;

	get_options(buf, nints + 1, ints);
	*array = ints;

	return 0;
}

/**
 * parse_int_array_user - Split string into a sequence of integers
 * @from:	The user space buffer to read from
 * @count:	The maximum number of bytes to read
 * @array:	Returned pointer to sequence of integers
 *
 * On success @array is allocated and initialized with a sequence of
 * integers extracted from the @from plus an additional element that
 * begins the sequence and specifies the integers count.
 *
 * Caller takes responsibility for freeing @array when it is no longer
 * needed.
 */
int parse_int_array_user(const char __user *from, size_t count, int **array)
{
	char *buf;
	int ret;

	buf = memdup_user_nul(from, count);
	if (IS_ERR(buf))
		return PTR_ERR(buf);

	ret = parse_int_array(buf, count, array);
	kfree(buf);
	return ret;
}
EXPORT_SYMBOL(parse_int_array_user);

#endif /* BPM_PARSE_INT_ARRAY_USER_NOT_PRESENT */
