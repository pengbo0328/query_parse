/*-------------------------------------------------------------------------
 *
 * keywords.c
 *	  lexical token lookup for key words in PostgreSQL
 *
 *
 * Portions Copyright (c) 2003-2018, PgPool Global Development Group
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/parser/keywords.c
 *
 *-------------------------------------------------------------------------
 */

#include <string.h>
#include "parsenodes.h"
#ifndef FRONTEND

#include "gramparse.h"			/* required before parser/parse.h! */

#define PG_KEYWORD(a,b,c) {a,b,c},

#else

#include "keywords.h"

/*
 * We don't need the token number for frontend uses, so leave it out to avoid
 * requiring backend headers that won't compile cleanly here.
 */
#define PG_KEYWORD(a,b,c) {a,0,c},

#endif							/* FRONTEND */

#include "gram.h"

const ScanKeyword ScanKeywords[] = {
#include "kwlist.h"
};

const int	NumScanKeywords = lengthof(ScanKeywords);

/*
 * ScanKeywordLookup - see if a given word is a keyword
 *
 * Returns a pointer to the ScanKeyword table entry, or NULL if no match.
 *
 * The match is done case-insensitively.  Note that we deliberately use a
 * dumbed-down case conversion that will only translate 'A'-'Z' into 'a'-'z',
 * even if we are in a locale where tolower() would produce more or different
 * translations.  This is to conform to the SQL99 spec, which says that
 * keywords are to be matched in this way even though non-keyword identifiers
 * receive a different case-normalization mapping.
 */
const ScanKeyword *
ScanKeywordLookup(const char *text,
				  const ScanKeyword *keywords,
				  int num_keywords)
{
	int			len,
				i;
	char		word[NAMEDATALEN];
	const ScanKeyword *low;
	const ScanKeyword *high;

	len = strlen(text);
	/* We assume all keywords are shorter than NAMEDATALEN. */
	if (len >= NAMEDATALEN)
		return NULL;

	/*
	 * Apply an ASCII-only downcasing.  We must not use tolower() since it may
	 * produce the wrong translation in some locales (eg, Turkish).
	 */
	for (i = 0; i < len; i++)
	{
		char		ch = text[i];

		if (ch >= 'A' && ch <= 'Z')
			ch += 'a' - 'A';
		word[i] = ch;
	}
	word[len] = '\0';

	/*
	 * Now do a binary search using plain strcmp() comparison.
	 */
	low = keywords;
	high = keywords + (num_keywords - 1);
	while (low <= high)
	{
		const ScanKeyword *middle;
		int			difference;

		middle = low + (high - low) / 2;
		difference = strcmp(middle->name, word);
		if (difference == 0)
			return middle;
		else if (difference < 0)
			low = middle + 1;
		else
			high = middle - 1;
	}

	return NULL;
}
