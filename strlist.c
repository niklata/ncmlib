/* strlist.c - string list functions
 *
 * (c) 2005-2014 Nicholas J. Kain <njkain at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "malloc.h"
#include "xstrdup.h"
#include "strlist.h"

void add_to_strlist(strlist_t **list, char *name)
{
	strlist_t *item, *t;
	char *s;

	if (!list || !name || !name[0]) return;

	item = xmalloc(sizeof (strlist_t));
	item->str = xstrdup(name);
	item->next = NULL;

	if (!*list) {
		*list = item;
		return;
	}

	t = *list;
	while (t) {
		if (t->next == NULL) {
			t->next = item;
			return;
		}
		t = t->next;
	}

	free(item); /* should be impossible, but hey */
	free(s);
	return;
}

void free_strlist(strlist_t *head)
{
    strlist_t *p = head, *q = NULL;

    while (p != NULL) {
        free(p->str);
        q = p;
        p = q->next;
        free(q);
    }
}

void free_stritem(strlist_t **p)
{
    strlist_t *q;

    if (!p) return;
    if (!*p) return;

    q = (*p)->next;
    free((*p)->str);
    free(*p);
    *p = q;
}

int get_strlist_arity(strlist_t *list)
{
	int i;
	strlist_t *c;

	for (c = list, i = 0; c != NULL; c = c->next, ++i);
	return i;
}


