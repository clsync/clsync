/*
    clsync - file tree sync utility based on inotify/kqueue
    
    Copyright (C) 2013-2014 Dmitry Yu Okunev <dyokunev@ut.mephi.ru> 0x8E30679C
    
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "common.h"

#include <glib.h>	// g_hash_table_*

#include "rules.h"
#include "error.h"

int rule_complete(rule_t *rule_p, char *expr, size_t *rules_count_p) {
	debug(3, "<%s>.", expr);
#ifdef VERYPARANOID
	if (rule_p->mask == RA_NONE) {
		error("Received a rule with rule_p->mask == 0x00. Exit.");
		return EINVAL;
	}
#endif

	char buf[BUFSIZ];
	int ret = 0;

	if (rule_p->num >= MAXRULES) {
		error("Too many rules (%i >= %i).", rule_p->num, MAXRULES);
		return ENOMEM;
	}

	if ((ret = regcomp(&rule_p->expr,       expr, REG_EXTENDED | REG_NOSUB))) {
		regerror(ret, &rule_p->expr, buf, BUFSIZ);
		error("Invalid regexp pattern <%s>: %s (regex-errno: %i).", expr, buf, ret);
		return ret;
	}

	(*rules_count_p)++;
	return ret;
}

int parse_rules_fromfile(ctx_t *ctx_p) {
	int ret = 0;
	char *rulfpath = ctx_p->rulfpath;
	rule_t *rules  = ctx_p->rules;
	size_t *rules_count_p = &ctx_p->rules_count;

	char *line_buf=NULL;
	FILE *f = fopen(rulfpath, "r");
	
	if(f == NULL) {
		rules->mask   = RA_NONE;		// Terminator. End of rules' chain.
		rules->perm   = DEFAULT_RULES_PERM;
		error("Cannot open \"%s\" for reading.", rulfpath);
		return errno;
	}

	GHashTable *autowrules_ht = g_hash_table_new_full(g_str_hash,	g_str_equal,	free,    0);

	int i=0;
	size_t linelen, size=0;
	while((linelen = getline(&line_buf, &size, f)) != -1) {
		if(linelen>1) {
			uint8_t sign = 0;
			char *line = line_buf;
			rule_t *rule;

			rule = &rules[i];
#ifdef VERYPARANOID
			memset(rule, 0, sizeof(*rule));
#endif
			rule->num = i++;
			line[--linelen] = 0; 


			// Parsing the first character of the line
			switch(*line) {
				case '+':
					sign = RS_PERMIT;
					break;
				case '-':
					sign = RS_REJECT;
					break;
				case '#':	// Comment?
					i--;	// Canceling new rule
					continue;
				default:
					error("Wrong rule action <%c>.", *line);
					return EINVAL;
			}

			line++;
			linelen--;

			// Parsing the second character of the line
			*line |= 0x20;	// lower-casing
			// Default rule->mask and rule->perm

			// rule->mask - sets bitmask of operations that are affected by the rule
			// rule->perm - sets bitmask of permit/reject for every operation. Effect have only bits specified by the rule->mask.

			rule->mask = RA_ALL;
			switch(sign) {
				case RS_REJECT:
					rule->perm = RA_NONE;
					break;
				case RS_PERMIT:
					rule->perm = RA_ALL;
					break;
			}

			switch(*line) {
				case '*':
					rule->objtype = 0;	// "0" - means "of any type"
					break;
#ifdef DETAILED_FTYPE
				case 's':
					rule->objtype = S_IFSOCK;
					break;
				case 'l':
					rule->objtype = S_IFLNK;
					break;
				case 'b':
					rule->objtype = S_IFBLK;
					break;
				case 'c':
					rule->objtype = S_IFCHR;
					break;
				case 'p':
					rule->objtype = S_IFIFO;
					break;
#endif
				case 'f':
					rule->objtype = S_IFREG;
					break;
				case 'd':
					rule->objtype = S_IFDIR;
					break;
				case 'w':	// accept or reject walking to directory
					if (
						(ctx_p->flags[MODE] == MODE_RSYNCDIRECT) ||
						(ctx_p->flags[MODE] == MODE_RSYNCSHELL)  ||
						(ctx_p->flags[MODE] == MODE_RSYNCSO)
					)
						warning("Used \"w\" rule in \"--rsync\" case."
							" This may cause unexpected problems.");

					rule->objtype = S_IFDIR;
					rule->mask    = RA_WALK;
					break;
				default:
					warning("Cannot parse the rule <%s>", &line[-1]);
					i--;	// Canceling new rule
					continue;
			}


			line++;
			linelen--;

			// Parsing the rest part of the line

			debug(1, "Rule #%i <%c>[0x%02x 0x%02x] <%c>[0x%04x] pattern <%s> (length: %i).", rule->num, line[-2], rule->perm, rule->mask, line[-1], rule->objtype, line, linelen);
			if((ret=rule_complete(rule, line, rules_count_p)))
				goto l_parse_rules_fromfile_end;

			// Post-processing:

			line--;
			linelen++;

#ifdef AUTORULESW
			if(*line != 'w') {
				// processing --auto-add-rules-w
				if(ctx_p->flags[AUTORULESW] && (sign == RS_PERMIT)) {
					// Preparing to add appropriate w-rules
					char skip = 0;
					char *expr = alloca(linelen+2);
					memcpy(expr, line, linelen+1);
					size_t exprlen = linelen;

					// Making expr to be starting with '^'
					if(line[1] == '^') {
						expr++;
						exprlen--;
					} else
						*expr = '^';

					char *end;

					if(*line == 'd' || *line == '*') {
						// "d" rule already doing what we need, so we can skip the last level

						end = &expr[exprlen];
						if(end[-1] != '$')
							*(end++) = '$';
						*end = 0;

//						debug(3, "Don't adding w-rule for \"%s\" due to [*d]-rule for \"%s\"",
//							expr, &line[1]);
						g_hash_table_insert(autowrules_ht, strdup(expr), GINT_TO_POINTER(1));

					}

					if(!skip) {

						do {
							// Decreasing directory level and make the '$' ending
							end = strrchr(expr, '/');
							if(end != NULL) {
								if(end[-1] != '$')
									*(end++) = '$';
								*end = 0;
								exprlen = (size_t)(end - expr);
							} else {
								expr[1] = '$';
								expr[2] = 0;
								exprlen = 2;
							}

							// Checking if it not already set
							if(!g_hash_table_lookup(autowrules_ht, expr)) {

								// Switching to next rule:

								rule = &rules[i];
								rule->num = i++;

								// Adding the rule

								rule->objtype = S_IFDIR;
								rule->mask    = RA_WALK;
								rule->perm    = RA_WALK;

								debug(1, "Rule #%i <+> <w> pattern <%s> (length: %i) [auto].", 
									rule->num, expr, exprlen);
								if((ret=rule_complete(rule, expr, rules_count_p)))
									goto l_parse_rules_fromfile_end;
								g_hash_table_insert(autowrules_ht, strdup(expr), GINT_TO_POINTER(1));

							}
						} while (end != NULL);
					}
				}
			}
#endif
		}
	}

l_parse_rules_fromfile_end:
	if (size)
		free(line_buf);

	fclose(f);

	debug(3, "Adding tail-rule #%u (effective #%u).", -1, i);

	rules[i].mask   = RA_NONE;		// Terminator. End of rules' chain.
	rules[i].perm   = DEFAULT_RULES_PERM;

	g_hash_table_destroy(autowrules_ht);
#ifdef _DEBUG_FORCE
	debug(3, "Total (p == %p):", rules);
	i=0;
	do {
		debug(4, "\t%i\t%i\t%p/%p", i, rules[i].objtype, (void *)(long)rules[i].perm, (void *)(long)rules[i].mask);
		i++;
	} while(rules[i].mask != RA_NONE);
#endif
	return ret;
}

/**
 * @brief 			Checks file path by rules' expressions (parsed from file)
 * 
 * @param[in] 	fpath		Path to file of directory
 * @param[in] 	st_mode		st_mode received via *stat() functions
 * @param[in] 	rules_p		Pointer to start of rules array
 * @param[in] 	ruleaction	Operaton ID (see ruleaction_t)
 * @param[i/o] 	rule_pp		Pointer to pointer to rule, where the last search ended. Next search will be started from the specified rule. Can be "NULL" to disable this feature.
 *
 * @retval	perm		Permission bitmask
 * 
 */
// Checks file path by rules' expressions (parsed from file)
// Return: RS_PERMIT or RS_REJECT for the "file path" and specified ruleaction

ruleaction_t rules_search_getperm(const char *fpath, mode_t st_mode, rule_t *rules_p, const ruleaction_t ruleaction, rule_t **rule_pp) {
	debug(3, "rules_search_getperm(\"%s\", %p, %p, %p, %p)", 
			fpath, (void *)(unsigned long)st_mode, rules_p,
			(void *)(long)ruleaction, (void *)(long)rule_pp
		);

	int i;
	i = 0;
	rule_t *rule_p = rules_p;
	mode_t ftype = st_mode & S_IFMT;

#ifdef _DEBUG_FORCE
	debug(3, "Rules (p == %p):", rules_p);
	i=0;
	do {
		debug(3, "\t%i\t%i\t%p/%p", i, rules_p[i].objtype, (void *)(long)rules_p[i].perm, (void *)(long)rules_p[i].mask);
		i++;
	} while (rules_p[i].mask != RA_NONE);
#endif

        i=0;
	if (rule_pp != NULL)
		if (*rule_pp != NULL) {
			debug(3, "Previous position is set.");
			if (rule_p->mask == RA_NONE)
				return rule_p->perm;

			rule_p = ++(*rule_pp);
			i = rule_p->num;
		}

	debug(3, "Starting from position %i", i);
	while (rule_p->mask != RA_NONE) {
		debug(3, "%i -> %p/%p: type compare: %p, %p -> %i", 
				i,
				(void *)(long)rule_p->perm, (void *)(long)rule_p->mask,
				(void *)(unsigned long)ftype, (void *)(unsigned long)rule_p->objtype, 
				(unsigned char)!(rule_p->objtype && (rule_p->objtype != ftype))
			);

		if (!(rule_p->mask & ruleaction)) {	// Checking wrong operation type
			debug(3, "action-mask mismatch. Skipping.");
			rule_p++;i++;// = &rules_p[++i];
			continue;
		}

		if (rule_p->objtype && (rule_p->objtype != ftype)) {
			debug(3, "objtype mismatch. Skipping.");
			rule_p++;i++;// = &rules_p[++i];
			continue;
		}

		if(!regexec(&rule_p->expr, fpath, 0, NULL, 0))
			break;

		debug(3, "doesn't match regex. Skipping.");
		rule_p++;i++;// = &rules_p[++i];

	}

	debug(2, "matched to rule #%u for \"%s\":\t%p/%p (queried: %p).", rule_p->mask==RA_NONE?-1:i, fpath, 
			(void *)(long)rule_p->perm, (void *)(long)rule_p->mask,
			(void *)(long)ruleaction
		);

	if (rule_pp != NULL)
		*rule_pp = rule_p;

	return rule_p->perm;
}

ruleaction_t rules_getperm(const char *fpath, mode_t st_mode, rule_t *rules_p, ruleaction_t ruleactions) {
	rule_t *rule_p = NULL;
	ruleaction_t gotpermto  = 0;
	ruleaction_t resultperm = 0;
	debug(3, "rules_getperm(\"%s\", %p, %p (#%u), %p)", 
		fpath, (void *)(long)st_mode, rules_p, rules_p->num, (void *)(long)ruleactions);

	while((gotpermto&ruleactions) != ruleactions) {
		rules_search_getperm(fpath, st_mode, rules_p, ruleactions, &rule_p);
		if(rule_p->mask == RA_NONE) { // End of rules' list 
			resultperm |= rule_p->perm & (gotpermto^RA_ALL);
			break;
		}
		resultperm |= rule_p->perm & ((gotpermto^rule_p->mask)&rule_p->mask);	// Adding perm bitmask of operations that was unknown before
		gotpermto  |= rule_p->mask;						// Adding the mask
	}

	debug(3, "rules_getperm(\"%s\", %p, rules_p, %p): result perm is %p",
		fpath, (void *)(long)st_mode, (void *)(long)ruleactions, (void *)(long)resultperm);

	return resultperm;
}

