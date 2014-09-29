/*
    clsync - file tree sync utility based on inotify/kqueue/bsm
    
    Copyright (C) 2014  Dmitry Yu Okunev <dyokunev@ut.mephi.ru> 0x8E30679C
    
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
#include "port-hacks.h"
#include <stdlib.h>

#ifdef tdestroy_UNDEFINED
struct _tdestroy_tree {
	void *data;
	struct _tdestroy_tree *left;
	struct _tdestroy_tree *right;
};
 
void tdestroy(void *root, void (*free_node)(void *node_data)) {
	struct _tdestroy_tree *node_p = root;
	if (node_p == NULL)
		return;
	
	tdestroy(node_p->left , free_node);
	tdestroy(node_p->right, free_node);

	free_node(node_p->data);
	free(node_p);
	return;
}
#endif

