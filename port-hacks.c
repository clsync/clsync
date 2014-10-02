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

#include "error.h"

#ifdef tdestroy_UNDEFINED
struct _tcallfunct_tree {
	void *data;
	struct _tcallfunct_tree *left;
	struct _tcallfunct_tree *right;
};
 
void tcallfunct(void *root, void (*funct)(struct _tcallfunct_tree *node_p, void *arg), void *arg) {
	struct _tcallfunct_tree *node_p = root;
	if (node_p == NULL)
		return;
	
	tcallfunct(node_p->left , funct, arg);
	tcallfunct(node_p->right, funct, arg);

	funct(node_p, arg);
	return;
}

void tdump_node(struct _tcallfunct_tree *node_p, void *arg) {
	debug(80, "node_p == %p; node_p->left == %p; node_p->right == %p; node_p->data == %p", node_p, node_p->left, node_p->right, node_p->data);
	return;
}

void _tdump(void *root) {
	debug(20, "root = %p", root);
	tcallfunct(root, tdump_node, NULL);
	return;
}

void tdestroy_freenode(struct _tcallfunct_tree *node_p, void *_free_node_funct) {
	void (*free_node_funct)(void *node_data) = _free_node_funct;
	free_node_funct(node_p->data);
	free(node_p);
	return;
}

void tdestroy(void *root, void (*free_node)(void *node_data)) {
	tcallfunct(root, tdestroy_freenode, free_node);
	return;
}
#endif

