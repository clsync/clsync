/*
    clsync - file tree sync utility based on inotify
    
    Copyright (C) 2013  Dmitry Yu Okunev <dyokunev@ut.mephi.ru> 0x8E30679C
    
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
#include "glibex.h"

__extension__ struct keyvalue_copy_arg {
	union {
		GHashTable *ht_dst;
		GTree      *bt_dst;
	};
	GDupFunc k_dup_funct;
	GDupFunc v_dup_funct;
};

void g_hash_table_dup_item(gpointer k, gpointer v, gpointer arg_gp) {
	GHashTable *ht_dst	= ((struct keyvalue_copy_arg *)arg_gp)->ht_dst;
	GDupFunc k_dup_funct	= ((struct keyvalue_copy_arg *)arg_gp)->k_dup_funct;
	GDupFunc v_dup_funct	= ((struct keyvalue_copy_arg *)arg_gp)->v_dup_funct;

	g_hash_table_insert(ht_dst, k_dup_funct==NULL?NULL:k_dup_funct(k), v_dup_funct==NULL?NULL:v_dup_funct(v));

	return;
}

GHashTable *g_hash_table_dup(GHashTable *src, GHashFunc hash_funct, GEqualFunc key_equal_funct, GDestroyNotify key_destroy_funct, GDestroyNotify value_destroy_funct, GDupFunc key_dup_funct, GDupFunc value_dup_funct) {
	GHashTable *dst = g_hash_table_new_full(hash_funct, key_equal_funct, key_destroy_funct, value_destroy_funct);

	struct keyvalue_copy_arg arg;
	arg.ht_dst = dst;
	arg.k_dup_funct =   key_dup_funct;
	arg.v_dup_funct = value_dup_funct;

	g_hash_table_foreach(src, g_hash_table_dup_item, &arg);

	return dst;
}

gboolean g_tree_dup_item(gpointer k, gpointer v, gpointer arg_gp) {
	GTree *bt_dst		= ((struct keyvalue_copy_arg *)arg_gp)->bt_dst;
	GDupFunc k_dup_funct	= ((struct keyvalue_copy_arg *)arg_gp)->k_dup_funct;
	GDupFunc v_dup_funct	= ((struct keyvalue_copy_arg *)arg_gp)->v_dup_funct;

	g_tree_replace(bt_dst, k_dup_funct==NULL?NULL:k_dup_funct(k), v_dup_funct==NULL?NULL:v_dup_funct(v));

	return FALSE;
}

GTree *g_tree_dup(GTree *src, GCompareDataFunc key_compare_func, gpointer key_compare_data, GDestroyNotify key_destroy_func, GDestroyNotify value_destroy_func, GDupFunc key_dup_funct, GDupFunc value_dup_funct) {
	GTree *dst = g_tree_new_full(key_compare_func, key_compare_data, key_destroy_func, value_destroy_func);

	struct keyvalue_copy_arg arg;
	arg.bt_dst = dst;
	arg.k_dup_funct =   key_dup_funct;
	arg.v_dup_funct = value_dup_funct;

	g_tree_foreach(src, g_tree_dup_item, &arg);

	return dst;
}

