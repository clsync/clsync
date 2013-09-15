/*
    clsync - file tree sync utility based on fanotify and inotify
    
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

typedef gpointer(*GDupFunc)(gpointer data);

extern GHashTable *g_hash_table_dup(GHashTable *ht, GHashFunc hash_funct, GEqualFunc key_equal_funct, GDestroyNotify key_destroy_funct, GDestroyNotify value_destroy_funct, GDupFunc key_dup_funct, GDupFunc value_dup_funct);

