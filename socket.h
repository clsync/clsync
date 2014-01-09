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

#define SOCKET_DEFAULT_PROT 0
#define SOCKET_DEFAULT_SUBPROT SUBPROT0_TEXT

// buffer size
#define SOCKET_BUFSIZ			(1<<12)

struct client {
	int sock;
	uint16_t prot;
	uint16_t subprot;
};
typedef struct client client_t;

enum subprot0 {
	SUBPROT0_TEXT,
	SUBPROT0_BINARY,
};
typedef enum subprot0 subprot0_t;

struct sockcmd_negotiation {
	uint16_t prot;
	uint16_t subprot;
};

enum client_state {
	CLSTATE_NONE	= 0,
	CLSTATE_AUTH,
	CLSTATE_MAIN,
	CLSTATE_DYING,
	CLSTATE_DIED,
};
typedef enum client_state client_state_t;

enum sockcmd_id {
	SOCKCMD_NEGOTIATION	=  00,
	SOCKCMD_ACK		=  50,
	SOCKCMD_UNKNOWNCMD	=  60,
	SOCKCMD_INVALIDCMDID	=  61,
	SOCKCMD_EINVAL		=  62,
	SOCKCMD_LOGIN		= 100,
	SOCKCMD_VERSION		= 201,
	SOCKCMD_INFO		= 202,
	SOCKCMD_DIE		= 210,
	SOCKCMD_UNEXPECTEDEND	= 300,
	SOCKCMD_QUIT		= 301,
	SOCKCMD_BYE		= 350,
};
typedef enum sockcmd_id sockcmd_id_t;

static char *const textmessage_args[] = {
	[SOCKCMD_NEGOTIATION] 	= "%u",
	[SOCKCMD_ACK]		= "%03u %lu",
	[SOCKCMD_EINVAL]	= "%03u %lu",
	[SOCKCMD_VERSION]	= "%u %u",
	[SOCKCMD_INFO]		= "%s\003/ %s\003/ %x %x",
	[SOCKCMD_UNKNOWNCMD]	= "%03u %lu",
	[SOCKCMD_INVALIDCMDID]	= "%lu",
};

static char *const textmessage_descr[] = {
	[SOCKCMD_NEGOTIATION] 	= "Protocol version is %u.",
	[SOCKCMD_ACK]		= "Acknowledged command: id == %03u; num == %lu.",
	[SOCKCMD_EINVAL]	= "Rejected command: id == %03u; num == %lu. Invalid arguments: %s.",
	[SOCKCMD_LOGIN]		= "Enter your login and password, please.",
	[SOCKCMD_UNEXPECTEDEND]	= "Need to go, sorry. :)",
	[SOCKCMD_DIE]		= "Okay :(",
	[SOCKCMD_BYE]		= "Bye.",
	[SOCKCMD_VERSION]	= "clsync v%u.%u.",
	[SOCKCMD_INFO]		= "config_block == \"%s\"; label == \"%s\"; flags == %x; flags_set == %x.",
	[SOCKCMD_UNKNOWNCMD]	= "Unknown command.",
	[SOCKCMD_INVALIDCMDID]	= "Invalid command id. Required: 0 <= cmd_id < 1000.",
};

struct sockcmd {
	uint64_t	cmd_num;
	uint16_t	cmd_id;
	size_t		data_len;
	char		data[1];
};
typedef struct sockcmd sockcmd_t;

extern int socket_run(options_t *options_p);
extern int socket_cleanup(options_t *options_p);


