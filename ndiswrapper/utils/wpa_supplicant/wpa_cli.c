/*
 * WPA Supplicant - command line interface for wpa_supplicant daemon
 * Copyright (c) 2004, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "wpa_ctrl.h"


static const char *wpa_cli_version =
"wpa_cli v0.0 - Copyright (c) 2004, Jouni Malinen <jkmaline@cc.hut.fi>";


static const char *wpa_cli_license =
"This program is free software. You can distribute it and/or modify it\n"
"under the terms of the GNU General Public License version 2.\n"
"\n"
"Alternatively, this software may be distributed under the terms of the\n"
"BSD license. See README and COPYING for more details.\n";

static const char *wpa_cli_full_license =
"This program is free software; you can redistribute it and/or modify\n"
"it under the terms of the GNU General Public License version 2 as\n"
"published by the Free Software Foundation.\n"
"\n"
"This program is distributed in the hope that it will be useful,\n"
"but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
"MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
"GNU General Public License for more details.\n"
"\n"
"You should have received a copy of the GNU General Public License\n"
"along with this program; if not, write to the Free Software\n"
"Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA\n"
"\n"
"Alternatively, this software may be distributed under the terms of the\n"
"BSD license.\n"
"\n"
"Redistribution and use in source and binary forms, with or without\n"
"modification, are permitted provided that the following conditions are\n"
"met:\n"
"\n"
"1. Redistributions of source code must retain the above copyright\n"
"   notice, this list of conditions and the following disclaimer.\n"
"\n"
"2. Redistributions in binary form must reproduce the above copyright\n"
"   notice, this list of conditions and the following disclaimer in the\n"
"   documentation and/or other materials provided with the distribution.\n"
"\n"
"3. Neither the name(s) of the above-listed copyright holder(s) nor the\n"
"   names of its contributors may be used to endorse or promote products\n"
"   derived from this software without specific prior written permission.\n"
"\n"
"THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS\n"
"\"AS IS\" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT\n"
"LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR\n"
"A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT\n"
"OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,\n"
"SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT\n"
"LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,\n"
"DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY\n"
"THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT\n"
"(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE\n"
"OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n"
"\n";

static const char *commands_help =
"commands:\n"
"  status = get current WPA/EAPOL/EAP status\n"
"  mib = get MIB variables (dot1x, dot11)\n"
"  help = show this usage help\n"
"  level <debug level> = change debug level\n"
"  license = show full wpa_cli license\n"
"  logoff = IEEE 802.1X EAPOL state machine logoff\n"
"  logon = IEEE 802.1X EAPOL state machine logon\n"
"  set = set variables (shows list of variables when run without arguments)\n"
"  pmksa = show PMKSA cache\n"
"  reassociate = force reassociation\n"
"  preauthenticate <BSSID> = force preauthentication\n"
"  identity <network id> <identity> = configure identity for an SSID\n"
"  password <network id> <password> = configure password for an SSID\n"
"  quit = exit wpa_cli\n";

static struct wpa_ctrl *ctrl_conn;
static int wpa_cli_quit = 0;
static int wpa_cli_attached = 0;


static void usage(void)
{
	printf("wpa_cli <path to wpa_supplicant ctrl socket> [command..]\n%s",
	       commands_help);
	exit(1);
}


static int wpa_ctrl_command(struct wpa_ctrl *ctrl, char *cmd)
{
	char buf[2048];
	size_t len;
	int ret;

	len = sizeof(buf) - 1;
	ret = wpa_ctrl_request(ctrl, cmd, strlen(cmd), buf, &len);
	if (ret == -2) {
		printf("'%s' command timed out.\n", cmd);
		return -2;
	} else if (ret < 0) {
		printf("'%s' command failed.\n", cmd);
		return -1;
	}
	buf[len] = '\0';
	printf("%s", buf);
	return 0;
}


static int wpa_cli_cmd_status(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	return wpa_ctrl_command(ctrl, "STATUS");
}


static int wpa_cli_cmd_mib(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	return wpa_ctrl_command(ctrl, "MIB");
}


static int wpa_cli_cmd_pmksa(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	return wpa_ctrl_command(ctrl, "PMKSA");
}


static int wpa_cli_cmd_help(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	printf("%s", commands_help);
	return 0;
}


static int wpa_cli_cmd_license(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	printf("%s\n\n%s\n", wpa_cli_version, wpa_cli_full_license);
	return 0;
}


static int wpa_cli_cmd_quit(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	wpa_cli_quit = 1;
	return 0;
}


static void wpa_cli_show_variables(void)
{
	printf("set variables:\n"
	       "  EAPOL::heldPeriod (EAPOL state machine held period, "
	       "in seconds)\n"
	       "  EAPOL::authPeriod (EAPOL state machine authentication "
	       "period, in seconds)\n"
	       "  EAPOL::startPeriod (EAPOL state machine start period, in "
	       "seconds)\n"
	       "  EAPOL::maxStart (EAPOL state machine maximum start "
	       "attempts)\n");
}


static int wpa_cli_cmd_set(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	char cmd[256];

	if (argc == 0) {
		wpa_cli_show_variables();
		return 0;
	}

	if (argc != 2) {
		printf("Invalid SET command: needs two arguments (variable "
		       "name and value)\n");
		return 0;
	}

	if (snprintf(cmd, sizeof(cmd), "SET %s %s", argv[0], argv[1]) >=
	    sizeof(cmd) - 1) {
		printf("Too long SET command.\n");
		return 0;
	}
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_logoff(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	return wpa_ctrl_command(ctrl, "LOGOFF");
}


static int wpa_cli_cmd_logon(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	return wpa_ctrl_command(ctrl, "LOGON");
}


static int wpa_cli_cmd_reassociate(struct wpa_ctrl *ctrl, int argc,
				   char *argv[])
{
	return wpa_ctrl_command(ctrl, "REASSOCIATE");
}


static int wpa_cli_cmd_preauthenticate(struct wpa_ctrl *ctrl, int argc,
				       char *argv[])
{
	char cmd[256];

	if (argc != 1) {
		printf("Invalid PREAUTH command: needs one argument "
		       "(BSSID)\n");
		return 0;
	}

	if (snprintf(cmd, sizeof(cmd), "PREAUTH %s", argv[0]) >=
	    sizeof(cmd) - 1) {
		printf("Too long PREAUTH command.\n");
		return 0;
	}
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_level(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	char cmd[256];
	if (argc != 1) {
		printf("Invalid LEVEL command: needs one argument (debug "
		       "level)\n");
		return 0;
	}
	snprintf(cmd, sizeof(cmd), "LEVEL %s", argv[0]);
	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_identity(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	char cmd[256], *pos, *end;
	int i;

	if (argc < 2) {
		printf("Invalid LEVEL command: needs two arguments (network "
		       "id and identity)\n");
		return 0;
	}

	end = cmd + sizeof(cmd);
	pos = cmd;
	pos += snprintf(pos, end - pos, "CTRL-RSP-IDENTITY-%s:%s",
		       argv[0], argv[1]);
	for (i = 2; i < argc; i++)
		pos += snprintf(pos, end - pos, " %s", argv[i]);

	return wpa_ctrl_command(ctrl, cmd);
}


static int wpa_cli_cmd_password(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	char cmd[256], *pos, *end;
	int i;

	if (argc < 2) {
		printf("Invalid LEVEL command: needs two arguments (network "
		       "id and password)\n");
		return 0;
	}

	end = cmd + sizeof(cmd);
	pos = cmd;
	pos += snprintf(pos, end - pos, "CTRL-RSP-PASSWORD-%s:%s",
		       argv[0], argv[1]);
	for (i = 2; i < argc; i++)
		pos += snprintf(pos, end - pos, " %s", argv[i]);

	return wpa_ctrl_command(ctrl, cmd);
}


struct wpa_cli_cmd {
	const char *cmd;
	int (*handler)(struct wpa_ctrl *ctrl, int argc, char *argv[]);
};

static struct wpa_cli_cmd wpa_cli_commands[] = {
	{ "status", wpa_cli_cmd_status },
	{ "mib", wpa_cli_cmd_mib },
	{ "help", wpa_cli_cmd_help },
	{ "level", wpa_cli_cmd_level },
	{ "license", wpa_cli_cmd_license },
	{ "quit", wpa_cli_cmd_quit },
	{ "set", wpa_cli_cmd_set },
	{ "logon", wpa_cli_cmd_logon },
	{ "logoff", wpa_cli_cmd_logoff },
	{ "pmksa", wpa_cli_cmd_pmksa },
	{ "reassociate", wpa_cli_cmd_reassociate },
	{ "preauthenticate", wpa_cli_cmd_preauthenticate },
	{ "identity", wpa_cli_cmd_identity },
	{ "password", wpa_cli_cmd_password },
	{ NULL, NULL }
};


static void wpa_request(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	struct wpa_cli_cmd *cmd, *match = NULL;
	int count;

	count = 0;
	cmd = wpa_cli_commands;
	while (cmd->cmd) {
		if (strncasecmp(cmd->cmd, argv[0], strlen(argv[0])) == 0) {
			match = cmd;
			count++;
		}
		cmd++;
	}

	if (count > 1) {
		printf("Ambiguous command '%s'; possible commands:", argv[0]);
		cmd = wpa_cli_commands;
		while (cmd->cmd) {
			if (strncasecmp(cmd->cmd, argv[0], strlen(argv[0])) ==
			    0) {
				printf(" %s", cmd->cmd);
			}
			cmd++;
		}
		printf("\n");
	} else if (count == 0) {
		printf("Unknown command '%s'\n", argv[0]);
	} else {
		match->handler(ctrl, argc - 1, &argv[1]);
	}
}


static void wpa_cli_recv_pending(struct wpa_ctrl *ctrl, int in_read)
{
	int first = 1;
	while (wpa_ctrl_pending(ctrl)) {
		char buf[256];
		size_t len = sizeof(buf) - 1;
		if (wpa_ctrl_recv(ctrl, buf, &len) == 0) {
			buf[len] = '\0';
			if (in_read && first)
				printf("\n");
			first = 0;
			printf("%s\n", buf);
		}
	}
}


static void wpa_cli_interactive(struct wpa_ctrl *ctrl)
{
	const int max_args = 10;
	char cmd[256], *res, *argv[max_args], *pos;
	int argc;

	printf("%s\n\n%s\n\n"
	       "Interactive mode\n\n",
	       wpa_cli_version, wpa_cli_license);

	do {
		wpa_cli_recv_pending(ctrl, 0);
		printf("> ");
		alarm(1);
		res = fgets(cmd, sizeof(cmd), stdin);
		alarm(0);
		if (res == NULL)
			break;
		pos = cmd;
		while (*pos != '\0') {
			if (*pos == '\n') {
				*pos = '\0';
				break;
			}
			pos++;
		}
		argc = 0;
		pos = cmd;
		for (;;) {
			while (*pos == ' ')
				pos++;
			if (*pos == '\0')
				break;
			argv[argc] = pos;
			argc++;
			if (argc == max_args)
				break;
			while (*pos != '\0' && *pos != ' ')
				pos++;
			if (*pos == ' ')
				*pos++ = '\0';
		}
		if (argc)
			wpa_request(ctrl, argc, argv);
	} while (!wpa_cli_quit);
}


static void wpa_cli_terminate(int sig)
{
	if (ctrl_conn) {
		if (wpa_cli_attached)
			wpa_ctrl_detach(ctrl_conn);
		wpa_ctrl_close(ctrl_conn);
	}
	exit(0);
}


static void wpa_cli_alarm(int sig)
{
	wpa_cli_recv_pending(ctrl_conn, 1);
	alarm(1);
}


int main(int argc, char *argv[])
{

	if (argc < 2)
		usage();

	ctrl_conn = wpa_ctrl_open(argv[1]);
	if (ctrl_conn == NULL) {
		perror("wpa_ctrl_open");
		return -1;
	}

	signal(SIGINT, wpa_cli_terminate);
	signal(SIGTERM, wpa_cli_terminate);
	signal(SIGALRM, wpa_cli_alarm);

	if (argc == 2) {
		if (wpa_ctrl_attach(ctrl_conn) == 0) {
			wpa_cli_attached = 1;
		} else {
			printf("Warning: Failed to attach to "
			       "wpa_supplicant.\n");
		}
		wpa_cli_interactive(ctrl_conn);
	} else
		wpa_request(ctrl_conn, argc - 2, &argv[2]);

	wpa_cli_terminate(0);
	return 0;
}
