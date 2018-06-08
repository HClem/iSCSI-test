/* 
   Copyright (C) 2012 by Ronnie Sahlberg <ronniesahlberg@gmail.com>
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/



/* This is an example of using libiscsi.
 * It basically logs in to the the target and performs a discovery. --> interesting
 * It then selects the last target in the returned list and
 * starts a normal login to that target.
 * Once logged in it issues a REPORTLUNS call and selects the last returned lun in the list.
 * This LUN is then used to send INQUIRY, READCAPACITY10 and READ10 test calls to.
 */
/* The reason why we have to specify an allocation length and sometimes probe, starting with a small value, probing how big the buffer 
 * should be, and asking again with a bigger buffer.
 * Why not just always ask with a buffer that is big enough?
 * The reason is that a lot of scsi targets are "sensitive" and ""buggy""
 * many targets will just fail the operation completely if they thing alloc len is unreasonably big.
 */

/* This is the host/port we connect to.*/
#define TARGET "127.0.0.1:3260"

#include <poll.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "iscsi/iscsi.h"
#include "iscsi/scsi-lowlevel.h"


struct iscsi_sync_state {
        int finished;
        int status;
        void *ptr;
        struct scsi_task *task;
};

static void
event_loop(struct iscsi_context *iscsi, struct iscsi_sync_state *state)
{
        struct pollfd pfd;
        int ret;

        while (state->finished == 0) {
                short revents;

                pfd.fd = iscsi_get_fd(iscsi);
                pfd.events = iscsi_which_events(iscsi);

                if ((ret = poll(&pfd, 1, 1000)) < 0) {
                        state->status = -1;
                        return;
                }
                revents = (ret == 0) ? 0 : pfd.revents;
                if (iscsi_service(iscsi, revents) < 0) {
                        state->status = -1;
                        return;
                }
        }
}
static void
iscsi_discovery_cb(struct iscsi_context *iscsi , int status,
              void *command_data, void *private_data)
{
	(void) iscsi;
        struct iscsi_sync_state *state = private_data;
        struct iscsi_discovery_address *da;
        struct iscsi_discovery_address *dahead = NULL;
        struct iscsi_target_portal *po;

        for (da = command_data; da != NULL; da = da->next) {
                struct iscsi_discovery_address *datmp;

                datmp = malloc(sizeof(struct iscsi_discovery_address));
                memset(datmp, 0, sizeof(struct iscsi_discovery_address));
                datmp->target_name = strdup(da->target_name);
                datmp->next = dahead;
                dahead = datmp;

                for (po = da->portals; po != NULL; po = po->next) {
                        struct iscsi_target_portal *potmp;

                        potmp = malloc(sizeof(struct iscsi_target_portal));
                        memset(potmp, 0, sizeof(struct iscsi_target_portal));
                        potmp->portal = strdup(po->portal);

                        potmp->next = dahead->portals;
                        dahead->portals = potmp;
                }
        }

        if (state != NULL) {
                state->status    = status;
                state->finished = 1;
                state->ptr = dahead;
        }
}

struct iscsi_discovery_address *
iscsi_discovery_sync(struct iscsi_context *iscsi)
{
        struct iscsi_sync_state state;

        memset(&state, 0, sizeof(state));

        if (iscsi_discovery_async(iscsi, iscsi_discovery_cb, &state) != 0) {
                printf("async discovery call failed\n");
                return NULL;
        }

        event_loop(iscsi, &state);

        return state.ptr;
}

struct client_state {
       int finished;
       const char *message;
       int has_discovered_target;
       char *target_name;
       char *target_address;
       int lun;
       int block_size;
};

unsigned char small_buffer[512];

void
printluns(struct scsi_reportluns_list *list, struct client_state *client_state)
{
	for (int i = 0; i < (int)list->num; i++) {
		printf("LUN:%d found\n", list->luns[i]);
		client_state->lun = list->luns[i];
	}
}

void
reportluns(struct iscsi_context *iscsi_context, struct scsi_task *scsi_task,
		struct client_state *client_state)
{
	struct scsi_reportluns_list *list;
	int full_report_size;

	if (scsi_task->status != SCSI_STATUS_GOOD) {
                printf("Reportluns failed with : %s\n", iscsi_get_error(iscsi_context));
                scsi_free_scsi_task(scsi_task);
                return;
        }

	full_report_size = scsi_datain_getfullsize(scsi_task);

	printf("REPORTLUNS data size:%d,   full reports luns data size:%d\n",
		scsi_task->datain.size, full_report_size);

	if (full_report_size > scsi_task->datain.size) {
		printf("We did not get all the data we need in reportluns, ask again\n");
		scsi_free_scsi_task(scsi_task);
		scsi_task = iscsi_reportluns_sync(iscsi_context, 0, full_report_size);
		if (!scsi_task) {
			printf("failed to send reportluns command\n");
			scsi_free_scsi_task(scsi_task);
			exit(10);
		}
		reportluns(iscsi_context, scsi_task, client_state);
		scsi_free_scsi_task(scsi_task);
		return;
	}

	list = scsi_datain_unmarshall(scsi_task);
	if (list == NULL) {
		printf("failed to unmarshall reportluns datain blob\n");
		scsi_free_scsi_task(scsi_task);
		exit(10);
	}
	printluns(list, client_state);
	scsi_free_scsi_task(scsi_task);
}


void 
discovery(struct iscsi_context *iscsi_context, const char *portal, struct client_state *client_state)
{
	/*if (iscsi_set_alias(iscsi_context, alias) != 0) {
		printf("Failed to add alias\n");
		exit(1);
	}*/

	client_state->message = "Hello iSCSI";
	client_state->has_discovered_target = 0;

	if (iscsi_connect_sync(iscsi_context, portal) != 0) {
		printf("iscsi_connect failed. %s\n", iscsi_get_error(iscsi_context));
		exit(1);
	}

	printf("connected, send login command\n");
	iscsi_set_session_type(iscsi_context, ISCSI_SESSION_DISCOVERY);

	if (iscsi_login_sync(iscsi_context) != 0) {
		printf("iscsi_login failed : %s\n", iscsi_get_error(iscsi_context));
		exit(1);
	}

	printf("Logged in to target, send discovery command\n");
	struct iscsi_discovery_address *addr = iscsi_discovery_sync(iscsi_context);
	if (!addr) {
		printf("failed to send discovery command : %s\n", iscsi_get_error(iscsi_context));
		exit(1);
	}

	struct iscsi_discovery_address *addr_tmp = addr;
	for(; addr_tmp; addr_tmp = addr_tmp->next) {	
		printf("Target:%s Address:%s\n", addr->target_name, addr->portals->portal);
	}

	client_state->has_discovered_target = 1;
	client_state->target_name    = strdup(addr->target_name);
	client_state->target_address = strdup(addr->portals->portal);
	
	printf("discovery complete, send logout command\n");

	if (iscsi_logout_sync(iscsi_context) != 0) {
		printf("iscsi_logout failed : %s\n", iscsi_get_error(iscsi_context));
		exit(1);
	}

	printf("disconnect socket\n");
	if (iscsi_disconnect(iscsi_context) != 0) {
		printf("Failed to disconnect old socket\n");
		exit(1);
	}
}

int 
main(void)
{
	struct iscsi_context *iscsi_context;
	char *alias = "clem";
	struct client_state client_state;
	char *portal = "127.0.0.1";
	char *initiator_name = "iqn.2005-03.org.open-iscsi:clem";
	char *user = "user";
	char *passwd = "pass";
	printf("iscsi client\n");


	memset(&client_state, 0, sizeof(client_state));

	iscsi_context = iscsi_create_context(initiator_name);
	if (!iscsi_context) {
		printf("Failed to create context\n");
		exit(1);
	}

	discovery(iscsi_context, portal, &client_state);

	printf("reconnect with normal login to [%s]\n", client_state.target_address);
	printf("Use targetname [%s] when connecting\n", client_state.target_name);
	if (iscsi_set_targetname(iscsi_context, client_state.target_name)) {
		printf("Failed to set target name\n");
		exit(1);
	}
	if (iscsi_set_alias(iscsi_context, alias) != 0) {
		printf("Failed to add alias\n");
		exit(1);
	}
	if (iscsi_set_session_type(iscsi_context, ISCSI_SESSION_NORMAL) != 0) {
		printf("Failed to set settion type to normal\n");
		exit(1);
	}

	if (iscsi_connect_sync(iscsi_context, client_state.target_address) != 0) {
		printf("iscsi_connect failed : %s\n", iscsi_get_error(iscsi_context));
		exit(1);
	}

	printf("connected, send login command\n");
	iscsi_set_header_digest(iscsi_context, ISCSI_HEADER_DIGEST_CRC32C_NONE);
	iscsi_set_target_username_pwd(iscsi_context, user, passwd);
	//iscsi_set_initiator_username_pwd(iscsi_context, user, passwd);
	if (iscsi_login_sync(iscsi_context) != 0) {
		printf("iscsi_login failed hello\n");
		exit(1);
	}

	printf("Logged in normal session, send reportluns\n");
	struct scsi_task *scsi_task = iscsi_reportluns_sync(iscsi_context, 0, 16);
	if (!scsi_task) {
		printf("failed to send reportluns command : %s\n", iscsi_get_error(iscsi_context));
		exit(1);
	}
	printf("Logged in normal session, send reportluns\n");
	reportluns(iscsi_context, scsi_task, &client_state);

	iscsi_destroy_context(iscsi_context);

	if (client_state.target_name) {
		free(client_state.target_name);
	}
	if (client_state.target_address) {
		free(client_state.target_address);
	}

	printf("ok\n");
	return 0;
}
