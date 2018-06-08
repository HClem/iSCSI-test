#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "iscsi/iscsi.h"
#include "iscsi/scsi-lowlevel.h"

struct client_state {
       int finished;
       const char *message;
       int has_discovered_target;
       char *target_name;
       char *target_address;
       int lun;
       int block_size;
};

void
printluns(struct scsi_reportluns_list *list, struct client_state *client_state)
{
	for (int i = 0; i < (int)list->num; i++) {
		printf("LUN:%d found\n", list->luns[i]);
		client_state->lun = list->luns[i];
	}
}

void
printdiscoveryaddr(struct iscsi_discovery_address *addr)
{
	struct iscsi_discovery_address *addr_tmp = addr;
	for(; addr_tmp; addr_tmp = addr_tmp->next) {	
		printf("Target:%s Address:%s\n", addr->target_name, addr->portals->portal);
	}
}

void
reportluns(struct iscsi_context *iscsi_context, struct client_state *client_state)
{
	struct scsi_reportluns_list *list;
	int full_report_size;

	printf("Logged in normal session, send reportluns\n");
	struct scsi_task *scsi_task = iscsi_reportluns_sync(iscsi_context, 0, 16);
	if (!scsi_task) {
		printf("failed to send reportluns command : %s\n", iscsi_get_error(iscsi_context));
		exit(1);
	}

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
	}

	list = scsi_datain_unmarshall(scsi_task);
	if (!list) {
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

	printdiscoveryaddr(addr);

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

void
normallogin(struct iscsi_context *iscsi_context, char *user, char *passwd, struct client_state *client_state)
{
	printf("Reconnect with normal login to [%s]\n", client_state->target_address);
	printf("Use targetname [%s] when connecting\n", client_state->target_name);
	if (iscsi_set_targetname(iscsi_context, client_state->target_name)) {
		printf("Failed to set target name\n");
		exit(1);
	}
	if (iscsi_set_session_type(iscsi_context, ISCSI_SESSION_NORMAL) != 0) {
		printf("Failed to set settion type to normal\n");
		exit(1);
	}
        iscsi_set_header_digest(iscsi_context, ISCSI_HEADER_DIGEST_CRC32C_NONE);

	if (iscsi_connect_sync(iscsi_context, client_state->target_address) != 0) {
		printf("iscsi_connect failed : %s\n", iscsi_get_error(iscsi_context));
		exit(1);
	}
	printf("connected, send login command\n");
	iscsi_set_target_username_pwd(iscsi_context, user, passwd);
	if (iscsi_login_sync(iscsi_context) != 0) {
		printf("iscsi_login failed\n");
		exit(1);
	}
}

int 
main(void)
{
	struct iscsi_context *iscsi_context;
	struct client_state client_state;
	char *portal = "127.0.0.1";
	char *initiator_name = "iqn.2005-03.org.open-iscsi:clem";
	char *user = "user";
	char *passwd = "pass";


	memset(&client_state, 0, sizeof(client_state));

	iscsi_context = iscsi_create_context(initiator_name);
	if (!iscsi_context) {
		printf("Failed to create context\n");
		exit(1);
	}

	discovery(iscsi_context, portal, &client_state);

	normallogin(iscsi_context, user, passwd, &client_state);

	reportluns(iscsi_context, &client_state);

	iscsi_destroy_context(iscsi_context);

	if (client_state.target_name) {
		free(client_state.target_name);
	}
	if (client_state.target_address) {
		free(client_state.target_address);
	}

	printf("Ok\n");

	return 0;
}
