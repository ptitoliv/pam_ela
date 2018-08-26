#define _GNU_SOURCE
#define PAM_SM_SESSION
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <stdio.h>
#include <sched.h>
#include <fcntl.h>
#include <errno.h>
#include <netlink/netlink.h>
#include <netlink/route/link.h>
#include <netlink/route/link/veth.h>
#include <netlink/route/link/bridge.h>
#include <netinet/ether.h>
#include <linux/netlink.h>
#include <net/if.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>
#include <utmp.h>
#include <pwd.h>
#include <unistd.h>

#define NETNS_DIR "/var/run/netns/"
#define VETH_PREFIX "veth"
#define MAC_PREFIX "00:11:22:33"

char * int2mac(int value)
{
	char *temp = malloc(5);
	char *final_mac = malloc(17);

	if (value < 0 || value > 65535 )
		return NULL;

	sprintf(temp, "%x", value);
	sprintf(final_mac,"%s:%c%c:%c%c", MAC_PREFIX,temp[0],temp[1],temp[2],temp[3]);
	return final_mac;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv) {
	(void)flags;
	(void)argc;
	(void)argv;
	int fd;
	int err;
	int status;
  	struct passwd *pwd;
	struct nl_sock *sk;
	const char *user;
	char ns_path[512];
	char dhclient_pidfile[512];
	char link_name[50];
	char peer_name[50];
	struct rtnl_link *link = NULL, *peer = NULL, *req = NULL, *bridge = NULL;
	struct nl_cache *cache;
	struct nl_addr *hwaddr;
	char *mac_address;
	pid_t pidf;

	pam_syslog(pamh, LOG_INFO, "Entering PAM_ELA");

	// First let's get the username in order to create the correct namespace
	pam_get_user(pamh, &user, NULL);
	pwd = getpwnam(user);
	strcpy(ns_path,NETNS_DIR);
	strcat(ns_path,user);

	pam_syslog(pamh, LOG_INFO, "Entering PAM_ELA");

	// Define VETH names
	sprintf(link_name,"%s_%d_%d",VETH_PREFIX,pwd->pw_uid,0);
	sprintf(peer_name,"%s_%d_%d",VETH_PREFIX,pwd->pw_uid,1);
	sprintf(dhclient_pidfile,"/var/run/dhclient-%s",link_name);

	pam_syslog(pamh, LOG_INFO,"Link_name: %s", link_name);
	pam_syslog(pamh, LOG_INFO,"Peer_name: %s", peer_name);
	pam_syslog(pamh, LOG_INFO,"DHCLIENT PIDFILE: %s", dhclient_pidfile);

	pam_syslog(pamh, LOG_INFO, "Chemin du namespace: %s\n",ns_path);

	// Create filedescriptor for the namespace
	mkdir(NETNS_DIR, S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH);

	pam_syslog(pamh, LOG_INFO, "Assignation de la mac");
	mac_address = int2mac(pwd->pw_uid);
	if (mac_address == NULL)
	{
		pam_syslog(pamh, LOG_INFO, "MAC incorrecte");
		return PAM_SESSION_ERR;
	}
	else
	{
		pam_syslog(pamh, LOG_INFO, "MAC du user: %s", mac_address);
	}

	
	fd = open(ns_path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Cannot open network namespace: %s\n",
			strerror(errno));
		// Test if the namespace already exists and enter it
		fd = open(ns_path, O_RDONLY|O_CREAT|O_EXCL, 0);
			if (fd < 0) {
				fprintf(stderr, "Could not create %s: %s\n",
					ns_path, strerror(errno));
				return PAM_SESSION_ERR;
			}
		close(fd);	

		pam_syslog(pamh, LOG_INFO, "Network Namespace created");

		// Let's fork a process in order to keep one process in the namespace and the other in the master net namespace
		pidf = fork();

		if (pidf == 0) {
		
			// Child process
			// Let's init and enter the namespace
			if (unshare(CLONE_NEWNET) < 0) {
				fprintf(stderr, "Failed to create a new network namespace: %s\n",
					strerror(errno));
			}	

			// This is where the magic happens (We bind the namespace id on the fd created previously)
			if (mount("/proc/self/ns/net", ns_path, "none", MS_BIND, NULL) < 0) {
				fprintf(stderr, "Bind /proc/self/ns/net -> %s failed: %s\n",
					ns_path, strerror(errno));
			}

			pam_syslog(pamh, LOG_INFO, "Namespace created");

			// Init the veth pair
			sk = nl_socket_alloc();

			if (nl_connect(sk, NETLINK_ROUTE) < 0) {
				return PAM_SESSION_ERR;
			}		

			// This is where the magic happens
			link = rtnl_link_veth_alloc();
			peer = rtnl_link_veth_get_peer(link);

			rtnl_link_set_name(link, link_name);
			rtnl_link_set_name(peer, peer_name);
			rtnl_link_set_ns_pid(peer, getppid());

			pam_syslog(pamh, LOG_INFO, "Iface correctement mise dans le namespace");

			hwaddr = nl_addr_build(AF_LLC, ether_aton(mac_address), ETH_ALEN);
        		rtnl_link_set_addr(link, hwaddr);
			nl_addr_put(hwaddr);

			// Create the vpeth pair
			if (0 != (err = rtnl_link_add(sk, link, NLM_F_CREATE))) {
				nl_perror(err, "Impossible de creer l'interface");
			};

			rtnl_link_put(link); 
			rtnl_link_put(bridge); 

			rtnl_link_alloc_cache(sk, AF_UNSPEC, &cache);
			link = rtnl_link_alloc();
			link = rtnl_link_get_by_name(cache, link_name);


			req = rtnl_link_alloc();
			rtnl_link_set_flags(req, IFF_UP);

			if (0 != (err = rtnl_link_change(sk, link, req, 0))) {
				nl_perror(err, "Impossible de mettre l'interface UP");
			};

			pam_syslog(pamh, LOG_INFO, "Iface UP dans le namespace");
			exit(1);
		}
		else
		{
			// Father process
			// Wait that the child process finished to create the namespace
			wait(&status);
			pam_syslog(pamh, LOG_INFO, "Child process fini");

			// Init the veth pair
			sk = nl_socket_alloc();

			if (nl_connect(sk, NETLINK_ROUTE) < 0) {
				return PAM_SESSION_ERR;
			}		

			pam_syslog(pamh, LOG_INFO, "Socket connectée");

			// Fetch bridge
			rtnl_link_alloc_cache(sk, AF_UNSPEC, &cache);
			link = rtnl_link_alloc();
			bridge = rtnl_link_alloc();
			bridge = rtnl_link_get_by_name(cache, "br0");
			link = rtnl_link_get_by_name(cache, peer_name);

			if(rtnl_link_is_bridge(bridge) == 0) {
				fprintf(stderr, "Link is not a bridge\n");
				return PAM_SESSION_ERR;
			}

			pam_syslog(pamh, LOG_INFO, "On a trouve un bridge");

			if ((err = rtnl_link_enslave(sk, bridge, link)) < 0) {
				pam_syslog(pamh, LOG_INFO, "Impossible d'enslave l'interface");
			}

			pam_syslog(pamh, LOG_INFO, "Interface enslavee");

			req = rtnl_link_alloc();
			rtnl_link_set_flags(req, IFF_UP);

			if (0 != (err = rtnl_link_change(sk, link, req, 0))) {
				nl_perror(err, "Impossible de mettre l'interface UP");
			};

			pam_syslog(pamh, LOG_INFO, "Interface UP");
	
			// Lauch DHCP and we're done
			pam_syslog(pamh, LOG_INFO, "Trying to enter the namespace");

			fd = open(ns_path, O_RDONLY);
			if (fd > 0) {

				if(setns(fd,CLONE_NEWNET) < 0)
				{
					pam_syslog(pamh, LOG_INFO, "Ah bah non");
				}
				else {

					pidf = fork();
					if (pidf == 0)
					{
						pam_syslog(pamh, LOG_INFO, "We are in the namespace launchhing DHCP for %s\n",link_name);
						pam_syslog(pamh, LOG_INFO, "Launching command for iface %s\n",link_name);
						if(execl("/sbin/dhclient","/sbin/dhclient", link_name, "-pf", dhclient_pidfile, NULL) < 0){
							perror("Erreur DHCLIENT:");
						}
					}
					else
					{
						wait(&status);
						return PAM_SUCCESS;
					}
				}
			}
			else
			{
				return PAM_SESSION_ERR;
			}
			
		}

	} else {
		// If we are here, the network namespace exists, just enter into it
		if(setns(fd,CLONE_NEWNET) < 0)
		{
			fprintf(stderr,"Ah bah non: %s\n",strerror(errno));
		}
		else {
			return PAM_SUCCESS;
		}
		
	}

	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv) {
	(void)flags;
	(void)argc;
	(void)argv;
	int ret;
	int err;
	struct nl_sock *sk;
	struct rtnl_link *link = NULL;
	struct nl_cache *cache;
	const char * user;
	char ns_path[512];
	char dhclient_pidfile[512];
	char link_name[50];
  	struct passwd *pwd;
	FILE *f;
	int pid;
	struct utmp *user_entry;
	int logged_users=0;

	pam_syslog(pamh, LOG_INFO, "PAM_ELA closing session");

	// First let's get the username in order to create the correct namespace
	pam_get_user(pamh, &user, NULL);

	user_entry = getutent();
	while(user_entry != NULL)
	{
		if (strcmp(user, &user_entry->ut_name) == 0)
		{
			logged_users++;
		}
		user_entry = getutent();
	}

	pam_syslog(pamh, LOG_INFO, "Logged users; %d",logged_users);

	// Check if we were the last user
	if (logged_users == 0)
	{
		pwd = getpwnam(user);
		sprintf(link_name,"%s_%d_%d",VETH_PREFIX,pwd->pw_uid,0);
		sprintf(dhclient_pidfile,"/var/run/dhclient-%s",link_name);

		// Init the veth pair
		sk = nl_socket_alloc();

		if (nl_connect(sk, NETLINK_ROUTE) < 0) {
			return -1;
		}	

		// let's try to remove the namespace and kill dhcplient
		strcpy(ns_path,NETNS_DIR);
		strcat(ns_path,user);
		pam_syslog(pamh, LOG_INFO, "Suppression de %s\n",ns_path);
		umount2(ns_path, MNT_DETACH);
		if ( (ret = unlink(ns_path) < 0) )
		{
			pam_syslog(pamh, LOG_INFO, "Unable to delete namespace :%d\n",ret);
		}

		// Test if dhclient is running
		pam_syslog(pamh, LOG_INFO, "Test DHCP; %s\n",dhclient_pidfile);
		if ( (f=fopen(dhclient_pidfile,"r")) )
		{
			fscanf(f,"%d", &pid);
			fclose(f);
			pam_syslog(pamh, LOG_INFO, "PID DHCP; %d\n",pid);

			// Kill the proess
			if(kill(pid, 2) == 0)
			{
				pam_syslog(pamh, LOG_INFO, "Process DHCP termine");
			}
			else
			{
				pam_syslog(pamh, LOG_INFO, "DHCP impossible a kill: %d\n",errno);
			};
		}

		// Destroy the link
		rtnl_link_alloc_cache(sk, AF_UNSPEC, &cache);
		link = rtnl_link_alloc();
		link = rtnl_link_get_by_name(cache, link_name);

		if (0 != (err = rtnl_link_delete(sk, link))) {
			pam_syslog(pamh, LOG_INFO, "Unable to destroy link :%d\n",err);
		};

		pam_syslog(pamh, LOG_INFO, "Link destroyed %s\n", link_name);
		
		return PAM_SUCCESS;
	}
	else
	{
		return PAM_SUCCESS;
	}
}

#ifdef PAM_STATIC
struct pam_module _pam_network_namespace_modstruct = {
     "pam_ela",
     NULL,
     NULL,
     NULL,
     pam_sm_open_session,
     pam_sm_close_session,
     NULL
};
#endif

