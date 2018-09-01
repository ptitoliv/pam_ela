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

#define MAC_LENGTH 6*2+5+1
#define MAC_PREFIX "00:11:22:33"

void int2mac(uint16_t value, char *dst)
{
	struct ether_addr mac = { { 0x00, 0x11, 0x22, 0x33, 0, 0 } };

	mac.ether_addr_octet[4] = ( value & 0xFF00 ) >> 8 ;
	mac.ether_addr_octet[5] = value & 0x00FF ;

	strncpy(dst, ether_ntoa(&mac), MAC_LENGTH);
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
				   int argc, const char **argv) {
	(void)flags;
	(void)argc;
	(void)argv;
	int fd, err, status;
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
	char mac_address [MAC_LENGTH];
	pid_t pidf;

	pam_syslog(pamh, LOG_INFO, "Entering PAM_ELA");

	// First let's get the username in order to create the correct namespace
	err = pam_get_user(pamh, &user, NULL);
	if (err != PAM_SUCCESS)
	{
		pam_syslog(pamh, LOG_INFO, "Failed to get username: %s", pam_strerror(pamh, err));
		return PAM_SESSION_ERR;
	}
	pwd = getpwnam(user);
	if (pwd == NULL)
	{
		pam_syslog(pamh, LOG_INFO, "Failed to get user passwd entry: %s", strerror(errno));
		return PAM_SESSION_ERR;
	}

	strcpy(ns_path, NETNS_DIR);
	if (strlen(ns_path)+strlen(user)+1 > 512)
	{
		pam_syslog(pamh, LOG_INFO, "Unable to build namespace length for %s-%s: too many chars", ns_path, user);
		return PAM_SESSION_ERR;
	}
	strcat(ns_path, user);

	pam_syslog(pamh, LOG_INFO, "Entering PAM_ELA");

	// Define VETH names
	snprintf(link_name, 50, "%s_%d_%d", VETH_PREFIX, pwd->pw_uid, 0);
	snprintf(peer_name, 50, "%s_%d_%d", VETH_PREFIX, pwd->pw_uid, 1);
	snprintf(dhclient_pidfile, 512, "/var/run/dhclient-%s", link_name);

	pam_syslog(pamh, LOG_INFO, "Link_name: %s", link_name);
	pam_syslog(pamh, LOG_INFO, "Peer_name: %s", peer_name);
	pam_syslog(pamh, LOG_INFO, "DHCLIENT PIDFILE: %s", dhclient_pidfile);

	pam_syslog(pamh, LOG_INFO, "Chemin du namespace: %s\n", ns_path);

	// Create filedescriptor for the namespace
	mkdir(NETNS_DIR, S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH);

	pam_syslog(pamh, LOG_INFO, "Assignation de la mac");

	int2mac(pwd->pw_uid, mac_address);
	pam_syslog(pamh, LOG_INFO, "MAC du user: %s", mac_address);

	fd = open(ns_path, O_RDONLY);
	if (fd > 0)
	{
		// If we are here, the network namespace exists, just enter into it
		if(setns(fd,CLONE_NEWNET) < 0)
		{
			pam_syslog(pamh, LOG_INFO, "Network namespace exists but unusable: %s\n",strerror(errno));
			return PAM_SESSION_ERR;
		}
		else
		{
			return PAM_SUCCESS;
		}
	}

	// Create the namespace enter it
	fd = open(ns_path, O_RDONLY|O_CREAT|O_EXCL, 0);
	if (fd < 0)
	{
		pam_syslog(pamh, LOG_INFO, "Network namespace creation failed: %s\n",strerror(errno));
		return PAM_SESSION_ERR;
	}
	close(fd);

	pam_syslog(pamh, LOG_INFO, "Network Namespace created");

	// Let's fork a process in order to keep one process in the namespace and the other in the master net namespace
	pidf = fork();

	if (pidf == 0)
	{
		// Child process
		// Let's init and enter the namespace
		if (unshare(CLONE_NEWNET) < 0)
		{
			fprintf(stderr, "Failed to create a new network namespace: %s\n",
				strerror(errno));
			exit (PAM_SESSION_ERR);
		}

		// This is where the magic happens (We bind the namespace id on the fd created previously)
		if (mount("/proc/self/ns/net", ns_path, "none", MS_BIND, NULL) < 0)
		{
			fprintf(stderr, "Bind /proc/self/ns/net -> %s failed: %s\n",
				ns_path, strerror(errno));
			exit (PAM_SESSION_ERR);
		}

		pam_syslog(pamh, LOG_INFO, "Namespace created");

		// Init the veth pair
		sk = nl_socket_alloc();

		if (nl_connect(sk, NETLINK_ROUTE) < 0)
		{
			exit (PAM_SESSION_ERR);
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
		if (0 != (err = rtnl_link_add(sk, link, NLM_F_CREATE)))
		{
			nl_perror(err, "Impossible de creer l'interface");
			exit (PAM_SESSION_ERR);
		}

		rtnl_link_put(link);
		rtnl_link_put(bridge);

		rtnl_link_alloc_cache(sk, AF_UNSPEC, &cache);
		link = rtnl_link_alloc();
		link = rtnl_link_get_by_name(cache, link_name);

		req = rtnl_link_alloc();
		rtnl_link_set_flags(req, IFF_UP);

		if (0 != (err = rtnl_link_change(sk, link, req, 0)))
		{
			nl_perror(err, "Impossible de mettre l'interface UP");
			exit (PAM_SESSION_ERR);
		}

		pam_syslog(pamh, LOG_INFO, "Iface UP dans le namespace");
		exit(0);
	}
	else
	{
		// Father process
		// Wait that the child process finished to create the namespace
		pid_t childstatus = waitpid(pidf, &status, 0);

		if (childstatus == -1)
		{
			pam_syslog(pamh, LOG_INFO, "Erreur lors de l'attente du child: %s", strerror(errno));
			return PAM_SESSION_ERR;
		}
		else
		{
			pam_syslog(pamh, LOG_INFO, "Child process fini avec: %d", WEXITSTATUS(status));
			if (0 != WEXITSTATUS(status))
				return WEXITSTATUS(status);
		}

		// Init the veth pair
		sk = nl_socket_alloc();

		if (nl_connect(sk, NETLINK_ROUTE) < 0)
		{
			return PAM_SESSION_ERR;
		}

		pam_syslog(pamh, LOG_INFO, "Socket connectée");

		// Fetch bridge
		rtnl_link_alloc_cache(sk, AF_UNSPEC, &cache);
		link = rtnl_link_alloc();
		bridge = rtnl_link_alloc();
		bridge = rtnl_link_get_by_name(cache, "br0");
		link = rtnl_link_get_by_name(cache, peer_name);

		if (rtnl_link_is_bridge(bridge) == 0)
		{
			pam_syslog(pamh, LOG_INFO, "Error: Link is not a bridge\n");
			return PAM_SESSION_ERR;
		}

		pam_syslog(pamh, LOG_INFO, "On a trouve un bridge");

		if ((err = rtnl_link_enslave(sk, bridge, link)) < 0)
		{
			pam_syslog(pamh, LOG_INFO, "Impossible d'enslave l'interface");
			return PAM_SESSION_ERR;
		}

		pam_syslog(pamh, LOG_INFO, "Interface enslavee");

		req = rtnl_link_alloc();
		rtnl_link_set_flags(req, IFF_UP);

		if (0 != (err = rtnl_link_change(sk, link, req, 0)))
		{
			pam_syslog(pamh, LOG_INFO, "Erreur lors de l'activation de l'interface: %s", nl_geterror(err));
			return PAM_SESSION_ERR;
		}

		pam_syslog(pamh, LOG_INFO, "Interface UP");

		// Launch DHCP and we're done
		pam_syslog(pamh, LOG_INFO, "Trying to enter the namespace");

		fd = open(ns_path, O_RDONLY);
		if (fd < 0)
		{
			pam_syslog(pamh, LOG_INFO, "Erreur lors de l'ouverture du namespace: %s", strerror(errno));
			return PAM_SESSION_ERR;
		}

		// Associate with the namespace
		if(setns(fd,CLONE_NEWNET) < 0)
		{
			pam_syslog(pamh, LOG_INFO, "Erreur lors de l'association au namespace: %s", strerror(errno));
			return PAM_SESSION_ERR;
		}

		// Fork to call dhclient
		pidf = fork();
		if (pidf == 0)
		{
			pam_syslog(pamh, LOG_INFO, "We are in the namespace launchhing DHCP for %s\n", link_name);
			pam_syslog(pamh, LOG_INFO, "Launching command for iface %s\n", link_name);
			if (execl("/sbin/dhclient","/sbin/dhclient", link_name, "-pf", dhclient_pidfile, NULL) < 0)
			{
				pam_syslog(pamh, LOG_INFO, "Erreur DHCLIENT: %s", strerror(errno));
				exit(PAM_SESSION_ERR);
			}
			else
			{
				exit(0);
			}
		}
		else
		{
			// Attente du retour du dhclient
			pid_t childstatus = waitpid(pidf, &status, 0);

			if (childstatus == -1)
			{
				pam_syslog(pamh, LOG_INFO, "Erreur lors de l'attente du child: %s", strerror(errno));
				return PAM_SESSION_ERR;
			}
			else
			{
				pam_syslog(pamh, LOG_INFO, "Child process fini avec: %d", WEXITSTATUS(status));
				if (0 != WEXITSTATUS(status))
					return WEXITSTATUS(status);
			}
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
	int ret, err, len_user;
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
	err = pam_get_user(pamh, &user, NULL);
	if (err != PAM_SUCCESS)
	{
		pam_syslog(pamh, LOG_INFO, "Failed to get username: %s", pam_strerror(pamh, err));
		return PAM_SESSION_ERR;
	}
	pwd = getpwnam(user);
	if (pwd == NULL)
	{
		pam_syslog(pamh, LOG_INFO, "Failed to get user passwd entry: %s", strerror(errno));
		return PAM_SESSION_ERR;
	}

	len_user = strlen(user);
	while ((user_entry = getutent()))
	{
		// utmp aren't safe for str comparison
		ret = strnlen(user_entry->ut_name, UT_NAMESIZE);

		if (ret > len_user)
			continue;

		if (memcmp(user, user_entry->ut_name, ret) == 0)
		{
			logged_users++;
		}
	}

	pam_syslog(pamh, LOG_INFO, "Active sessions for user %s: %d",user, logged_users);

	// Check if we are the last user
	if (logged_users == 1)
	{
		sprintf(link_name,"%s_%d_%d",VETH_PREFIX,pwd->pw_uid,0);
		sprintf(dhclient_pidfile,"/var/run/dhclient-%s",link_name);

		// Init the veth pair
		sk = nl_socket_alloc();

		if (nl_connect(sk, NETLINK_ROUTE) < 0)
		{
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
			}
		}

		// Destroy the link
		rtnl_link_alloc_cache(sk, AF_UNSPEC, &cache);
		link = rtnl_link_alloc();
		link = rtnl_link_get_by_name(cache, link_name);

		if (0 != (err = rtnl_link_delete(sk, link)))
		{
			pam_syslog(pamh, LOG_INFO, "Unable to destroy link :%d\n",err);
		}

		pam_syslog(pamh, LOG_INFO, "Link destroyed %s\n", link_name);
	}

	return PAM_SUCCESS;
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

// Local Variables:
// c-basic-offset: 8
// indent-tabs-mode: t
// End:
