
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <argp.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#define VERSION "0.0.1"
#define AUTHOR_EMAIL "sergey@de-bs.ru"


#define STR_EXPAND(tok) #tok
#define STR(tok) STR_EXPAND(tok)

#define CRITICAL_DEFAULT   20
#define WARNING_DEFAULT    40

#define PROC_CONNTR_MAX "/proc/sys/net/nf_conntrack_max"


const char *argp_program_version = VERSION;
const char *argp_program_bug_address = AUTHOR_EMAIL;

static char args_doc[] = "empty";

static char doc[] =
"nagios plugin: check number of conntrack states ";

static struct argp_option options[] = {
	{"critical", 'c', "CRT", 0, "critical (free, %), default - "STR(CRITICAL_DEFAULT) },
	{"warning", 'w', "WRN", 0, "warnings (free, %), default - "STR(WARNING_DEFAULT) },
	{ 0 }
};

struct arguments
{
	char *args;
	int   critical;
	int   warning;
} ;

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
	struct arguments *arguments = state->input;
	
	switch (key)
	{
	case 'c':
		arguments->critical = atoi ((char *)arg);
		break;
	case 'w':
		arguments->warning = atoi ((char *)arg);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc, 0, 0, 0};

static unsigned long st;

static int cb(enum nf_conntrack_msg_type type,
	      struct nf_conntrack *ct,
	      void *data)
{
	st++;
	return NFCT_CB_CONTINUE;
}


static int get_conntr (u_int32_t family )
{
        struct nfct_handle *h;
	int ret = -1;
	st = 0;

        h = nfct_open(CONNTRACK, 0);
        if (!h) {
                perror("nfct_open");
                return ret;
        }

        nfct_callback_register(h, NFCT_T_ALL, cb, NULL);
        ret = nfct_query(h, NFCT_Q_DUMP, &family);

	nfct_close(h);

	return ret == 0 ? st : ret;
}

int main(int argc, char ** argv)
{
	unsigned long st_ipv4 = 0;
	unsigned long st_ipv6 = 0;
	int exit_code = 0;
	u_int32_t family;

	char fbuf[32] = {};
	unsigned long conntr_max = 0;

	struct arguments arguments;
	arguments.critical = CRITICAL_DEFAULT;
	arguments.warning  = WARNING_DEFAULT;

	st = 0;



	argp_parse (&argp, argc, argv, 0 , 0, &arguments);

	if (arguments.critical > 100)
	{
		printf("Critical can not be more than 100%%\n");
		exit(1);
	}

	if (arguments.warning > 100)
	{
		printf("Warning can not be more than 100%%\n");
		exit(1);
	}

	if (arguments.warning < arguments.critical)
	{
		printf("Warning can not be less than Critical\n");
		exit(1);
	}



	FILE *fd = fopen(PROC_CONNTR_MAX,"r");

	if (fd == NULL) {
		perror("Ensure all required modules loaded\n");
		exit(1);
	}

	if ( fgets(fbuf,32,fd) == NULL ) {
		fclose(fd);
		perror("Error: can not read proc.\n");
		exit(1);
	}
	fclose(fd);

	conntr_max = atol(fbuf);


        family = AF_INET;
	st_ipv4 = get_conntr(family);

	if (st_ipv4 == -1)
	{
		printf("(%lu)(%s)\n", st_ipv4, strerror(errno));
		exit_code = -1;
	}

        family = AF_INET6;
	st_ipv6 = get_conntr(family);

	if (st_ipv6 == -1)
	{
		printf("(%lu)(%s)\n", st_ipv6, strerror(errno));
		exit_code = -1;
	}


	if ((( conntr_max - (st_ipv4 + st_ipv6)) * 100 / conntr_max ) <= arguments.critical ) {
		printf("ERROR : ");
	 	exit_code = 3;
	
	} else if ((( conntr_max - (st_ipv4 + st_ipv6)) * 100 / conntr_max ) <= arguments.warning ) {
	 	printf("WARN : ");
	 	exit_code = 2;
	
	} else {
	 	printf("OK : ");
	}

	printf("%lu states | conntrack4_states=%lu conntrack6_states=%lu conntrack_max=%lu",
		st_ipv4 + st_ipv6,st_ipv4, st_ipv6 ,conntr_max);

	exit(exit_code);
}
