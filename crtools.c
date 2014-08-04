#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <string.h>
#include <ctype.h>

#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <dlfcn.h>

#include "asm/types.h"

#include "compiler.h"
#include "crtools.h"
#include "cr_options.h"
#include "sockets.h"
#include "syscall.h"
#include "files.h"
#include "sk-inet.h"
#include "net.h"
#include "version.h"
#include "page-xfer.h"
#include "tty.h"
#include "file-lock.h"
#include "cr-service.h"
#include "plugin.h"
#include "mount.h"

struct cr_options opts;

void init_opts(void)
{
	memset(&opts, 0, sizeof(opts));

	/* Default options */
	opts.final_state = TASK_DEAD;
	INIT_LIST_HEAD(&opts.veth_pairs);
	INIT_LIST_HEAD(&opts.scripts);
	INIT_LIST_HEAD(&opts.ext_mounts);

	opts.cpu_cap = CPU_CAP_ALL;
	opts.restore_cgroups = true;
}

static int parse_ns_string(const char *ptr)
{
	const char *end = ptr + strlen(ptr);

	do {
		if (ptr[3] != ',' && ptr[3] != '\0')
			goto bad_ns;
		if (!strncmp(ptr, "uts", 3))
			opts.rst_namespaces_flags |= CLONE_NEWUTS;
		else if (!strncmp(ptr, "ipc", 3))
			opts.rst_namespaces_flags |= CLONE_NEWIPC;
		else if (!strncmp(ptr, "mnt", 3))
			opts.rst_namespaces_flags |= CLONE_NEWNS;
		else if (!strncmp(ptr, "pid", 3))
			opts.rst_namespaces_flags |= CLONE_NEWPID;
		else if (!strncmp(ptr, "net", 3))
			opts.rst_namespaces_flags |= CLONE_NEWNET;
		else
			goto bad_ns;
		ptr += 4;
	} while (ptr < end);
	return 0;

bad_ns:
	pr_msg("Error: unknown namespace: %s\n", ptr);
	return -1;
}

static int parse_cpu_cap(struct cr_options *opts, const char *optarg)
{
	bool inverse = false;

#define ____cpu_set_cap(__opts, __cap, __inverse)	\
	do {						\
		if ((__inverse))			\
			(__opts)->cpu_cap &= ~(__cap);	\
		else					\
			(__opts)->cpu_cap |=  (__cap);	\
	} while (0)

	for (; *optarg; optarg++) {
		if (optarg[0] == '^') {
			inverse = !inverse;
			continue;
		} else if (optarg[0] == ',') {
			inverse = false;
			continue;
		}

		if (!strncmp(optarg, "fpu", 3))
			____cpu_set_cap(opts, CPU_CAP_FPU, inverse);
		if (!strncmp(optarg, "all", 3))
			____cpu_set_cap(opts, CPU_CAP_ALL, inverse);
		else
			goto Esyntax;
	}
#undef ____cpu_set_cap

	return 0;

Esyntax:
	pr_err("Unknown FPU mode `%s' selected\n", optarg);
	return -1;
}

int main(int argc, char *argv[])
{
	pid_t pid = 0, tree_id = 0;
	int ret = -1;
	bool usage_error = true;
	bool has_exec_cmd = false;
	int opt, idx;
	int log_level = LOG_UNSET;
	char *imgs_dir = ".";
	char *work_dir = NULL;
	static const char short_opts[] = "dsRf:F:t:p:hcD:o:n:v::xVr:jlW:L:M:";
	static struct option long_opts[] = {
		{ "tree", required_argument, 0, 't' },
		{ "pid", required_argument, 0, 'p' },
		{ "leave-stopped", no_argument, 0, 's' },
		{ "leave-running", no_argument, 0, 'R' },
		{ "restore-detached", no_argument, 0, 'd' },
		{ "daemon", no_argument, 0, 'd' },
		{ "contents", no_argument, 0, 'c' },
		{ "file", required_argument, 0, 'f' },
		{ "fields", required_argument, 0, 'F' },
		{ "images-dir", required_argument, 0, 'D' },
		{ "work-dir", required_argument, 0, 'W' },
		{ "log-file", required_argument, 0, 'o' },
		{ "namespaces", required_argument, 0, 'n' },
		{ "root", required_argument, 0, 'r' },
		{ USK_EXT_PARAM, no_argument, 0, 'x' },
		{ "help", no_argument, 0, 'h' },
		{ SK_EST_PARAM, no_argument, 0, 42 },
		{ "close", required_argument, 0, 43 },
		{ "log-pid", no_argument, 0, 44},
		{ "version", no_argument, 0, 'V'},
		{ "evasive-devices", no_argument, 0, 45},
		{ "pidfile", required_argument, 0, 46},
		{ "veth-pair", required_argument, 0, 47},
		{ "action-script", required_argument, 0, 49},
		{ LREMAP_PARAM, no_argument, 0, 41},
		{ OPT_SHELL_JOB, no_argument, 0, 'j'},
		{ OPT_FILE_LOCKS, no_argument, 0, 'l'},
		{ "page-server", no_argument, 0, 50},
		{ "address", required_argument, 0, 51},
		{ "port", required_argument, 0, 52},
		{ "prev-images-dir", required_argument, 0, 53},
		{ "ms", no_argument, 0, 54},
		{ "track-mem", no_argument, 0, 55},
		{ "auto-dedup", no_argument, 0, 56},
		{ "libdir", required_argument, 0, 'L'},
		{ "cpu-cap", required_argument, 0, 57},
		{ "force-irmap", no_argument, 0, 58},
		{ "ext-mount-map", required_argument, 0, 'M'},
		{ "exec-cmd", no_argument, 0, 59},
		{ "no-restore-cgroups", no_argument, 0, 60},
		{ },
	};

	BUILD_BUG_ON(PAGE_SIZE != PAGE_IMAGE_SIZE);

	cr_pb_init();
	restrict_uid(getuid(), getgid());

	if (argc < 2)
		goto usage;

	init_opts();

	if (init_service_fd())
		return 1;

	if (!strcmp(argv[1], "swrk")) {
		/*
		 * This is to start criu service worker from libcriu calls.
		 * The usage is "criu swrk <fd>" and is not for CLI/scripts.
		 * The arguments semantics can change at any tyme with the
		 * corresponding lib call change.
		 */
		opts.swrk_restore = true;
		return cr_service_work(atoi(argv[2]));
	}

	while (1) {
		idx = -1;
		opt = getopt_long(argc, argv, short_opts, long_opts, &idx);
		if (opt == -1)
			break;

		switch (opt) {
		case 's':
			opts.final_state = TASK_STOPPED;
			break;
		case 'R':
			opts.final_state = TASK_ALIVE;
			break;
		case 'x':
			opts.ext_unix_sk = true;
			break;
		case 'p':
			pid = atoi(optarg);
			if (pid <= 0)
				goto bad_arg;
			break;
		case 't':
			tree_id = atoi(optarg);
			if (tree_id <= 0)
				goto bad_arg;
			break;
		case 'c':
			opts.show_pages_content	= true;
			break;
		case 'f':
			opts.show_dump_file = optarg;
			break;
		case 'F':
			opts.show_fmt = optarg;
			break;
		case 'r':
			opts.root = optarg;
			break;
		case 'd':
			opts.restore_detach = true;
			break;
		case 'D':
			imgs_dir = optarg;
			break;
		case 'W':
			work_dir = optarg;
			break;
		case 'o':
			opts.output = optarg;
			break;
		case 'n':
			if (parse_ns_string(optarg))
				goto bad_arg;
			break;
		case 'v':
			if (log_level == LOG_UNSET)
				log_level = 0;
			if (optarg) {
				if (optarg[0] == 'v')
					/* handle -vvvvv */
					log_level += strlen(optarg) + 1;
				else
					log_level = atoi(optarg);
			} else
				log_level++;
			break;
		case 41:
			pr_info("Will allow link remaps on FS\n");
			opts.link_remap_ok = true;
			break;
		case 42:
			pr_info("Will dump TCP connections\n");
			opts.tcp_established_ok = true;
			break;
		case 43: {
			int fd;

			fd = atoi(optarg);
			pr_info("Closing fd %d\n", fd);
			close(fd);
			break;
		}
		case 44:
			opts.log_file_per_pid = 1;
			break;
		case 45:
			opts.evasive_devices = true;
			break;
		case 46:
			opts.pidfile = optarg;
			break;
		case 47:
			{
				char *aux;

				aux = strchr(optarg, '=');
				if (aux == NULL)
					goto bad_arg;

				*aux = '\0';
				if (veth_pair_add(optarg, aux + 1))
					return 1;
			}
			break;
		case 49:
			{
				struct script *script;

				script = xmalloc(sizeof(struct script));
				if (script == NULL)
					return 1;

				script->path = optarg;
				list_add(&script->node, &opts.scripts);
			}
			break;
		case 50:
			opts.use_page_server = true;
			break;
		case 51:
			opts.addr = optarg;
			break;
		case 52:
			opts.ps_port = htons(atoi(optarg));
			if (!opts.ps_port)
				goto bad_arg;
			break;
		case 'j':
			opts.shell_job = true;
			break;
		case 'l':
			opts.handle_file_locks = true;
			break;
		case 53:
			opts.img_parent = optarg;
			break;
		case 55:
			opts.track_mem = true;
			break;
		case 56:
			opts.auto_dedup = true;
			break;
		case 57:
			if (parse_cpu_cap(&opts, optarg))
				goto usage;
			break;
		case 58:
			opts.force_irmap = true;
			break;
		case 54:
			opts.check_ms_kernel = true;
			break;
		case 'L':
			opts.libdir = optarg;
			break;
		case 59:
			has_exec_cmd = true;
			break;
		case 60:
			opts.restore_cgroups = false;
			break;
		case 'M':
			{
				char *aux;

				aux = strchr(optarg, ':');
				if (aux == NULL)
					goto bad_arg;

				*aux = '\0';
				if (ext_mount_add(optarg, aux + 1))
					return 1;
			}
			break;
		case 'V':
			pr_msg("Version: %s\n", CRIU_VERSION);
			if (strcmp(CRIU_GITID, "0"))
				pr_msg("GitID: %s\n", CRIU_GITID);
			return 0;
		case 'h':
			usage_error = false;
			goto usage;
		default:
			goto usage;
		}
	}

	if (work_dir == NULL)
		work_dir = imgs_dir;

	if (optind >= argc) {
		pr_msg("Error: command is required\n");
		goto usage;
	}

	if (has_exec_cmd) {
		if (argc - optind <= 1) {
			pr_msg("Error: --exec-cmd requires a command\n");
			goto usage;
		}

		if (strcmp(argv[optind], "restore")) {
			pr_msg("Error: --exec-cmd is available for the restore command only\n");
			goto usage;
		}

		if (opts.restore_detach) {
			pr_msg("Error: --restore-detached and --exec-cmd cannot be used together\n");
			goto usage;
		}

		opts.exec_cmd = xmalloc((argc - optind) * sizeof(char *));
		memcpy(opts.exec_cmd, &argv[optind + 1], (argc - optind - 1) * sizeof(char *));
		opts.exec_cmd[argc - optind - 1] = NULL;
	}

	/* We must not open imgs dir, if service is called */
	if (strcmp(argv[optind], "service")) {
		ret = open_image_dir(imgs_dir);
		if (ret < 0)
			return 1;
	}

	if (chdir(work_dir)) {
		pr_perror("Can't change directory to %s", work_dir);
		return 1;
	}

	log_set_loglevel(log_level);

	if (log_init(opts.output))
		return 1;

	if (opts.img_parent)
		pr_info("Will do snapshot from %s\n", opts.img_parent);

	if (!strcmp(argv[optind], "dump")) {
		if (!tree_id)
			goto opt_pid_missing;
		return cr_dump_tasks(tree_id);
	}

	if (!strcmp(argv[optind], "pre-dump")) {
		if (!tree_id)
			goto opt_pid_missing;

		return cr_pre_dump_tasks(tree_id) != 0;
	}

	if (!strcmp(argv[optind], "restore")) {
		if (tree_id)
			pr_warn("Using -t with criu restore is obsoleted\n");

		ret = cr_restore_tasks();
		if (ret == 0 && opts.exec_cmd) {
			close_pid_proc();
			execvp(opts.exec_cmd[0], opts.exec_cmd);
			pr_perror("Failed to exec command %s", opts.exec_cmd[0]);
			ret = 1;
		}

		return ret != 0;
	}

	if (!strcmp(argv[optind], "show"))
		return cr_show(pid) != 0;

	if (!strcmp(argv[optind], "check"))
		return cr_check() != 0;

	if (!strcmp(argv[optind], "exec")) {
		if (!pid)
			pid = tree_id; /* old usage */
		if (!pid)
			goto opt_pid_missing;
		return cr_exec(pid, argv + optind + 1) != 0;
	}

	if (!strcmp(argv[optind], "page-server"))
		return cr_page_server(opts.restore_detach) > 0 ? 0 : 1;

	if (!strcmp(argv[optind], "service"))
		return cr_service(opts.restore_detach);

	if (!strcmp(argv[optind], "dedup"))
		return cr_dedup() != 0;

	pr_msg("Error: unknown command: %s\n", argv[optind]);
usage:
	pr_msg("\n"
"Usage:\n"
"  criu dump|pre-dump -t PID [<options>]\n"
"  criu restore [<options>]\n"
"  criu show (-D DIR)|(-f FILE) [<options>]\n"
"  criu check [--ms]\n"
"  criu exec -p PID <syscall-string>\n"
"  criu page-server\n"
"  criu service [<options>]\n"
"  criu dedup\n"
"\n"
"Commands:\n"
"  dump           checkpoint a process/tree identified by pid\n"
"  pre-dump       pre-dump task(s) minimizing their frozen time\n"
"  restore        restore a process/tree\n"
"  show           show dump file(s) contents\n"
"  check          checks whether the kernel support is up-to-date\n"
"  exec           execute a system call by other task\n"
"  page-server    launch page server\n"
"  service        launch service\n"
"  dedup          remove duplicates in memory dump\n"
	);

	if (usage_error) {
		pr_msg("\nTry -h|--help for more info\n");
		return 1;
	}

	pr_msg("\n"
"Dump/Restore options:\n"
"\n"
"* Generic:\n"
"  -t|--tree PID         checkpoint a process tree identified by PID\n"
"  -d|--restore-detached detach after restore\n"
"  -s|--leave-stopped    leave tasks in stopped state after checkpoint\n"
"  -R|--leave-running    leave tasks in running state after checkpoint\n"
"  -D|--images-dir DIR   directory for image files\n"
"     --pidfile FILE     write root task, service or page-server pid to FILE\n"
"  -W|--work-dir DIR     directory to cd and write logs/pidfiles/stats to\n"
"                        (if not specified, value of --images-dir is used)\n"
"     --cpu-cap CAP      require certain cpu capability. CAP: may be one of:\n"
"                        'fpu','all'. To disable capability, prefix it with '^'.\n"
"     --exec-cmd         execute the command specified after '--' on successful\n"
"                        restore making it the parent of the restored process\n"
"\n"
"* Special resources support:\n"
"  -x|--" USK_EXT_PARAM "      allow external unix connections\n"
"     --" SK_EST_PARAM "  checkpoint/restore established TCP connections\n"
"  -r|--root PATH        change the root filesystem (when run in mount namespace)\n"
"  --evasive-devices     use any path to a device file if the original one\n"
"                        is inaccessible\n"
"  --veth-pair IN=OUT    map inside veth device name to outside one\n"
"  --link-remap          allow to link unlinked files back when possible\n"
"  --action-script FILE  add an external action script\n"
"  -j|--" OPT_SHELL_JOB "        allow to dump and restore shell jobs\n"
"  -l|--" OPT_FILE_LOCKS "       handle file locks, for safety, only used for container\n"
"  -L|--libdir           path to a plugin directory (by default " CR_PLUGIN_DEFAULT ")\n"
"  --force-irmap         force resolving names for inotify/fsnotify watches\n"
"  -M|--ext-mount-map KEY:VALUE\n"
"                        add external mount mapping\n"
"\n"
"* Logging:\n"
"  -o|--log-file FILE    log file name\n"
"     --log-pid          enable per-process logging to separate FILE.pid files\n"
"  -v[NUM]               set logging level (higher level means more output):\n"
"                          -v1|-v    - only errors and messages\n"
"                          -v2|-vv   - also warnings (default level)\n"
"                          -v3|-vvv  - also information messages and timestamps\n"
"                          -v4|-vvvv - lots of debug\n"
"\n"
"* Memory dumping options:\n"
"  --track-mem           turn on memory changes tracker in kernel\n"
"  --prev-images-dir DIR path to images from previous dump (relative to -D)\n"
"  --page-server         send pages to page server (see options below as well)\n"
"  --auto-dedup          when used on dump it will deduplicate \"old\" data in\n"
"                        pages images of previous dump\n"
"                        when used on restore, as soon as page is restored, it\n"
"                        will be punched from the image.\n"
"\n"
"Page/Service server options:\n"
"  --address ADDR        address of server or service\n"
"  --port PORT           port of page server\n"
"  -d|--daemon           run in the background after creating socket\n"
"\n"
"Show options:\n"
"  -f|--file FILE        show contents of a checkpoint file\n"
"  -F|--fields FIELDS    show specified fields (comma separated)\n"
"  -D|--images-dir DIR   directory where to get images from\n"
"  -c|--contents         show contents of pages dumped in hexdump format\n"
"  -p|--pid PID          show files relevant to PID (filter -D flood)\n"
"\n"
"Other options:\n"
"  -h|--help             show this text\n"
"  -V|--version          show version\n"
"     --ms               don't check not yet merged kernel features\n"
	);

	return 0;

opt_pid_missing:
	pr_msg("Error: pid not specified\n");
	return 1;

bad_arg:
	if (idx < 0) /* short option */
		pr_msg("Error: invalid argument for -%c: %s\n",
				opt, optarg);
	else /* long option */
		pr_msg("Error: invalid argument for --%s: %s\n",
				long_opts[idx].name, optarg);
	return 1;
}
