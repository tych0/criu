#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "asm/types.h"
#include "namespaces.h"
#include "sysctl.h"
#include "util.h"

/* These are the namespaces we know how to restore in various ways.
 */
#define KNOWN_NS_MASK (CLONE_NEWUTS | CLONE_NEWNET | CLONE_NEWIPC)

struct sysctl_userns_req {
	int			op;
	unsigned int		ns;
	size_t			nr_req;
	struct sysctl_req	*reqs;
};

#define __SYSCTL_OP(__ret, __fd, __req, __type, __nr, __op)		\
do {									\
	if (__op == CTL_READ)						\
		__ret = sysctl_read_##__type(__fd, __req,		\
					     (__type *)(__req)->arg,	\
					     __nr);			\
	else if (__op == CTL_WRITE)					\
		__ret = sysctl_write_##__type(__fd, __req,		\
					      (__type *)(__req)->arg,	\
					      __nr);			\
	else								\
		__ret = -1;						\
} while (0)

#define GEN_SYSCTL_READ_FUNC(__type, __conv)				\
static int sysctl_read_##__type(int fd,					\
				struct sysctl_req *req,			\
				__type *arg,				\
				int nr)					\
{									\
	char buf[1024] = {0};						\
	int i, ret = -1;						\
	char *p = buf;							\
									\
	ret = read(fd, buf, sizeof(buf));				\
	if (ret < 0) {							\
		pr_perror("Can't read %s", req->name);			\
		ret = -1;						\
		goto err;						\
	}								\
									\
	for (i = 0; i < nr && p < buf + sizeof(buf); p++, i++)		\
		((__type *)arg)[i] = __conv(p, &p, 10);			\
									\
	if (i != nr) {							\
		pr_err("Not enough params for %s (%d != %d)\n",		\
			req->name, i, nr);				\
		goto err;						\
	}								\
									\
	ret = 0;							\
									\
err:									\
	return ret;							\
}

#define GEN_SYSCTL_WRITE_FUNC(__type, __fmt)				\
static int sysctl_write_##__type(int fd,				\
				 struct sysctl_req *req,		\
				 __type *arg,				\
				 int nr)				\
{									\
	char buf[1024];							\
	int i, ret = -1;						\
	int off = 0;							\
									\
	for (i = 0; i < nr && off < sizeof(buf) - 1; i++) {		\
		snprintf(&buf[off], sizeof(buf) - off, __fmt, arg[i]);	\
		off += strlen(&buf[off]);				\
	}								\
									\
	if (i != nr) {							\
		pr_err("Not enough space for %s (%d != %d)\n",		\
			req->name, i, nr);				\
		goto err;						\
	}								\
									\
	/* trailing spaces in format */					\
	while (off > 0 && isspace(buf[off - 1]))			\
		off--;							\
	buf[off + 0] = '\n';						\
	ret = write(fd, buf, off + 1);					\
	if (ret < 0) {							\
		pr_perror("Can't write %s", req->name);			\
		ret = -1;						\
		goto err;						\
	}								\
									\
	ret = 0;							\
err:									\
	return ret;							\
}

GEN_SYSCTL_READ_FUNC(u32, strtoul);
GEN_SYSCTL_READ_FUNC(u64, strtoull);
GEN_SYSCTL_READ_FUNC(s32, strtol);

GEN_SYSCTL_WRITE_FUNC(u32, "%u ");
GEN_SYSCTL_WRITE_FUNC(u64, "%"PRIu64" ");
GEN_SYSCTL_WRITE_FUNC(s32, "%d ");

static int
sysctl_write_char(int fd, struct sysctl_req *req, char *arg, int nr)
{
	pr_debug("%s nr %d\n", req->name, nr);
	if (dprintf(fd, "%s\n", arg) < 0)
		return -1;

	return 0;
}

static int
sysctl_read_char(int fd, struct sysctl_req *req, char *arg, int nr)
{
	int ret = -1;

	pr_debug("%s nr %d\n", req->name, nr);
	ret = read(fd, arg, nr);
	if (ret < 0) {
		pr_perror("Can't read %s", req->name);
		goto err;
	}
	ret = 0;

err:
	return ret;
}

static int sysctl_userns_arg_size(int type)
{
	switch(CTL_TYPE(type)) {
	case __CTL_U32A:
		return sizeof(u32) * CTL_LEN(type);
	case CTL_U32:
		return sizeof(u32);
	case CTL_32:
		return sizeof(s32);
	case __CTL_U64A:
		return sizeof(u64) * CTL_LEN(type);
	case CTL_U64:
		return sizeof(u64);
	case __CTL_STR:
		return sizeof(char) * CTL_LEN(type) + 1;
	default:
		pr_err("unknown arg type %d\n", type);

		/* Ensure overflow to cause an error */
		return MAX_UNSFD_MSG_SIZE;
	}
}

/*
 * In order to avoid lots of opening of /proc/sys for each struct sysctl_req,
 * we encode each array of sysctl_reqs into one contiguous region of memory so
 * it can be passed via userns_call if necessary. It looks like this:
 *
 *  struct sysctl_userns_req    struct sysctl_req       name        arg
 * ---------------------------------------------------------------------------
 * |  op  |  nr_req  |  reqs  | <fields> | name | arg | "the name" | "the arg" ...
 * ---------------------------------------------------------------------------
 *                       |____^             |______|__^            ^
 *                                                 |_______________|
 */
static int do_sysctl_op(int *fds, struct sysctl_userns_req *userns_req)
{
	int i, op = userns_req->op;
	struct sysctl_req *req;

	req = userns_req->reqs;

	for (i = 0; i < userns_req->nr_req; i++)  {
		int arg_len = sysctl_userns_arg_size(req->type);
		int name_len = strlen((char *) &req[1]) + 1;
		int total_len = sizeof(*req) + arg_len + name_len;
		int nr = 1, ret = -1;
		int fd = fds[i];

		switch (CTL_TYPE(req->type)) {
		case __CTL_U32A:
			nr = CTL_LEN(req->type);
		case CTL_U32:
			__SYSCTL_OP(ret, fd, req, u32, nr, op);
			break;
		case CTL_32:
			__SYSCTL_OP(ret, fd, req, s32, nr, op);
			break;
		case __CTL_U64A:
			nr = CTL_LEN(req->type);
		case CTL_U64:
			__SYSCTL_OP(ret, fd, req, u64, nr, op);
			break;
		case __CTL_STR:
			nr = CTL_LEN(req->type);
			__SYSCTL_OP(ret, fd, req, char, nr, op);
			break;
		}

		if (ret < 0)
			return ret;

		req = (struct sysctl_req *) (((char *) req) + total_len);
	}

	return 0;
}

static int __sysctl_op(void *arg, int unused, pid_t pid)
{
	int fd, ret = -1, flags, dir, i;
	struct sysctl_userns_req *userns_req = arg;
	int op = userns_req->op;
	struct sysctl_req *req;
	int *fds = NULL;

	// fix up the pointer
	req = userns_req->reqs = (struct sysctl_req *) &userns_req[1];

	/* In the case of user namespaces, unprivileged users cannot write to
	 * some files in /proc/sys (e.g. kernel/hostname), so we need to proxy
	 * requests through usernsd. However, unprivileged users with
	 * CAP_NET_ADMIN can write to sysctl files under net/. So, the way we
	 * restore sysctl files depends on how they behave under their
	 * namespace. For files under net/ it is easy, since the task still has
	 * CAP_NET_ADMIN in its user namespace, so we just write to it from the
	 * process directly.
	 *
	 * For files in the IPC/UTS namespaces, it is more complicated.
	 * Unprivileged users cannot even open these files, so they must be
	 * opened by usernsd. However, the value in the kernel is changed for
	 * the IPC/UTS namespace that write()s to the open sysctl file (not who
	 * opened it). So, we must set the value from inside the usernsd
	 * caller's namespace. We:
	 *
	 * 1. unsd opens the sysctl files
	 * 2. forks a task
	 * 3. setns()es to the UTS/IPC namespace of the caller
	 * 4. write()s to the files and exits
	 */
	dir = open("/proc/sys", O_RDONLY, O_DIRECTORY);
	if (dir < 0) {
		pr_perror("Can't open sysctl dir");
		return -1;
	}

	fds = xmalloc(sizeof(int) * userns_req->nr_req);
	if (!fds)
		goto out;

	memset(fds, -1, sizeof(int) * userns_req->nr_req);

	for (i = 0; i < userns_req->nr_req; i++)  {
		int arg_len = sysctl_userns_arg_size(req->type);
		int name_len = strlen((char *) &req[1]) + 1;
		int total_len = sizeof(*req) + arg_len + name_len;

		/* fix up the pointers */
		req->name = (char *) &req[1];
		req->arg = req->name + name_len;

		if (((char *) req) + total_len >= ((char *) userns_req) + MAX_UNSFD_MSG_SIZE) {
			pr_err("bad sysctl req %s, too big: %d\n", req->name, total_len);
			goto out;
		}

		if (op == CTL_READ)
			flags = O_RDONLY;
		else
			flags = O_WRONLY;

		fd = openat(dir, req->name, flags);
		if (fd < 0) {
			if (errno == ENOENT && (req->flags & CTL_FLAGS_OPTIONAL))
				continue;
			pr_perror("Can't open sysctl %s", req->name);
			goto out;
		}

		fds[i] = fd;

		req = (struct sysctl_req *) (((char *) req) + total_len);
	}

	/* Now, if we're trying to read stuff or if we're in the same pid, we
	 * can just do things directly in this process, since usernsd didn't
	 * call us (or we're reading and need to return the values).
	 *
	 * Otherwise, let's fork a new task as described above.
	 */
	if (pid == getpid() || op == CTL_READ) {
		ret = do_sysctl_op(fds, userns_req);
	} else {
		pid_t worker;
		int status;

		worker = fork();
		if (worker < 0)
			goto out;

		if (!worker) {
			int nsfd;
			const char *nsname = ns_to_string(userns_req->ns);

			BUG_ON(!nsname);
			nsfd = open_proc(pid, "ns/%s", nsname);
			if (nsfd < 0) {
				pr_perror("failed to open pid %d's ns %s", pid, nsname);
				exit(1);
			}

			if (setns(nsfd, 0) < 0) {
				pr_perror("failed to setns to %d's ns %s", pid, nsname);
				exit(1);
			}

			exit(do_sysctl_op(fds, userns_req));
		}

		if (waitpid(worker, &status, 0) != worker) {
			pr_err("worker didn't die?");
			kill(worker, SIGKILL);
			goto out;
		}

		if (!WIFEXITED(status) || WEXITSTATUS(status)) {
			pr_err("worker failed: %d\n", status);
			goto out;
		}

		ret = 0;
	}

out:
	if (fds) {
		for (i = 0; i < userns_req->nr_req; i++) {
			if (fds[i] < 0)
				break;
			close_safe(&fds[i]);
		}

		xfree(fds);
	}

	close_safe(&dir);

	return ret;
}

int sysctl_op(struct sysctl_req *req, size_t nr_req, int op, unsigned int ns)
{
	int ret = 0, i;
	struct sysctl_userns_req *userns_req;
	struct sysctl_req *cur;

	if (nr_req == 0)
		return 0;

	if (ns & !KNOWN_NS_MASK) {
		pr_err("don't know how to restore some namespaces in %u\n", ns);
		return -1;
	}

	userns_req = alloca(MAX_UNSFD_MSG_SIZE);
	userns_req->op = op;
	userns_req->nr_req = nr_req;
	userns_req->ns = ns;
	userns_req->reqs = (struct sysctl_req *) (&userns_req[1]);

	cur = userns_req->reqs;
	for (i = 0; i < nr_req; i++) {
		int arg_len = sysctl_userns_arg_size(req[i].type);
		int name_len = strlen(req[i].name) + 1;
		int total_len = sizeof(*cur) + arg_len + name_len;

		if (((char *) cur) + total_len >= ((char *) userns_req) + MAX_UNSFD_MSG_SIZE) {
			pr_err("sysctl msg %s too big: %d\n", req[i].name, total_len);
			return -1;
		}

		/* copy over the non-pointer fields */
		cur->type = req[i].type;
		cur->flags = req[i].flags;

		cur->name = (char *) &cur[1];
		strcpy(cur->name, req[i].name);

		cur->arg = cur->name + name_len;
		memcpy(cur->arg, req[i].arg, arg_len);

		cur = (struct sysctl_req *) (((char *) cur) + total_len);
	}

	/* Net namespaces can be restored without usernsd, since anything with
	 * CAP_SYS_ADMIN in its namespace can write to net/ sysctls. The other
	 * namespaces we allow to restore (IPC and UTS) must be restored via
	 * usernsd.
	 */
	if (ns & CLONE_NEWNET)
		ret = __sysctl_op(userns_req, -1, getpid());
	else
		ret = userns_call(__sysctl_op, UNS_ASYNC, userns_req, MAX_UNSFD_MSG_SIZE, -1);

	if (ret < 0)
		return -1;

	if (op != CTL_READ)
		return 0;

	/*
	 * Here, we use a little hack: since we only read in dump mode when
	 * usernsd is not active, we know the above call happened in this
	 * address space, so we can just copy the value read back out. If there
	 * was an API to return stuff via userns_call(), that would be
	 * preferable.
	 */
	cur = userns_req->reqs;
	for (i = 0; i < nr_req; i++) {
		int arg_len = sysctl_userns_arg_size(cur->type);
		int name_len = strlen((char *) &cur[1]) + 1;
		int total_len = sizeof(*cur) + arg_len + name_len;
		void *arg = ((void *) &cur[1]) + name_len;

		memcpy(req[i].arg, arg, arg_len);

		cur = (struct sysctl_req *) (((char *) cur) + total_len);
	}

	return 0;
}
