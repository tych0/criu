#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#include "asm/types.h"
#include "namespaces.h"
#include "sysctl.h"
#include "util.h"

struct sysctl_userns_req {
	int			op;
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
 * it can be passed via userns_call. It looks like this:
 *
 *  struct sysctl_userns_req    struct sysctl_req       name        arg
 * ---------------------------------------------------------------------------
 * |  op  |  nr_req  |  reqs  | <fields> | name | arg | "the name" | "the arg" ...
 * ---------------------------------------------------------------------------
 *                       |____^             |______|__^            ^
 *                                                 |_______________|
 */

static int __sysctl_op(void *arg, int unused)
{
	int fd, ret = -1, nr, flags, dir, i;
	struct sysctl_userns_req *userns_req = arg;
	int op = userns_req->op;
	struct sysctl_req *req;

	dir = open("/proc/sys", O_RDONLY, O_DIRECTORY);
	if (dir < 0) {
		pr_perror("Can't open sysctl dir");
		return -1;
	}

	// fix up the pointer
	req = userns_req->reqs = (struct sysctl_req *) &userns_req[1];
	for (i = 0; i < userns_req->nr_req; i++)  {
		int arg_len = sysctl_userns_arg_size(req->type);
		int name_len = strlen((char *) &req[1]) + 1;
		int total_len = sizeof(*req) + arg_len + name_len;

		/* fix up the pointers */
		req->name = (char *) &req[1];
		req->arg = req->name + name_len;

		if (((char *) req) + total_len >= ((char *) userns_req) + MAX_UNSFD_MSG_SIZE) {
			pr_err("bad sysctl req %s, too big: %d\n", req->name, total_len);
			return -1;
		}

		if (op == CTL_READ)
			flags = O_RDONLY;
		else
			flags = O_WRONLY;

		fd = openat(dir, req->name, flags);
		if (fd < 0) {
			close_safe(&dir);
			if (errno == ENOENT && (req->flags & CTL_FLAGS_OPTIONAL))
				continue;
			pr_perror("Can't open sysctl %s", req->name);
			return -1;
		}

		nr = 1;
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

		close_safe(&fd);
		req = (struct sysctl_req *) (((char *) req) + total_len);
	}

	close_safe(&dir);

	return ret;
}

int sysctl_op(struct sysctl_req *req, size_t nr_req, int op)
{
	int ret = 0, i;
	struct sysctl_userns_req *userns_req;
	struct sysctl_req *cur;

	if (nr_req == 0)
		return 0;

	userns_req = alloca(MAX_UNSFD_MSG_SIZE);
	userns_req->op = op;
	userns_req->nr_req = nr_req;
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

	ret = userns_call(__sysctl_op, UNS_ASYNC, userns_req, MAX_UNSFD_MSG_SIZE, 0);
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
