#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <ctype.h>

#include <google/protobuf-c/protobuf-c.h>

#include "image.h"
#include "servicefd.h"
#include "compiler.h"
#include "asm/types.h"
#include "log.h"
#include "util.h"
#include "string.h"
#include "sockets.h"
#include "cr_options.h"
#include "bfd.h"
#include "protobuf.h"

/*
 * To speed up reading of packed objects
 * by providing space on stack, this should
 * be more than enough for most objects.
 */
#define PB_PKOBJ_LOCAL_SIZE	1024

#define INET_ADDR_LEN		40

typedef struct {
	void		*data;
	int		number;
	int		depth;
	int		count;
	char		fmt[32];
} pb_pr_field_t;

typedef struct {
	void		*arg;
	int		single_entry;
	const char	*pretty_fmt;
	pb_pr_field_t	cur;
} pb_pr_ctl_t;

typedef int (*pb_pr_show_t)(pb_pr_field_t *field);

/*
 * This one describes how fields should be shown
 * @fsize is the size of the field entry
 * @show is the callback to print the entry
 */
struct pb_shower {
	size_t fsize;
	pb_pr_show_t show;
};

static int pb_msg_int32x(pb_pr_field_t *field)
{
	pr_msg("%#x", *(int *)field->data);
	return 0;
}

static int pb_msg_int64x(pb_pr_field_t *field)
{
	pr_msg("%#016lx", *(long *)field->data);
	return 0;
}

static int pb_msg_int64x_r(pb_pr_field_t *field)
{
	long val = *(long *)field->data;
	if (val)
		pr_msg("%#016lx", val);
	else
		pr_msg("0");
	return 0;
}

static int pb_msg_string(pb_pr_field_t *field)
{
	pr_msg("\"%s\"",	*(char **)field->data);
	return 0;
}

static int pb_msg_unk(pb_pr_field_t *field)
{
	pr_msg("unknown object %p", field->data);
	return 0;
}

static inline void print_tabs(pb_pr_ctl_t *ctl)
{
	int counter = ctl->cur.depth;

	if (!ctl->single_entry)
		return;

	while (counter--)
		pr_msg("\t");
}

static void print_nested_message_braces(pb_pr_ctl_t *ctl, int right_brace)
{
	print_tabs(ctl);
	pr_msg("%s%s", (right_brace) ? "}" : "{", (ctl->single_entry) ? "\n" : " ");
}

static void pb_show_msg(const void *msg, pb_pr_ctl_t *ctl);

static int show_nested_message(pb_pr_field_t *field)
{
	pb_pr_ctl_t *ctl = container_of(field, pb_pr_ctl_t, cur);
	void *arg = ctl->arg;

	print_nested_message_braces(ctl, 0);
	field->depth++;
	pb_show_msg(field->data, ctl);
	field->depth--;
	print_nested_message_braces(ctl, 1);
	ctl->arg = arg;
	return 0;
}

static int show_enum(pb_pr_field_t *field)
{
	pb_pr_ctl_t *ctl = container_of(field, pb_pr_ctl_t, cur);
	ProtobufCEnumDescriptor *d = ctl->arg;
	const char *val_name = NULL;
	int val, i;

	val = *(int *)field->data;
	for (i = 0; i < d->n_values; i++)
		if (d->values[i].value == val) {
			val_name = d->values[i].name;
			break;
		}

	if (val_name != NULL)
		pr_msg("%s", val_name);
	else
		pr_msg("%d", val);
	return 0;
}

static int show_bool(pb_pr_field_t *field)
{
	protobuf_c_boolean val = *(protobuf_c_boolean *)field->data;

	if (val)
		pr_msg("True");
	else
		pr_msg("False");
	return 0;
}

static int show_bytes(pb_pr_field_t *field)
{
	ProtobufCBinaryData *bytes = (ProtobufCBinaryData *)field->data;
	int i = 0;

	while (i < bytes->len)
		pr_msg("%02x ", bytes->data[i++]);
	return 0;
}

static int pb_show_pretty(pb_pr_field_t *field)
{
	switch (field->fmt[0]) {
	case '%':
		pr_msg(field->fmt, *(long *)field->data);
		break;
	case 'S':
		{
			ProtobufCBinaryData *name = (ProtobufCBinaryData *)field->data;
			int i;

			for (i = 0; i < name->len; i++) {
				char c = (char)name->data[i];

				if (isprint(c))
					pr_msg("%c", c);
				else if (c != 0)
					pr_msg(".");
			}
			break;
		}
	case 'A':
		{
			char addr[INET_ADDR_LEN] = "<unknown>";
			int family = (field->count == 1) ? AF_INET : AF_INET6;

			if (inet_ntop(family, (void *)field->data, addr,
				      INET_ADDR_LEN) == NULL)
				pr_msg("failed to translate");
			else
				pr_msg("%s", addr);
		}
		return 1;
	}
	return 0;
}

static void pb_copy_fmt(const char *fmt, char *to)
{
	while (*fmt != ' ' && *fmt != '\0') {
		*to = *fmt;
		to++;
		fmt++;
	}

	*to = '\0';
}

static const char *pb_next_pretty(const char *pfmt)
{
	pfmt = strchr(pfmt, ' ');
	if (pfmt) {
		while (*pfmt == ' ')
			pfmt++;

		if (*pfmt == '\0')
			pfmt = NULL;
	}

	return pfmt;
}

static int pb_find_fmt(char *what, pb_pr_ctl_t *ctl)
{
	int len;
	const char *pretty = ctl->pretty_fmt;

	len = strlen(what);
	while (1) {
		if (!strncmp(pretty, what, len)) {
			pb_copy_fmt(pretty + len, ctl->cur.fmt);
			return 1;
		}

		pretty = pb_next_pretty(pretty + len);
		if (!pretty)
			return 0;
	}
}

static int pb_field_show_pretty(const ProtobufCFieldDescriptor *fd, pb_pr_ctl_t *ctl)
{
	char cookie[32];

	if (!ctl->pretty_fmt)
		return 0;

	sprintf(cookie, "%s:", fd->name);
	if (pb_find_fmt(cookie, ctl))
		return 1;

	if (!ctl->cur.depth)
		sprintf(cookie, "%d:", ctl->cur.number);
	else
		sprintf(cookie, "%d.%d:", ctl->cur.depth, ctl->cur.number);

	if (pb_find_fmt(cookie, ctl))
		return 1;

	sprintf(cookie, "*:");
	if (pb_find_fmt(cookie, ctl))
		return 1;

	return 0;
}

static void pb_prepare_shower(const ProtobufCFieldDescriptor *fd,
		pb_pr_ctl_t *ctl, struct pb_shower *sh)
{
	sh->fsize = 0;
	sh->show = pb_msg_unk;

	switch (fd->type) {
	case PROTOBUF_C_TYPE_INT32:
	case PROTOBUF_C_TYPE_SINT32:
	case PROTOBUF_C_TYPE_UINT32:
	case PROTOBUF_C_TYPE_SFIXED32:
		sh->fsize = 4;
		sh->show = pb_msg_int32x;
		break;

	case PROTOBUF_C_TYPE_INT64:
	case PROTOBUF_C_TYPE_SINT64:
	case PROTOBUF_C_TYPE_SFIXED64:
	case PROTOBUF_C_TYPE_FIXED32:
	case PROTOBUF_C_TYPE_UINT64:
	case PROTOBUF_C_TYPE_FIXED64:
		sh->fsize = 8;
		sh->show = (fd->label == PROTOBUF_C_LABEL_REPEATED ?
				pb_msg_int64x_r : pb_msg_int64x);
		break;

	case PROTOBUF_C_TYPE_STRING:
		sh->fsize = sizeof (void *);
		sh->show = pb_msg_string;
		break;
	case PROTOBUF_C_TYPE_MESSAGE:
		sh->fsize = sizeof (void *);
		sh->show = show_nested_message;
		ctl->arg = (void *)fd->descriptor;
		break;
	case PROTOBUF_C_TYPE_ENUM:
		sh->fsize = 4;
		sh->show = show_enum;
		ctl->arg = (void *)fd->descriptor;
		break;

	case PROTOBUF_C_TYPE_BOOL:
		sh->fsize = sizeof (protobuf_c_boolean);
		sh->show = show_bool;
		break;
	case PROTOBUF_C_TYPE_BYTES:
		sh->fsize = sizeof (ProtobufCBinaryData);
		sh->show = show_bytes;
		break;
	case PROTOBUF_C_TYPE_FLOAT:
		sh->fsize = 4;
		break;
	case PROTOBUF_C_TYPE_DOUBLE:
		sh->fsize = 8;
		break;

	default:
		BUG();
	}

	if (pb_field_show_pretty(fd, ctl))
		sh->show = pb_show_pretty;
}

static void pb_show_repeated(const ProtobufCFieldDescriptor *fd,
		pb_pr_ctl_t *ctl, struct pb_shower *sh)
{
	pb_pr_field_t *field = &ctl->cur;
	unsigned long i, nr_fields = field->count;

	if (nr_fields == 0) {
		pr_msg("<empty>");
		return;
	}

	if (fd->type == PROTOBUF_C_TYPE_MESSAGE) {
		void *p = field->data;

		for (i = 0; i < nr_fields; i++) {
			field->data = (void *)(*(long *)p);
			sh->show(field);
			p += sh->fsize;
		}

		return;
	}

	for (i = 0; i < nr_fields; i++) {
		if (i)
			pr_msg(":");
		if (sh->show(field))
			break;
		field->data += sh->fsize;
	}
}

static void pb_show_field(const ProtobufCFieldDescriptor *fd, pb_pr_ctl_t *ctl)
{
	struct pb_shower sh;

	print_tabs(ctl);
	pr_msg("%s: ", fd->name);

	pb_prepare_shower(fd, ctl, &sh);
	pb_show_repeated(fd, ctl, &sh);

	if (ctl->single_entry)
		pr_msg("\n");
	else
		pr_msg(" ");
}

static int pb_optional_field_present(const ProtobufCFieldDescriptor *field,
		const void *msg)
{
	if ((field->type == PROTOBUF_C_TYPE_MESSAGE) ||
		(field->type == PROTOBUF_C_TYPE_STRING)) {
		const void *opt_flag = * (const void * const *)(msg + field->offset);

		if ((opt_flag == NULL) || (opt_flag == field->default_value))
			return 0;
	} else {
		const protobuf_c_boolean *has = msg + field->quantifier_offset;

		if (!*has)
			return 0;
	}
	return 1;
}

static bool should_show_field(const char *name)
{
	char *s, *e;
	int len;

	if (!opts.show_fmt)
		return true;

	len = strlen(name);
	s = opts.show_fmt;

	while (1) {
		e = strchrnul(s, ',');
		if (e - s == len) {
			if (!strncmp(name, s, len))
				return true;
		}
		if (*e == '\0')
			return false;
		s = e + 1;
	}
}

static void pb_show_msg(const void *msg, pb_pr_ctl_t *ctl)
{
	int i;
	const ProtobufCMessageDescriptor *md = ctl->arg;

	BUG_ON(md == NULL);

	for (i = 0; i < md->n_fields; i++) {
		const ProtobufCFieldDescriptor fd = md->fields[i];
		unsigned long *data;
		size_t nr_fields;

		nr_fields = 1;
		data = (unsigned long *)(msg + fd.offset);

		if (fd.label == PROTOBUF_C_LABEL_OPTIONAL) {
			if (!pb_optional_field_present(&fd, msg))
				continue;
		}

		if (!should_show_field(fd.name))
			continue;

		if (fd.label == PROTOBUF_C_LABEL_REPEATED) {
			nr_fields = *(size_t *)(msg + fd.quantifier_offset);
			data = (unsigned long *)*data;
		}

		ctl->cur.data = data;
		ctl->cur.number = i + 1;
		ctl->cur.count = nr_fields;

		pb_show_field(&fd, ctl);
	}
}

static inline void pb_no_payload(struct cr_img *i, void *obj) { }

void do_pb_show_plain(struct cr_img *img, int type, int single_entry,
		void (*payload_hadler)(struct cr_img *, void *obj),
		const char *pretty_fmt)
{
	pb_pr_ctl_t ctl = {NULL, single_entry, pretty_fmt};
	void (*handle_payload)(struct cr_img *, void *obj);

	if (!cr_pb_descs[type].pb_desc) {
		pr_err("Wrong object requested %d\n", type);
		return;
	}

	handle_payload = (payload_hadler) ? : pb_no_payload;

	while (1) {
		void *obj;

		if (pb_read_one_eof(img, &obj, type) <= 0)
			break;

		ctl.arg = (void *)cr_pb_descs[type].pb_desc;
		pb_show_msg(obj, &ctl);
		handle_payload(img, obj);
		cr_pb_descs[type].free(obj, NULL);
		if (single_entry)
			break;
		pr_msg("\n");
	}
}

static char *image_name(struct cr_img *img)
{
	int fd = img->_x.fd;
	static char image_path[PATH_MAX];

	if (read_fd_link(fd, image_path, sizeof(image_path)) > 0)
		return image_path;
	return NULL;
}

/*
 * Reads PB record (header + packed object) from file @fd and unpack
 * it with @unpack procedure to the pointer @pobj
 *
 *  1 on success
 * -1 on error (or EOF met and @eof set to false)
 *  0 on EOF and @eof set to true
 *
 * Don't forget to free memory granted to unpacked object in calling code if needed
 */

int do_pb_read_one(struct cr_img *img, void **pobj, int type, bool eof)
{
	u8 local[PB_PKOBJ_LOCAL_SIZE];
	void *buf = (void *)&local;
	u32 size;
	int ret;

	if (!cr_pb_descs[type].pb_desc) {
		pr_err("Wrong object requested %d on %s\n",
			type, image_name(img));
		return -1;
	}

	*pobj = NULL;

	if (unlikely(empty_image(img)))
		ret = 0;
	else
		ret = bread(&img->_x, &size, sizeof(size));
	if (ret == 0) {
		if (eof) {
			return 0;
		} else {
			pr_err("Unexpected EOF on %s\n",
			       image_name(img));
			return -1;
		}
	} else if (ret < sizeof(size)) {
		pr_perror("Read %d bytes while %d expected on %s",
			  ret, (int)sizeof(size),
			  image_name(img));
		return -1;
	}

	if (size > sizeof(local)) {
		ret = -1;
		buf = xmalloc(size);
		if (!buf)
			goto err;
	}

	ret = bread(&img->_x, buf, size);
	if (ret < 0) {
		pr_perror("Can't read %d bytes from file %s",
			  size, image_name(img));
		goto err;
	} else if (ret != size) {
		pr_perror("Read %d bytes while %d expected from %s",
			  ret, size, image_name(img));
		ret = -1;
		goto err;
	}

	*pobj = cr_pb_descs[type].unpack(NULL, size, buf);
	if (!*pobj) {
		ret = -1;
		pr_err("Failed unpacking object %p from %s\n",
		       pobj, image_name(img));
		goto err;
	}

	ret = 1;
err:
	if (buf != (void *)&local)
		xfree(buf);

	return ret;
}

/*
 * Writes PB record (header + packed object pointed by @obj)
 * to file @fd, using @getpksize to get packed size and @pack
 * to implement packing
 *
 *  0 on success
 * -1 on error
 */
int pb_write_one(struct cr_img *img, void *obj, int type)
{
	u8 local[PB_PKOBJ_LOCAL_SIZE];
	void *buf = (void *)&local;
	u32 size, packed;
	int ret = -1;
	struct iovec iov[2];

	if (!cr_pb_descs[type].pb_desc) {
		pr_err("Wrong object requested %d\n", type);
		return -1;
	}

	if (lazy_image(img) && open_image_lazy(img))
		return -1;

	size = cr_pb_descs[type].getpksize(obj);
	if (size > (u32)sizeof(local)) {
		buf = xmalloc(size);
		if (!buf)
			goto err;
	}

	packed = cr_pb_descs[type].pack(obj, buf);
	if (packed != size) {
		pr_err("Failed packing PB object %p\n", obj);
		goto err;
	}

	iov[0].iov_base = &size;
	iov[0].iov_len = sizeof(size);
	iov[1].iov_base = buf;
	iov[1].iov_len = size;

	ret = bwritev(&img->_x, iov, 2);
	if (ret != size + sizeof(size)) {
		pr_perror("Can't write %d bytes", (int)(size + sizeof(size)));
		goto err;
	}

	ret = 0;
err:
	if (buf != (void *)&local)
		xfree(buf);
	return ret;
}

int collect_image(struct collect_image_info *cinfo)
{
	int ret;
	struct cr_img *img;
	void *(*o_alloc)(size_t size) = malloc;
	void (*o_free)(void *ptr) = free;

	pr_info("Collecting %d/%d (flags %x)\n",
			cinfo->fd_type, cinfo->pb_type, cinfo->flags);

	img = open_image(cinfo->fd_type, O_RSTR);
	if (!img)
		return -1;

	cinfo->flags |= COLLECT_HAPPENED;
	if (cinfo->flags & COLLECT_SHARED) {
		o_alloc = shmalloc;
		o_free = shfree_last;
	}

	while (1) {
		void *obj;
		ProtobufCMessage *msg;

		if (cinfo->priv_size) {
			ret = -1;
			obj = o_alloc(cinfo->priv_size);
			if (!obj)
				break;
		} else
			obj = NULL;

		ret = pb_read_one_eof(img, &msg, cinfo->pb_type);
		if (ret <= 0) {
			o_free(obj);
			break;
		}

		ret = cinfo->collect(obj, msg);
		if (ret < 0) {
			o_free(obj);
			cr_pb_descs[cinfo->pb_type].free(msg, NULL);
			break;
		}

		if (!cinfo->priv_size)
			cr_pb_descs[cinfo->pb_type].free(msg, NULL);
	}

	close_image(img);
	pr_debug(" `- ... done\n");
	return ret;
}
