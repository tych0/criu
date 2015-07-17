#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "asm/string.h"
#include "asm/types.h"

#include "compiler.h"
#include "syscall.h"
#include "image.h"
#include "vdso.h"
#include "vma.h"
#include "log.h"
#include "bug.h"

#ifdef LOG_PREFIX
# undef LOG_PREFIX
#endif
#define LOG_PREFIX "vdso: "

#ifdef CONFIG_X86_64
typedef struct {
	u16	movabs;
	u64	imm64;
	u16	jmp_rax;
	u32	guards;
} __packed jmp_t;

int vdso_redirect_calls(void *base_to, void *base_from,
			struct vdso_symtable *to,
			struct vdso_symtable *from)
{
	jmp_t jmp = {
		.movabs		= 0xb848,
		.jmp_rax	= 0xe0ff,
		.guards		= 0xcccccccc,
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(to->symbols); i++) {
		if (vdso_symbol_empty(&from->symbols[i]))
			continue;

		pr_debug("jmp: %lx/%lx -> %lx/%lx (index %d)\n",
			 (unsigned long)base_from, from->symbols[i].offset,
			 (unsigned long)base_to, to->symbols[i].offset, i);

		jmp.imm64 = (unsigned long)base_to + to->symbols[i].offset;
		builtin_memcpy((void *)(base_from + from->symbols[i].offset), &jmp, sizeof(jmp));
	}

	return 0;
}


/* Check if pointer is out-of-bound */
static bool __ptr_oob(void *ptr, void *start, size_t size)
{
	void *end = (void *)((unsigned long)start + size);
	return ptr > end || ptr < start;
}

/*
 * Elf hash, see format specification.
 */
static unsigned long elf_hash(const unsigned char *name)
{
	unsigned long h = 0, g;

	while (*name) {
		h = (h << 4) + *name++;
		g = h & 0xf0000000ul;
		if (g)
			h ^= g >> 24;
		h &= ~g;
	}
	return h;
}

int vdso_fill_symtable(char *mem, size_t size, struct vdso_symtable *t)
{
	Elf64_Phdr *dynamic = NULL, *load = NULL;
	Elf64_Ehdr *ehdr = (void *)mem;
	Elf64_Dyn *dyn_strtab = NULL;
	Elf64_Dyn *dyn_symtab = NULL;
	Elf64_Dyn *dyn_strsz = NULL;
	Elf64_Dyn *dyn_syment = NULL;
	Elf64_Dyn *dyn_hash = NULL;
	Elf64_Word *hash = NULL;
	Elf64_Phdr *phdr;
	Elf64_Dyn *d;

	Elf64_Word *bucket, *chain;
	Elf64_Word nbucket, nchain;

	/*
	 * See Elf specification for this magic values.
	 */
	const char elf_ident[] = {
		0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};

	const char *vdso_symbols[VDSO_SYMBOL_MAX] = {
		[VDSO_SYMBOL_CLOCK_GETTIME]	= VDSO_SYMBOL_CLOCK_GETTIME_NAME,
		[VDSO_SYMBOL_GETCPU]		= VDSO_SYMBOL_GETCPU_NAME,
		[VDSO_SYMBOL_GETTIMEOFDAY]	= VDSO_SYMBOL_GETTIMEOFDAY_NAME,
		[VDSO_SYMBOL_TIME]		= VDSO_SYMBOL_TIME_NAME,
	};

	char *dynsymbol_names;
	unsigned int i, j, k;

	BUILD_BUG_ON(sizeof(elf_ident) != sizeof(ehdr->e_ident));

	pr_debug("Parsing at %lx %lx\n", (long)mem, (long)mem + (long)size);

	/*
	 * Make sure it's a file we support.
	 */
	if (builtin_memcmp(ehdr->e_ident, elf_ident, sizeof(elf_ident))) {
		pr_err("Elf header magic mismatch\n");
		return -EINVAL;
	}

	/*
	 * We need PT_LOAD and PT_DYNAMIC here. Each once.
	 */
	phdr = (void *)&mem[ehdr->e_phoff];
	for (i = 0; i < ehdr->e_phnum; i++, phdr++) {
		if (__ptr_oob(phdr, mem, size))
			goto err_oob;
		switch (phdr->p_type) {
		case PT_DYNAMIC:
			if (dynamic) {
				pr_err("Second PT_DYNAMIC header\n");
				return -EINVAL;
			}
			dynamic = phdr;
			break;
		case PT_LOAD:
			if (load) {
				pr_err("Second PT_LOAD header\n");
				return -EINVAL;
			}
			load = phdr;
			break;
		}
	}

	if (!load || !dynamic) {
		pr_err("One of obligated program headers is missed\n");
		return -EINVAL;
	}

	pr_debug("PT_LOAD p_vaddr: %lx\n", (unsigned long)load->p_vaddr);

	/*
	 * Dynamic section tags should provide us the rest of information
	 * needed. Note that we're interested in a small set of tags.
	 */
	d = (void *)&mem[dynamic->p_offset];
	for (i = 0; i < dynamic->p_filesz / sizeof(*d); i++, d++) {
		if (__ptr_oob(d, mem, size))
			goto err_oob;

		if (d->d_tag == DT_NULL) {
			break;
		} else if (d->d_tag == DT_STRTAB) {
			dyn_strtab = d;
			pr_debug("DT_STRTAB: %p\n", (void *)d->d_un.d_ptr);
		} else if (d->d_tag == DT_SYMTAB) {
			dyn_symtab = d;
			pr_debug("DT_SYMTAB: %p\n", (void *)d->d_un.d_ptr);
		} else if (d->d_tag == DT_STRSZ) {
			dyn_strsz = d;
			pr_debug("DT_STRSZ: %lu\n", (unsigned long)d->d_un.d_val);
		} else if (d->d_tag == DT_SYMENT) {
			dyn_syment = d;
			pr_debug("DT_SYMENT: %lu\n", (unsigned long)d->d_un.d_val);
		} else if (d->d_tag == DT_HASH) {
			dyn_hash = d;
			pr_debug("DT_HASH: %p\n", (void *)d->d_un.d_ptr);
		}
	}

	if (!dyn_strtab || !dyn_symtab || !dyn_strsz || !dyn_syment || !dyn_hash) {
		pr_err("Not all dynamic entries are present\n");
		return -EINVAL;
	}

	dynsymbol_names = &mem[dyn_strtab->d_un.d_val - load->p_vaddr];
	if (__ptr_oob(dynsymbol_names, mem, size))
		goto err_oob;

	hash = (void *)&mem[(unsigned long)dyn_hash->d_un.d_ptr - (unsigned long)load->p_vaddr];
	if (__ptr_oob(hash, mem, size))
		goto err_oob;

	nbucket = hash[0];
	nchain = hash[1];
	bucket = &hash[2];
	chain = &hash[nbucket + 2];

	pr_debug("nbucket %lu nchain %lu bucket %p chain %p\n",
		 (long)nbucket, (long)nchain, bucket, chain);

	for (i = 0; i < ARRAY_SIZE(vdso_symbols); i++) {
		k = elf_hash((const unsigned char *)vdso_symbols[i]);

		for (j = bucket[k % nbucket]; j < nchain && chain[j] != STN_UNDEF; j = chain[j]) {
			Elf64_Sym *sym = (void *)&mem[dyn_symtab->d_un.d_ptr - load->p_vaddr];
			char *name;

			sym = &sym[j];
			if (__ptr_oob(sym, mem, size))
				continue;

			if (ELF64_ST_TYPE(sym->st_info) != STT_FUNC &&
			    ELF64_ST_BIND(sym->st_info) != STB_GLOBAL)
				continue;

			name = &dynsymbol_names[sym->st_name];
			if (__ptr_oob(name, mem, size))
				continue;

			if (builtin_strcmp(name, vdso_symbols[i]))
				continue;

			builtin_memcpy(t->symbols[i].name, name, sizeof(t->symbols[i].name));
			t->symbols[i].offset = (unsigned long)sym->st_value - load->p_vaddr;
			break;
		}
	}

	return 0;

err_oob:
	pr_err("Corrupted Elf data\n");
	return -EFAULT;
}

static void vdso_debug_show_self_maps(void)
{
	int fd = sys_open("/proc/self/maps", O_RDONLY, 0);
	if (fd >= 0) {
		char buf[128];
		long len, i, pid = sys_getpid();

		do {
			len = sys_read(fd, buf, sizeof(buf));
			if (len > 0) {
				for (i = 0; i < len; i++) {
					if (buf[i] != '\n')
						continue;
					buf[i] = '\0';
					sys_lseek(fd, -(len - i - 1), SEEK_CUR);
					break;
				}
				pr_debug("cm: %i: %s\n", (int)pid, buf);
			}
		} while (len > 0);
	}
}

static int vdso_remap(char *who, unsigned long from, unsigned long to, size_t size)
{
	unsigned long addr;

	pr_debug("Remap %s %lx -> %lx\n", who, from, to);

	addr = sys_mremap(from, size, size, MREMAP_MAYMOVE | MREMAP_FIXED, to);
	if (addr != to) {
		pr_err("Unable to remap %lx -> %lx %lx\n", from, to, addr);
		vdso_debug_show_self_maps();
		return -1;
	}

	return 0;
}

/* Park runtime vDSO in some safe place where it can be accessible from restorer */
int vdso_do_park(struct vdso_symtable *sym_rt, unsigned long park_at, unsigned long park_size)
{
	int ret;

	BUG_ON((vdso_vma_size(sym_rt) + vvar_vma_size(sym_rt)) < park_size);

	if (sym_rt->vvar_start != VDSO_BAD_ADDR) {
		if (sym_rt->vma_start < sym_rt->vvar_start) {
			ret  = vdso_remap("rt-vdso", sym_rt->vma_start,
					  park_at, vdso_vma_size(sym_rt));
			park_at += vdso_vma_size(sym_rt);
			ret |= vdso_remap("rt-vvar", sym_rt->vvar_start,
					  park_at, vvar_vma_size(sym_rt));
		} else {
			ret  = vdso_remap("rt-vvar", sym_rt->vvar_start,
					  park_at, vvar_vma_size(sym_rt));
			park_at += vvar_vma_size(sym_rt);
			ret |= vdso_remap("rt-vdso", sym_rt->vma_start,
					  park_at, vdso_vma_size(sym_rt));
		}
	} else
		ret = vdso_remap("rt-vdso", sym_rt->vma_start,
				 park_at, vdso_vma_size(sym_rt));
	return ret;
}

int vdso_proxify(char *who, struct vdso_symtable *sym_rt,
		 unsigned long vdso_rt_parked_at, size_t index,
		 VmaEntry *vmas, size_t nr_vmas)
{
	VmaEntry *vma_vdso = NULL, *vma_vvar = NULL;
	struct vdso_symtable s = VDSO_SYMTABLE_INIT;
	bool remap_rt = false;

	/*
	 * Figue out which kind of vdso tuple we get.
	 */
	if (vma_entry_is(&vmas[index], VMA_AREA_VDSO))
		vma_vdso = &vmas[index];
	else if (vma_entry_is(&vmas[index], VMA_AREA_VVAR))
		vma_vvar = &vmas[index];

	if (index < (nr_vmas - 1)) {
		if (vma_entry_is(&vmas[index + 1], VMA_AREA_VDSO))
			vma_vdso = &vmas[index + 1];
		else if (vma_entry_is(&vmas[index + 1], VMA_AREA_VVAR))
			vma_vvar = &vmas[index + 1];
	}

	if (!vma_vdso) {
		pr_err("Can't find vDSO area in image\n");
		return -1;
	}

	/*
	 * vDSO mark overwrites Elf program header of proxy vDSO thus
	 * it must never ever be greater in size.
	 */
	BUILD_BUG_ON(sizeof(struct vdso_mark) > sizeof(Elf64_Phdr));

	/*
	 * Find symbols in vDSO zone read from image.
	 */
	if (vdso_fill_symtable((void *)vma_vdso->start, vma_entry_len(vma_vdso), &s))
		return -1;

	/*
	 * Proxification strategy
	 *
	 *  - There might be two vDSO zones: vdso code and optionally vvar data
	 *  - To be able to use in-place remapping we need
	 *
	 *    a) Size and order of vDSO zones are to match
	 *    b) Symbols offsets must match
	 *    c) Have same number of vDSO zones
	 */
	if (vma_entry_len(vma_vdso) == vdso_vma_size(sym_rt)) {
		size_t i;

		for (i = 0; i < ARRAY_SIZE(s.symbols); i++) {
			if (s.symbols[i].offset != sym_rt->symbols[i].offset)
				break;
		}

		if (i == ARRAY_SIZE(s.symbols)) {
			if (vma_vvar && sym_rt->vvar_start != VVAR_BAD_ADDR) {
				remap_rt = (vvar_vma_size(sym_rt) == vma_entry_len(vma_vvar));
				if (remap_rt) {
					long delta_rt = sym_rt->vvar_start - sym_rt->vma_start;
					long delta_this = vma_vvar->start - vma_vdso->start;

					remap_rt = (delta_rt ^ delta_this) < 0 ? false : true;
				}
			} else
				remap_rt = true;
		}
	}

	pr_debug("image [vdso] %lx-%lx [vvar] %lx-%lx\n",
		 vma_vdso->start, vma_vdso->end,
		 vma_vvar ? vma_vvar->start : VVAR_BAD_ADDR,
		 vma_vvar ? vma_vvar->end : VVAR_BAD_ADDR);

	/*
	 * Easy case -- the vdso from image has same offsets, order and size
	 * as runtime, so we simply remap runtime vdso to dumpee position
	 * without generating any proxy.
	 *
	 * Note we may remap VVAR vdso as well which might not yet been mapped
	 * by a caller code. So drop VMA_AREA_REGULAR from it and caller would
	 * not touch it anymore.
	 */
	if (remap_rt) {
		int ret = 0;

		pr_info("Runtime vdso/vvar matches dumpee, remap inplace\n");

		if (sys_munmap((void *)vma_vdso->start, vma_entry_len(vma_vdso))) {
			pr_err("Failed to unmap %s\n", who);
			return -1;
		}

		if (vma_vvar) {
			if (sys_munmap((void *)vma_vvar->start, vma_entry_len(vma_vvar))) {
				pr_err("Failed to unmap %s\n", who);
				return -1;
			}

			if (vma_vdso->start < vma_vvar->start) {
				ret  = vdso_remap(who, vdso_rt_parked_at, vma_vdso->start, vdso_vma_size(sym_rt));
				vdso_rt_parked_at += vdso_vma_size(sym_rt);
				ret |= vdso_remap(who, vdso_rt_parked_at, vma_vvar->start, vvar_vma_size(sym_rt));
			} else {
				ret  = vdso_remap(who, vdso_rt_parked_at, vma_vvar->start, vvar_vma_size(sym_rt));
				vdso_rt_parked_at += vvar_vma_size(sym_rt);
				ret |= vdso_remap(who, vdso_rt_parked_at, vma_vdso->start, vdso_vma_size(sym_rt));
			}
		} else
			ret = vdso_remap(who, vdso_rt_parked_at, vma_vdso->start, vdso_vma_size(sym_rt));

		return ret;
	}

	/*
	 * Now complex case -- we need to proxify calls. We redirect
	 * calls from dumpee vdso to runtime vdso, making dumpee
	 * to operate as proxy vdso.
	 */
	pr_info("Runtime vdso mismatches dumpee, generate proxy\n");

	/*
	 * Don't forget to shift if vvar is before vdso.
	 */
	if (sym_rt->vvar_start != VDSO_BAD_ADDR &&
	    sym_rt->vvar_start < sym_rt->vma_start)
		vdso_rt_parked_at += vvar_vma_size(sym_rt);

	if (vdso_redirect_calls((void *)vdso_rt_parked_at,
				(void *)vma_vdso->start,
				sym_rt, &s)) {
		pr_err("Failed to proxify dumpee contents\n");
		return -1;
	}

	/*
	 * Put a special mark into runtime vdso, thus at next checkpoint
	 * routine we could detect this vdso and do not dump it, since
	 * it's auto-generated every new session if proxy required.
	 */
	sys_mprotect((void *)vdso_rt_parked_at,  vdso_vma_size(sym_rt), PROT_WRITE);
	vdso_put_mark((void *)vdso_rt_parked_at, vma_vdso->start, vma_vvar ? vma_vvar->start : VVAR_BAD_ADDR);
	sys_mprotect((void *)vdso_rt_parked_at,  vdso_vma_size(sym_rt), VDSO_PROT);
	return 0;
}

#else /* CONFIG_X86_64 */

int vdso_redirect_calls(void *base_to, void *base_from,
			struct vdso_symtable *to,
			struct vdso_symtable *from)
{
	return 0;
}

int vdso_fill_symtable(char *mem, size_t size, struct vdso_symtable *t)
{
	return 0;
}

int vdso_do_park(struct vdso_symtable *sym_rt, unsigned long park_at, unsigned long park_size)
{
	return 0;
}

int vdso_proxify(char *who, struct vdso_symtable *sym_rt,
		 unsigned long vdso_rt_parked_at, size_t index,
		 VmaEntry *vmas, size_t nr_vmas)
{
	return 0;
}

#endif /* CONFIG_X86_64 */
