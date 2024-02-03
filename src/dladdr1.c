/*
    libfakechroot -- fake chroot environment
    Copyright (c) 2014 Robin McCorkell <rmccorkell@karoshi.org.uk>

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
*/


#include <config.h>

#ifdef HAVE_DLADDR1

#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>
#include <link.h>

#include "libfakechroot.h"

/*
 * udocker  2-Feb-2024
 * New function added in Feb 2024
 * Narrowing of dli_fname, dli_sname, l_name is only performed
 * when they contain a slash. A name without a slash does not
 * mean that the file is in the current working directory. 
 */


wrapper(dladdr1, int, (const void * addr, Dl_info * info, void **extra_info, int flags))
{
    int ret;
    struct link_map *link_map_p;

    debug("dladdr1(0x%x, &info, &&extra_info, %d)", addr, flags);

    if ((ret = nextcall(dladdr1)(addr, info, extra_info, flags)) == 0) {
	return 0;
    }

    if (info->dli_fname && strchr(info->dli_fname, '/')) {
        narrow_chroot_path(info->dli_fname);
	/*
        udocker_host_narrow_chroot_path(info->dli_fname);
	*/
    }

    /* translate symbol only if looks like a path (has a slash) */
    if (info->dli_sname && strchr(info->dli_sname, '/')) {
        narrow_chroot_path(info->dli_sname);
	/*
        udocker_host_narrow_chroot_path(info->dli_sname);
	*/
    }

    if (flags == RTLD_DL_LINKMAP) {
	link_map_p = *extra_info;
	while (link_map_p != NULL) {
	    if (link_map_p->l_name && strchr(link_map_p->l_name, '/')) {
                narrow_chroot_path(link_map_p->l_name);
		/*
                udocker_host_narrow_chroot_path(link_map_p->l_name);
		*/
	    }
	    link_map_p = link_map_p->l_next;
	}
    }	    

    return ret;
}

#else
typedef int empty_translation_unit;
#endif
