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

#ifdef HAVE_DLADDR

#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>

#include "libfakechroot.h"

/*
 * udocker  2-Feb-2024
 * Narrowing of dli_fname and dli_sname is only performed
 * when they contain a slash. A name without a slash does
 * not mean that the file is in the current working
 * directory. 
 */


wrapper(dladdr, int, (const void * addr, Dl_info * info))
{
    int ret;

    debug("dladdr(0x%x, &info)", addr);

    ret = nextcall(dladdr)(addr, info);

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

    return ret;
}

#else
typedef int empty_translation_unit;
#endif
