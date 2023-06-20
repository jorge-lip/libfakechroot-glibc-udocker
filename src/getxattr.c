/*
    libfakechroot -- fake chroot environment
    Copyright (c) 2010, 2013 Piotr Roszatycki <dexter@debian.org>

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

#ifdef HAVE_GETXATTR

#include <sys/types.h>
#include <stddef.h>
#include "libfakechroot.h"

#include <errno.h>

/*
 * Make sure we call the getxattr from libc and not from libattr
 * Otherwise we get a loop where fakechroot calls libattr and then
 * libattr calls libc, this last call is also intercepted by
 * fakechroot creating a loop.
 *
 * We get the function address directly from libc, alternatively
 * if FAKECHROOT_LIBC is not defined an error is returned.
 */

wrapper(getxattr, ssize_t, (const char * path, const char * name, void * value, size_t size))
{
    static ssize_t (*next_getxattr)(const char *, const char *, void *, size_t);

    debug("getxattr(\"%s\", \"%s\", &value, %zd)", path, name, size);
    expand_chroot_path(path);

    if (! next_getxattr)
        next_getxattr = get_from_libc("getxattr");

    if (next_getxattr)
        return next_getxattr(path, name, value, size);

    debug("getxattr return(-1)");
    __set_errno(ENOTSUP);
    return -1;

    /*
    debug("getxattr(\"%s\", \"%s\", &value, %zd)", path, name, size);
    expand_chroot_path(path);
    return nextcall(getxattr)(path, name, value, size);
    */
}

#else
typedef int empty_translation_unit;
#endif
