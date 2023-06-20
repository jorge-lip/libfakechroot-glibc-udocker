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

#ifdef HAVE_SETXATTR

#include "libfakechroot.h"

#include <errno.h>

/*
 * Make sure we call the setxattr, from libc and not from libattr
 * Otherwise we get a loop where fakechroot calls libattr and then
 * libattr calls libc, this last call is also intercepted by
 * fakechroot creating a loop.
 *
 * We get the function address directly from libc, alternatively
 * if FAKECHROOT_LIBC is not defined an error is returned.
 */

wrapper(setxattr, int, (const char * path, const char * name, const void * value, size_t size, int flags))
{
    static int (*next_setxattr)(const char *, const char *, const void *, size_t, int);

    debug("setxattr(\"%s\", \"%s\", &value, %zd, %d)", path, name, size, flags);
    expand_chroot_path(path);

    if (! next_setxattr)
        next_setxattr = get_from_libc("setxattr");

    if (next_setxattr)
        return next_setxattr(path, name, value, size, flags);

    debug("setxattr return(-1)");
    __set_errno(ENOTSUP);
    return -1;

    /*
    debug("setxattr(\"%s\", \"%s\", &value, %zd, %d)", path, name, size, flags);
    expand_chroot_path(path);
    return nextcall(setxattr)(path, name, value, size, flags);
    */
}

#else
typedef int empty_translation_unit;
#endif
