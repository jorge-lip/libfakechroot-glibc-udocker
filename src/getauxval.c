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

#if defined(HAVE_GETAUXVAL)

#include <sys/auxv.h>

#include "libfakechroot.h"

wrapper(getauxval, unsigned long, (unsigned long type))
{
    char *pathname;

    debug("getauxval(%ld)", type);

    if (type != AT_EXECFN) {
	return nextcall(getauxval)(type);
    } else {
	if ((pathname = (char *) nextcall(getauxval)(type)) == 0) {
            return 0;
	}
        udocker_host_narrow_chroot_path(pathname);
	return pathname;
    }
}

#else
typedef int empty_translation_unit;
#endif
