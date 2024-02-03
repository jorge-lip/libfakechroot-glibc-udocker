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

#ifdef HAVE_DLMOPEN

#define _GNU_SOURCE
#include <dlfcn.h>
#include "libfakechroot.h"

/*
 * udocker  2-Feb-2024
 * Narrowing of filename is only performed when it contains a slash. 
 * A name without a slash does not mean that the file is in the current 
 * working directory, instead tells the loader to search for the file.
 */


wrapper(dlmopen, void *, (Lmid_t nsid, const char * filename, int flag))
{
    debug("dlmopen(&nsid, \"%s\", %d)", filename, flag);
    if (filename && strchr(filename, '/')) {
        expand_chroot_path(filename);
    }

    return nextcall(dlmopen)(nsid, filename, flag);
}

#else
typedef int empty_translation_unit;
#endif
