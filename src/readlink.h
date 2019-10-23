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

#ifndef __READLINK_H
#define __READLINK_H

#include <config.h>

#include "libfakechroot.h"

wrapper_proto(readlink, READLINK_TYPE_RETURN, (const char *, char *, READLINK_TYPE_ARG3()));

LOCAL
READLINK_TYPE_RETURN udocker_readlink(const char * path, char * buf, READLINK_TYPE_ARG3(bufsiz));
#endif
