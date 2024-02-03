/*
    libfakechroot -- fake chroot environment
    Copyright (c) 2010-2015 Piotr Roszatycki <dexter@debian.org>

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
#include <stdio.h>

#include <config.h>

#include <errno.h>
#include <stddef.h>
#include <unistd.h>
#ifdef HAVE_ALLOCA_H
# include <alloca.h>
#endif
#include <stdlib.h>
#include <fcntl.h>
#include <alloca.h>
#include "strchrnul.h"
#include "libfakechroot.h"
#include "open.h"
#include "setenv.h"
#include "readlink.h"

#ifdef HAVE_EXECVEAT


wrapper(execveat, int, (int dirfd, const char * filename, char * const argv [], char * const envp [], int flags))
{
    int status;
    int file;
    char hashbang[FAKECHROOT_PATH_MAX];
    size_t argv_max = 1024;
    const char **newargv = alloca(argv_max * sizeof (const char *));
    char **newenvp, **ep;
    char *key, *env;
    char tmpkey[1024], *tp;
    char *cmdorig;
    char tmp[FAKECHROOT_PATH_MAX];
    char substfilename[FAKECHROOT_PATH_MAX];
    char newfilename[FAKECHROOT_PATH_MAX];
    char argv0[FAKECHROOT_PATH_MAX];
    char *ptr;
    unsigned int i, j, n, newenvppos;
    unsigned int do_cmd_subst = 0;
    size_t sizeenvp;
    char c;

    char *fakechroot_base = fakechroot_preserve_getenv("FAKECHROOT_BASE");
    char *elfloader = fakechroot_preserve_getenv("FAKECHROOT_ELFLOADER");
    char *elfloader_opt_argv0 = fakechroot_preserve_getenv("FAKECHROOT_ELFLOADER_OPT_ARGV0");
    char *fakechroot_disallow_env_changes = fakechroot_preserve_getenv("FAKECHROOT_DISALLOW_ENV_CHANGES");
    char *fakechroot_library_orig = fakechroot_preserve_getenv("FAKECHROOT_LIBRARY_ORIG");
    int ld_library_real_pos = -1;

    if (elfloader && !*elfloader) elfloader = NULL;
    if (elfloader_opt_argv0 && !*elfloader_opt_argv0) elfloader_opt_argv0 = NULL;

    debug("execveat(%d, \"%s\", {\"%s\", ...}, {\"%s\", ...}, %d)",
		    dirfd, filename, argv[0], envp ? envp[0] : "(null)", flags);

    strncpy(argv0, filename, FAKECHROOT_PATH_MAX);

    /* Substitute command only if FAKECHROOT_CMD_ORIG is not set. Unset variable if it is empty. */
    cmdorig = getenv("FAKECHROOT_CMD_ORIG");
    if (cmdorig == NULL)
        do_cmd_subst = fakechroot_try_cmd_subst(getenv("FAKECHROOT_CMD_SUBST"), argv0, substfilename);
    else if (!*cmdorig)
        unsetenv("FAKECHROOT_CMD_ORIG");

    /* Scan envp and check its size */
    sizeenvp = 0;
    if (envp) {
        for (ep = (char **)envp; *ep != NULL; ++ep) {
            sizeenvp++;
        }
    }

    /* Copy envp to newenvp */
    newenvp = malloc( (sizeenvp + preserve_env_list_count + 1) * sizeof (char *) );
    if (newenvp == NULL) {
        __set_errno(ENOMEM);
        return -1;
    }
    newenvppos = 0;

    /* Create new envp */
    newenvp[newenvppos] = malloc(strlen("FAKECHROOT=true") + 1);
    strcpy(newenvp[newenvppos], "FAKECHROOT=true");
    newenvppos++;

    /* Preserve old environment variables if not overwritten by new */
    for (j = 0; j < preserve_env_list_count; j++) {
        key = preserve_env_list[j];
        env = fakechroot_preserve_getenv(key);
        if (env != NULL && *env) {
            if (do_cmd_subst) { /* if cmd subst disable ENV to enable execution of host binaries*/
                if (strcmp(key, "FAKECHROOT_BASE") == 0) {
                    key = "FAKECHROOT_BASE_ORIG";
                } else if (strcmp(key, "LD_PRELOAD") == 0) {
                    key = "LD_PRELOAD_ORIG";
                } else if (strcmp(key, "LD_LIBRARY_PATH") == 0) {
                    key = "LD_LIBRARY_PATH_ORIG";
                }
            }
            if (envp && !fakechroot_disallow_env_changes) {
                for (ep = (char **) envp; *ep != NULL; ++ep) {
                    strncpy(tmpkey, *ep, 1024);
                    tmpkey[1023] = 0;
                    if ((tp = strchr(tmpkey, '=')) != NULL) {
                        *tp = 0;
                        if (strcmp(tmpkey, key) == 0) {
                            goto skip1;
                        }
                    }
                }
            }
            newenvp[newenvppos] = malloc(strlen(key) + strlen(env) + 3);
            if (strcmp(key, "LD_LIBRARY_REAL") == 0)
                ld_library_real_pos = newenvppos;
            strcpy(newenvp[newenvppos], key);
            strcat(newenvp[newenvppos], "=");
            strcat(newenvp[newenvppos], env);
            newenvppos++;
        skip1: ;
        }
    }

    /* Append old envp to new envp */
    if (envp) {
        for (ep = (char **) envp; *ep != NULL; ++ep) {
            strncpy(tmpkey, *ep, 1024);
            tmpkey[1023] = 0;
            if ((tp = strchr(tmpkey, '=')) != NULL) {
                *tp = 0;
                for (j=0; j < newenvppos; j++) {  /* ignoore env vars already added */
                    if (strncmp(newenvp[j], tmpkey, strlen(tmpkey)) == 0) {
                        goto skip2;
                    }
                }
                /* if cmd subst disable ENV to enable execution of host binaries*/
                if (strcmp(tmpkey, "FAKECHROOT") == 0 ||
                        (do_cmd_subst && strcmp(tmpkey, "FAKECHROOT_BASE") == 0) ||
                        (do_cmd_subst && strcmp(tmpkey, "LD_PRELOAD") == 0)      ||
                        (do_cmd_subst && strcmp(tmpkey, "LD_LIBRARY_PATH") == 0) ) {
                    goto skip2;
                }
                /* broken */
                if (fakechroot_library_orig && ld_library_real_pos != -1 && *(tp+1) != '\0' &&
                       strcmp(tmpkey, "LD_LIBRARY_PATH") == 0) {
                    int newsize, count = 1;
                    char *dir, *iter, *ld_library_real;
                    for (iter = *ep + (tp - tmpkey) + 1; *iter; iter++)
                        if (*iter == ':') count++;
                    newsize = sizeof("LD_LIBRARY_REAL=") + strlen(fakechroot_library_orig) +
                              strlen(tp+1) + (count * (strlen(fakechroot_base) + 1)) + 4;
                    free(newenvp[ld_library_real_pos]);
                    ld_library_real = newenvp[ld_library_real_pos] = malloc(newsize);
                    strcpy(ld_library_real, "LD_LIBRARY_REAL=");
                    for (iter = dir = *ep + (tp - tmpkey) + 1; *iter ; iter++) {
                        if (*iter == ':' || *(iter + 1) == 0) {
                            if (*iter == ':') *iter = 0; 
                            strcat(ld_library_real, fakechroot_base);
                            strcat(ld_library_real, "/");
                            strcat(ld_library_real, dir);
                            strcat(ld_library_real, ":");
                            dir = iter + 1; 
                        } 
                    }
                    strcat(ld_library_real, fakechroot_library_orig);
                }
            }
            newenvp[newenvppos] = *ep;
            newenvppos++;
        skip2: ;
        }
    }

    newenvp[newenvppos] = NULL;

    if (newenvp == NULL) {
        __set_errno(ENOMEM);
        return -1;
    }

    if (do_cmd_subst) {
        newenvp[newenvppos] = malloc(strlen("FAKECHROOT_CMD_ORIG=") + strlen(filename) + 1);
        strcpy(newenvp[newenvppos], "FAKECHROOT_CMD_ORIG=");
        strcat(newenvp[newenvppos], filename);
        newenvppos++;
    }

    newenvp[newenvppos] = NULL;

    /* Exec substituded command */
    if (do_cmd_subst) {
        debug("nextcall(execveat)(%d, \"%s\", {\"%s\", ...}, {\"%s\", ...}, %d)",
		       	dirfd, substfilename, argv[0], newenvp[0], flags);

        /* if cmd subst is a placeholder like RETURN(TRUE) or RETURN(FALSE) just exit with 0 or 1 */
        if (strcmp(substfilename, CMD_SUBST_RETURN_TRUE)) {
            exit(0);
        } else if (strcmp(substfilename, CMD_SUBST_RETURN_FALSE)) {
            exit(1);
        }

        /* Indigo udocker dynamically patch executable used in mode F4 */
        fakechroot_upatch_elf(substfilename);

        status = nextcall(execveat)(dirfd, substfilename, (char * const *)argv, newenvp, flags);
        goto error;
    }

    /* Expand and check for hashbang */
    if (flags & AT_SYMLINK_NOFOLLOW) {
        l_expand_chroot_path_at(dirfd, filename);
    }
    else {
        expand_chroot_path_at(dirfd, filename);
    }
    strcpy(tmp, filename);
    filename = tmp;

    if ((file = nextcall(open)(filename, O_RDONLY)) == -1) {
        __set_errno(ENOENT);
        return -1;
    }

    i = read(file, hashbang, FAKECHROOT_PATH_MAX-2);
    close(file);
    if (i == -1) {
        __set_errno(ENOENT);
        return -1;
    }

    /* Is this an ELF binary */
    if (hashbang[0] == 127 && hashbang[1] == 'E' && hashbang[2] == 'L' && hashbang[3] == 'F') {

        /* Indigo udocker dynamically patch executable used in mode F4 */
        fakechroot_upatch_elf(filename);

        if (!elfloader) {
            status = nextcall(execveat)(dirfd, filename, argv, newenvp, flags);
            goto error;
        }

        /* Run via elfloader */
        for (i = 0, n = (elfloader_opt_argv0 ? 3 : 1); argv[i] != NULL && i < argv_max; ) {
            newargv[n++] = argv[i++];
        }

        newargv[n] = 0;

        n = 0;
        newargv[n++] = elfloader;
        if (elfloader_opt_argv0) {
            newargv[n++] = elfloader_opt_argv0;
            newargv[n++] = argv0;
        }
        newargv[n] = filename;

        debug("nextcall(execveat)(%d, \"%s\", {\"%s\", \"%s\", ...}, {\"%s\", ...}, %d)",
			dirfd, elfloader, newargv[0], newargv[n], newenvp[0], flags);
        status = nextcall(execveat)(dirfd, elfloader, (char * const *)newargv, newenvp, flags);
        goto error;
    }

    /* Indigo udocker fix spaces before #! */
    for(j = 0; hashbang[j] == ' ' && j < 16; j++);
    if (j) memmove(hashbang, hashbang + j, i);

    /* For hashbang we must fix argv[0] */
    if (hashbang[0] == '#' && hashbang[1] == '!') {
        hashbang[i] = hashbang[i+1] = 0;
        for (i = j = 2; (hashbang[i] == ' ' || hashbang[i] == '\t') && i < FAKECHROOT_PATH_MAX; i++, j++);
        for (n = 0; i < FAKECHROOT_PATH_MAX; i++) {
            c = hashbang[i];
            if (hashbang[i] == 0 || hashbang[i] == ' ' || hashbang[i] == '\t' || hashbang[i] == '\n') {
                hashbang[i] = 0;
                if (i > j) {
                    if (n == 0) {
                        ptr = &hashbang[j];
                        if (flags & AT_SYMLINK_NOFOLLOW) {
                            l_expand_chroot_path_at(dirfd, ptr);
                        }
                        else {
                            expand_chroot_path_at(dirfd, ptr);
                        }
                        strcpy(newfilename, ptr);
                    }
                    newargv[n++] = &hashbang[j];
                }
                j = i + 1;
            }
            if (c == '\n' || c == 0)
                break;
        }
    }
    else {    /* default old behavior no hashbang in first line is shell */
        char *ptr2;
        ptr = ptr2 = "/bin/sh";
        if (flags & AT_SYMLINK_NOFOLLOW) {
            l_expand_chroot_path_at(dirfd, ptr);
        }
        else {
            expand_chroot_path_at(dirfd, ptr);
        }
        strcpy(newfilename, ptr);
        n = 0;
        newargv[n++] = ptr2;
    }

    newargv[n++] = argv0;

    for (i = 1; argv[i] != NULL && i < argv_max; ) {
        newargv[n++] = argv[i++];
    }

    /* Indigo udocker dynamically patch executable used in mode F4 */
    fakechroot_upatch_elf(newfilename);

    newargv[n] = 0;

    if (!elfloader) {
        
        status = nextcall(execveat)(dirfd, newfilename, (char * const *)newargv, newenvp, flags);
        goto error;
    }

    /* Run via elfloader */
    j = elfloader_opt_argv0 ? 3 : 1;
    if (n >= argv_max - 1) {
        n = argv_max - j - 1;
    }
    newargv[n+j] = 0;
    for (i = n; i >= j; i--) {
        newargv[i] = newargv[i-j];
    }
    n = 0;
    newargv[n++] = elfloader;
    if (elfloader_opt_argv0) {
        newargv[n++] = elfloader_opt_argv0;
        newargv[n++] = argv0;
    }
    newargv[n] = newfilename;

    debug("nextcall(execveat)(%d, \"%s\", {\"%s\", \"%s\", \"%s\", ...}, {\"%s\", ...}, %d)",
		    dirfd, elfloader, newargv[0], newargv[1], newargv[n], newenvp[0], flags);
    status = nextcall(execveat)(dirfd, elfloader, (char * const *)newargv, newenvp, flags);

error:
    free(newenvp);


    return status;
}

#else
typedef int empty_translation_unit;
#endif