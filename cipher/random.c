/* random.c  -	random number generator
 *	Copyright (C) 1998 Free Software Foundation, Inc.
 *
 * This file is part of GNUPG.
 *
 * GNUPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "util.h"
#include "cipher.h"
#include "ttyio.h"
#include "i18n.h"

struct cache {
    int len;
    byte buffer[100]; /* fixme: should be allocated with m_alloc_secure()*/
};

static struct cache cache[3];
#define MASK_LEVEL(a) do {if( a > 2 ) a = 2; else if( a < 0 ) a = 0; } while(0)


static void fill_buffer( byte *buffer, size_t length, int level );
static int quick_test;


int
quick_random_gen( int onoff )
{
    int last = quick_test;
    if( onoff != -1 )
	quick_test = onoff;
  #ifndef HAVE_DEV_RANDOM
    last = 1; /* insecure RNG */
  #endif
    return last;
}


/****************
 * Fill the buffer with LENGTH bytes of cryptologic strong
 * random bytes. level 0 is not very strong, 1 is strong enough
 * for most usage, 2 is good for key generation stuff but may be very slow.
 */
void
randomize_buffer( byte *buffer, size_t length, int level )
{
    for( ; length; length-- )
	*buffer++ = get_random_byte(level);
}


byte
get_random_byte( int level )
{
    MASK_LEVEL(level);
    if( !cache[level].len ) {
	fill_buffer(cache[level].buffer, DIM(cache[level].buffer), level );
	cache[level].len = DIM(cache[level].buffer);
    }

    return cache[level].buffer[--cache[level].len];
}



#ifdef HAVE_DEV_RANDOM

static int
open_device( const char *name, int minor )
{
    int fd;
    struct stat sb;

    fd = open( name, O_RDONLY );
    if( fd == -1 )
	log_fatal("can't open %s: %s\n", name, strerror(errno) );
    if( fstat( fd, &sb ) )
	log_fatal("stat() off %s failed: %s\n", name, strerror(errno) );
  #if defined(__sparc__) && defined(__linux__)
    #warning something is wrong with UltraPenguin /dev/random
  #else
    if( !S_ISCHR(sb.st_mode) )
	log_fatal("invalid random device!\n" );
  #endif
    return fd;
}


static void
fill_buffer( byte *buffer, size_t length, int level )
{
    static int fd_urandom = -1;
    static int fd_random = -1;
    int fd;
    int n;
    int warn=0;

    if( level == 2 && !quick_test ) {
	if( fd_random == -1 )
	    fd_random = open_device( "/dev/random", 8 );
	fd = fd_random;
    }
    else {
	if( fd_urandom == -1 )
	    fd_urandom = open_device( "/dev/urandom", 9 );
	fd = fd_urandom;
    }


    do {
	fd_set rfds;
	struct timeval tv;
	int rc;

	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);
	tv.tv_sec = 3;
	tv.tv_usec = 0;
	if( !(rc=select(fd+1, &rfds, NULL, NULL, &tv)) ) {
	    if( !warn )
		tty_printf( _(
"\n"
"Not enough random bytes available.  Please do some other work to give\n"
"the OS a chance to collect more entropy! (Need %d more bytes)\n"), length );
	    warn = 1;
	    continue;
	}
	else if( rc == -1 ) {
	    tty_printf("select() error: %s\n", strerror(errno));
	    continue;
	}

	assert( length < 200 );
	do {
	    n = read(fd, buffer, length );
	    if( n > length ) {
		log_error("bogus read from random device (n=%d)\n", n );
		n = length;
	    }
	} while( n == -1 && errno == EINTR );
	if( n == -1 )
	    log_fatal("read error on random device: %s\n", strerror(errno) );
	assert( n <= length );
	buffer += n;
	length -= n;
    } while( length );
}

#else /* not HAVE_DEV_RANDOM */


#ifndef RAND_MAX   /* for SunOS */
  #define RAND_MAX 32767
#endif

static void
fill_buffer( byte *buffer, size_t length, int level )
{
    static int initialized=0;

    if( !initialized ) {
	log_info(_("warning: using insecure random number generator!!\n"));
	tty_printf(_("The random number generator is only a kludge to let\n"
		   "it compile - it is in no way a strong RNG!\n\n"
		   "DON'T USE ANY DATA GENERATED BY THIS PROGRAM!!\n\n"));
	initialized=1;
      #ifdef HAVE_RAND
	srand(make_timestamp()*getpid());
      #else
	srandom(make_timestamp()*getpid());
      #endif
    }

  #ifdef HAVE_RAND
    while( length-- )
	*buffer++ = ((unsigned)(1 + (int) (256.0*rand()/(RAND_MAX+1.0)))-1);
  #else
    while( length-- )
	*buffer++ = ((unsigned)(1 + (int) (256.0*random()/(RAND_MAX+1.0)))-1);
  #endif
}

#endif

