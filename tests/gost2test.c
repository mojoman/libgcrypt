/* gost2test.c 2-GOST test, control example
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "../src/gcrypt-int.h"

static int verbose;
static int error_count;

static void
fail (const char *format, ...)
{
  va_list arg_ptr;

  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
  error_count++;
}

static void
die (const char *format, ...)
{
  va_list arg_ptr;

  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
  exit (1);
}



static void
check (int algo,
       const void *kek, size_t keklen,
       const void *data, size_t datalen,
       const void *expected, size_t expectedlen)
{
  gcry_error_t err;
  gcry_cipher_hd_t hd;
  unsigned char outbuf[8];
  size_t outbuflen;

  err = gcry_cipher_open (&hd, algo, GCRY_CIPHER_MODE_ECB, 0);
  if (err)
    {
      fail ("gcry_cipher_open failed: %s\n", gpg_strerror (err));
      return;
    }

  err = gcry_cipher_setkey (hd, kek, keklen);
  if (err)
    {
      fail ("gcry_cipher_setkey failed: %s\n", gpg_strerror (err));
      return;
    }

  outbuflen = datalen;
  if (outbuflen > sizeof outbuf)
    err = gpg_error (GPG_ERR_INTERNAL);
  else
    err = gcry_cipher_encrypt (hd, outbuf, outbuflen, data, datalen);
  if (err)
    {
      fail ("gcry_cipher_encrypt failed: %s\n", gpg_strerror (err));
      return;
    }

  if (outbuflen != expectedlen || memcmp (outbuf, expected, expectedlen))
    {
       fail ("mismatch at encryption!\n");
    }

  if (verbose)
    {
      const unsigned char *s;
      int i;
      fprintf (stderr, "Encrypt computed: ");
      for (i = 0; i < outbuflen; i++)
	fprintf (stderr, "%02x ", outbuf[i]);
      fprintf (stderr, "\nexpected: ");
      for (s = expected, i = 0; i < expectedlen; s++, i++)
	fprintf (stderr, "%02x ", *s);
      putc ('\n', stderr);
    }


  outbuflen = expectedlen;
  if (outbuflen > sizeof outbuf)
    err = gpg_error (GPG_ERR_INTERNAL);
  else
    err = gcry_cipher_decrypt (hd, outbuf, outbuflen, expected, expectedlen);
  if (err)
    {
      fail ("gcry_cipher_decrypt failed: %s\n", gpg_strerror (err));
      return;
    }

  if (outbuflen != datalen || memcmp (outbuf, data, datalen))
    {
      fail ("mismatch at decryption!\n");
    }

  if (verbose)
    {
      const unsigned char *s;
      int i;

      fprintf (stderr, "Decrypt computed: ");
      for (i = 0; i < outbuflen; i++)
	fprintf (stderr, "%02x ", outbuf[i]);
      fprintf (stderr, "\nexpected: ");
      for (s = data, i = 0; i < datalen; s++, i++)
        fprintf (stderr, "%02x ", *s);
      putc ('\n', stderr);
    }

  gcry_cipher_close (hd);
}


static void
check_all (void)
{
  if (verbose)
    fprintf (stderr, "Control example 1\n");
  check
    (GCRY_CIPHER_GOST2,
     "\x86\x3C\x01\xE5\xC2\x0B\x2E\x3F\xBB\x36\xD4\xDC\x45\x99\xE2\x3F\x4A\x55"
     "\x44\xF1\xB8\xBE\xFF\x84\x53\x64\xF2\x33\x9D\x70\x89\x7D", 32,
     "\xCF\xF1\x90\xC2\xC5\x19\x00\x4B", 8,
     "\xD4\xCF\xEC\x33\xB3\x5C\xA5\x94", 8);
}

int
main (int argc, char **argv)
{
  int debug = 0;

  if (argc > 1 && !strcmp (argv[1], "--verbose"))
    verbose = 1;
  else if (argc > 1 && !strcmp (argv[1], "--debug"))
    verbose = debug = 1;

  if (!gcry_check_version (GCRYPT_VERSION))
    die ("version mismatch\n");

  gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
  if (debug)
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1u, 0);
  check_all ();

  return error_count ? 1 : 0;
}
