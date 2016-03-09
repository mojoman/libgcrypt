/* gost2.c - 2-GOST implementation for Libgcrypt
 * Copyright (C) 2016 Free Software Foundation, Inc.
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
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* 2GOST is a modified version of GOST 28147-89 cipher,
 * as proposed by Dmukh, Dygin, Marshalko [2014].
 * 
 */

#include <config.h>
#include "types.h"
#include "g10lib.h"
#include "cipher.h"
#include "bufhelp.h"

#include "gost2.h"
#include "gost2-sb.h"

static gcry_err_code_t
gost2_setkey (void *c, const byte *key, unsigned keylen)
{
  int i;
  GOST2_context *ctx = c;

  if (keylen != 256 / 8)
    return GPG_ERR_INV_KEYLEN;

  if (!ctx->sbox)
    ctx->sbox = sbox_test_3411;

  for (i = 0; i < 8; i++)
    {
      ctx->key[i] = buf_get_le32(&key[4*i]);
    }
  return GPG_ERR_NO_ERROR;
}

static u32
gost2_val (GOST2_context *ctx, u32 cm1, int subkey)
{
  cm1 += ctx->key[subkey];
  cm1 = ctx->sbox[0*256 + ((cm1 >>  0) & 0xff)] |
        ctx->sbox[1*256 + ((cm1 >>  8) & 0xff)] |
        ctx->sbox[2*256 + ((cm1 >> 16) & 0xff)] |
        ctx->sbox[3*256 + ((cm1 >> 24) & 0xff)];
  return cm1;
}

static unsigned int
_gost2_encrypt_data (void *c, u32 *o1, u32 *o2, u32 n1, u32 n2)
{
  GOST2_context *ctx = c;
  /* 2-GOST uses a special key table for its rounds,
     for reference check the [2014] article.
  */
  n2 ^= gost2_val (ctx, n1, 0); n1 ^= gost2_val (ctx, n2, 1);
  n2 ^= gost2_val (ctx, n1, 2); n1 ^= gost2_val (ctx, n2, 3);
  n2 ^= gost2_val (ctx, n1, 4); n1 ^= gost2_val (ctx, n2, 5);
  n2 ^= gost2_val (ctx, n1, 6); n1 ^= gost2_val (ctx, n2, 7);

  n2 ^= gost2_val (ctx, n1, 3); n1 ^= gost2_val (ctx, n2, 4);
  n2 ^= gost2_val (ctx, n1, 5); n1 ^= gost2_val (ctx, n2, 6);
  n2 ^= gost2_val (ctx, n1, 7); n1 ^= gost2_val (ctx, n2, 0);
  n2 ^= gost2_val (ctx, n1, 1); n1 ^= gost2_val (ctx, n2, 2);

  n2 ^= gost2_val (ctx, n1, 5); n1 ^= gost2_val (ctx, n2, 6);
  n2 ^= gost2_val (ctx, n1, 7); n1 ^= gost2_val (ctx, n2, 0);
  n2 ^= gost2_val (ctx, n1, 1); n1 ^= gost2_val (ctx, n2, 2);
  n2 ^= gost2_val (ctx, n1, 3); n1 ^= gost2_val (ctx, n2, 4);

  n2 ^= gost2_val (ctx, n1, 6); n1 ^= gost2_val (ctx, n2, 5);
  n2 ^= gost2_val (ctx, n1, 4); n1 ^= gost2_val (ctx, n2, 3);
  n2 ^= gost2_val (ctx, n1, 2); n1 ^= gost2_val (ctx, n2, 1);
  n2 ^= gost2_val (ctx, n1, 0); n1 ^= gost2_val (ctx, n2, 7);

  *o1 = n2;
  *o2 = n1;

  return /* burn_stack */ 4*sizeof(void*) /* func call */ +
                          3*sizeof(void*) /* stack */ +
                          4*sizeof(void*) /* gost2_val call */;
}

static unsigned int
gost2_encrypt_block (void *c, byte *outbuf, const byte *inbuf)
{
  GOST2_context *ctx = c;
  u32 n1, n2;
  unsigned int burn;

  n1 = buf_get_le32 (inbuf);
  n2 = buf_get_le32 (inbuf+4);

  burn = _gost2_encrypt_data(ctx, &n1, &n2, n1, n2);

  buf_put_le32 (outbuf+0, n1);
  buf_put_le32 (outbuf+4, n2);

  return /* burn_stack */ burn + 6*sizeof(void*) /* func call */;
}

unsigned int _gcry_gost2_enc_data (GOST2_context *c, const u32 *key,
    u32 *o1, u32 *o2, u32 n1, u32 n2)
{
  c->sbox = sbox_test;
  memcpy (c->key, key, 8*4);
  return _gost2_encrypt_data (c, o1, o2, n1, n2) + 7 * sizeof(void *);
}

static unsigned int
gost2_decrypt_block (void *c, byte *outbuf, const byte *inbuf)
{
  GOST2_context *ctx = c;
  u32 n1, n2;

  n1 = buf_get_le32 (inbuf);
  n2 = buf_get_le32 (inbuf+4);

  n2 ^= gost2_val (ctx, n1, 7); n1 ^= gost2_val (ctx, n2, 0);
  n2 ^= gost2_val (ctx, n1, 1); n1 ^= gost2_val (ctx, n2, 2);
  n2 ^= gost2_val (ctx, n1, 3); n1 ^= gost2_val (ctx, n2, 4);
  n2 ^= gost2_val (ctx, n1, 5); n1 ^= gost2_val (ctx, n2, 6);

  n2 ^= gost2_val (ctx, n1, 4); n1 ^= gost2_val (ctx, n2, 3);
  n2 ^= gost2_val (ctx, n1, 2); n1 ^= gost2_val (ctx, n2, 1);
  n2 ^= gost2_val (ctx, n1, 0); n1 ^= gost2_val (ctx, n2, 7);
  n2 ^= gost2_val (ctx, n1, 6); n1 ^= gost2_val (ctx, n2, 5);

  n2 ^= gost2_val (ctx, n1, 2); n1 ^= gost2_val (ctx, n2, 1);
  n2 ^= gost2_val (ctx, n1, 0); n1 ^= gost2_val (ctx, n2, 7);
  n2 ^= gost2_val (ctx, n1, 6); n1 ^= gost2_val (ctx, n2, 5);
  n2 ^= gost2_val (ctx, n1, 4); n1 ^= gost2_val (ctx, n2, 3);

  n2 ^= gost2_val (ctx, n1, 7); n1 ^= gost2_val (ctx, n2, 6);
  n2 ^= gost2_val (ctx, n1, 5); n1 ^= gost2_val (ctx, n2, 4);
  n2 ^= gost2_val (ctx, n1, 3); n1 ^= gost2_val (ctx, n2, 2);
  n2 ^= gost2_val (ctx, n1, 1); n1 ^= gost2_val (ctx, n2, 0);

  buf_put_le32 (outbuf+0, n2);
  buf_put_le32 (outbuf+4, n1);

  return /* burn_stack */ 4*sizeof(void*) /* func call */ +
                          3*sizeof(void*) /* stack */ +
                          4*sizeof(void*) /* gost2_val call */;
}

static gpg_err_code_t
gost2_set_sbox (GOST2_context *ctx, const char *oid)
{
  int i;

  for (i = 0; gost2_oid_map[i].oid; i++)
    {
      if (!strcmp(gost2_oid_map[i].oid, oid))
        {
          ctx->sbox = gost2_oid_map[i].sbox;
          return 0;
        }
    }
  return GPG_ERR_VALUE_NOT_FOUND;
}

static gpg_err_code_t
gost2_set_extra_info (void *c, int what, const void *buffer, size_t buflen)
{
  GOST2_context *ctx = c;
  gpg_err_code_t ec = 0;

  (void)buffer;
  (void)buflen;

  switch (what)
    {
    case GCRYCTL_SET_SBOX:
      ec = gost2_set_sbox (ctx, buffer);
      break;

    default:
      ec = GPG_ERR_INV_OP;
      break;
    }
  return ec;
}

static gcry_cipher_oid_spec_t oids_gost2[] =
  {
    { "0.0.0.0.0.0.0", GCRY_CIPHER_MODE_CFB },
    { NULL }
  };

gcry_cipher_spec_t _gcry_cipher_spec_gost2 =
  {
    GCRY_CIPHER_GOST2, {0, 0},
    "2-GOST", NULL, oids_gost2, 8, 256,
    sizeof (GOST2_context),
    gost2_setkey,
    gost2_encrypt_block,
    gost2_decrypt_block,
    NULL, NULL, NULL, gost2_set_extra_info,
  };
