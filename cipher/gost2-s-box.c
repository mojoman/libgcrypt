/* gost2-s-box.c - 2-GOST S-Box expander
 * Copyright (C) 2016 Wartan Hachaturow
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

#include <stdio.h>
#include <stdlib.h>

#define DIM(v) (sizeof(v)/sizeof((v)[0]))

struct gost2_sbox
{
  const char *name;
  const char *oid;
  unsigned char sbox[16*8];
} gost2_sboxes[] = {
  { "test", "0.0.0.0.0.0.0", {              /* 2-GOST uses just 2 S-Boxes */
      0x6, 0x6, 0x6, 0x6, 0xE, 0xE, 0xE, 0xE,
      0xA, 0xA, 0xA, 0xA, 0x0, 0x0, 0x0, 0x0,
      0xF, 0xF, 0xF, 0xF, 0x8, 0x8, 0x8, 0x8,
      0x4, 0x4, 0x4, 0x4, 0x1, 0x1, 0x1, 0x1,
	                                  
      0x3, 0x3, 0x3, 0x3, 0x7, 0x7, 0x7, 0x7,
      0x8, 0x8, 0x8, 0x8, 0xA, 0xA, 0xA, 0xA,
      0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5,
      0x0, 0x0, 0x0, 0x0, 0x6, 0x6, 0x6, 0x6,
	                                  
      0xD, 0xD, 0xD, 0xD, 0xD, 0xD, 0xD, 0xD,
      0xE, 0xE, 0xE, 0xE, 0x2, 0x2, 0x2, 0x2,
      0x7, 0x7, 0x7, 0x7, 0x4, 0x4, 0x4, 0x4,
      0x1, 0x1, 0x1, 0x1, 0x9, 0x9, 0x9, 0x9,
	                                  
      0x2, 0x2, 0x2, 0x2, 0x3, 0x3, 0x3, 0x3,
      0xB, 0xB, 0xB, 0xB, 0xF, 0xF, 0xF, 0xF,
      0xC, 0xC, 0xC, 0xC, 0xC, 0xC, 0xC, 0xC,
      0x9, 0x9, 0x9, 0x9, 0xB, 0xB, 0xB, 0xB,
    }
  }
};

int main(int argc, char **argv)
{
  unsigned int i, j, s;
  FILE *f;

  if (argc == 1)
    f = stdin;
  else
    f = fopen(argv[1], "w");

  if (!f)
    {
      perror("fopen");
      exit(1);
    }

  for (s = 0; s < DIM(gost_sboxes); s++)
    {
      unsigned char *sbox = gost2_sboxes[s].sbox;
      fprintf (f, "static const u32 sbox_%s[4*256] =\n  {", gost2_sboxes[s].name);
      for (i = 0; i < 4; i++) {
        fprintf (f, 	"\n    /* %d */\n   ", i);
        for (j = 0; j < 256; j++) {
          unsigned int val;
          if (j % 4 == 0 && j != 0)
            fprintf (f, "\n   ");
          val = sbox[ (j & 0xf) * 8 + 2 * i + 0] |
               (sbox[ (j >> 4)  * 8 + 2 * i + 1] << 4);
          val <<= (8*i);
          val = (val << 11) | (val >> 21);
          fprintf (f, " 0x%08x,", val);
        }
      }
      fprintf (f, "\n  };\n\n");
    }

  fprintf (f, "static struct\n{\n  const char *oid;\n  const u32 *sbox;\n} gost_oid_map[] = {\n");

  for (s = 0; s < DIM(gost_sboxes); s++)
    {
      fprintf (f, "  { \"%s\", sbox_%s },\n", gost2_sboxes[s].oid, gost2_sboxes[s].name );
    }

  fprintf(f, "  { NULL, NULL }\n};\n");

  fclose (f);

  return 0;
}
