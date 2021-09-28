/* readpng.c
 *
 * Copyright (c) 2013 John Cunningham Bowler
 *
 * Last changed in libpng 1.6.1 [March 28, 2013]
 *
 * This code is released under the libpng license.
 * For conditions of distribution and use, see the disclaimer
 * and license in png.h
 *
 * Load an arbitrary number of PNG files (from the command line, or, if there
 * are no arguments on the command line, from stdin) then run a time test by
 * reading each file by row.  The test does nothing with the read result and
 * does no transforms.  The only output is a time as a floating point number of
 * seconds with 9 decimal digits.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#if defined(HAVE_CONFIG_H) && !defined(PNG_NO_CONFIG_H)
#  include <config.h>
#endif

/* Define the following to use this test against your installed libpng, rather
 * than the one being built here:
 */
#ifdef PNG_FREESTANDING_TESTS
#  include <png.h>
#else
#  include "../../png.h"
#endif

#define vvdump_ignore __attribute__((annotate("vvdump_ignore")))

vvdump_ignore
__attribute__((no_sanitize("address")))
static int
read_png(FILE *fp)
{
   png_structp png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING,0,0,0);
   png_infop info_ptr = NULL;
   png_bytep row = NULL, display = NULL;

   if (png_ptr == NULL)
      return 0;

   // Took out the calls to free because row and display aren't malloc'ed here yet.
   if (setjmp(png_jmpbuf(png_ptr)))
   {
      png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
      return 0;
   }

   png_init_io(png_ptr, fp);

   info_ptr = png_create_info_struct(png_ptr);
   if (info_ptr == NULL)
      png_error(png_ptr, "OOM allocating info structure");

   png_set_keep_unknown_chunks(png_ptr, PNG_HANDLE_CHUNK_ALWAYS, NULL, 0);

   png_read_info(png_ptr, info_ptr);

   {
      png_size_t rowbytes = png_get_rowbytes(png_ptr, info_ptr);

      row = malloc(rowbytes);
      display = malloc(rowbytes);

      if (row == NULL || display == NULL)
         png_error(png_ptr, "OOM allocating row buffers");

      // Copied this here so that row and display will be initialized. Otherwise there
      // is a memory leak...
      if (setjmp(png_jmpbuf(png_ptr)))
      {
         png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
         if (row != NULL) free(row);
         if (display != NULL) free(display);
         return 0;
      }

      {
         png_uint_32 height = png_get_image_height(png_ptr, info_ptr);
         int passes = png_set_interlace_handling(png_ptr);
         int pass;

         png_start_read_image(png_ptr);

         for (pass = 0; pass < passes; ++pass)
         {
            png_uint_32 y = height;

            /* NOTE: this trashes the row each time; interlace handling won't
             * work, but this avoids memory thrashing for speed testing.
             */
            while (y-- > 0) {
               png_read_row(png_ptr, row, display);
            }
         }
      }
   }

   /* Make sure to read to the end of the file: */
   png_read_end(png_ptr, info_ptr);
   png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
   free(row);
   free(display);
   return 1;
}

vvdump_ignore
__attribute__((no_sanitize("address")))
int
main(void)
{
   /* Exit code 0 on success. */
   return !read_png(stdin);
}
