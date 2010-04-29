/*
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef MISC_H
#define MISC_H

#define BUFFER_LEN 4096

#define MAX_URL_LEN	8192
#define MIME_BUFFER	255
#define MIME_UNKNOWN	"application/octet-stream"

#define UNPACKED_NAME "unpacked"

#define MAX_LEVEL	10

#define MD4_DIGEST_LENGTH 16
#define	MD5_DIGEST_LENGTH 16
#define SHA_DIGEST_LENGTH 20
#define SHA256_DIGEST_LENGTH 32
#define WHIRLPOOL_DIGEST_LENGTH 64



struct cur_entry {
	struct archive *arch;
	struct archive_entry *entry;

	struct cur_entry *parentEntry;
	struct cur_entry *subEntry;

	/*This is used for bzip/gzip files only */
	struct cur_entry *childEntry;

	unsigned char buffer[BUFFER_LEN];

	CURLM *curl_multi;
	CURL *curl_easy;
	unsigned char *curl_buf;
	long long curl_len;

	char url[MAX_URL_LEN];
	char *filename;
	long long filesize;


	magic_t magic_cookie;
	char mime_type[MIME_BUFFER];

	gcry_md_hd_t hash_handle;

	/* zlib/bzlib stuffs */
	int bz;
	bz_stream bzstream;
	int z;
	z_stream zstream;

	int level;
	int jsonArray;
};

void traverse( struct cur_entry *parent );
void output( struct cur_entry *curEntry );

/* libarchive functions */
void arch_init( struct cur_entry *curEntry );
void arch_close( struct cur_entry *curEntry );
ssize_t arch_read_block_cb( struct archive *arch, void *data, const void **buf );
ssize_t arch_read_web_cb( struct archive *arch, void *data, const void **buf );

/* hash (gcry/magic) functions */
void hash_init( struct cur_entry *curEntry );
void hash_updt( struct cur_entry *curEntry, ssize_t len );
void hash_close( struct cur_entry *curEntry );


/* curl functions */
void curl_init( struct cur_entry *curEntry );
void curl_close( struct cur_entry *curEntry );
size_t curl_read_cb( void *buf, size_t len, size_t nmemb, void *data );


#endif
