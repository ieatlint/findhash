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

#include <stdio.h>
#include <string.h>
#include <curl/curl.h>
#include <archive.h>
#include <archive_entry.h>
#include <gcrypt.h>
#include <magic.h>

#include <zlib.h>
#include <bzlib.h>


#include "rehasher.h"

int main() {
	traverse( NULL );
	return 0;
}


void traverse( struct cur_entry *parent ) {
	struct cur_entry curEntry = {0};
	const void *tmp;


	if( parent != NULL ) {
		curEntry.level = parent->level + 1;
		curEntry.parentEntry = parent;
		curEntry.jsonArray = parent->jsonArray;
		curEntry.magic_cookie = parent->magic_cookie;
	}
	if( curEntry.level > MAX_LEVEL )
		return;

	/* hash init */
	hash_init( &curEntry );

	/* libcurl init */
	if( curEntry.level == 0 )
		curl_init( &curEntry );

	/* libarchive init */
	arch_init( &curEntry );


	/* archive traversal  */
	while( archive_read_next_header( curEntry.arch, &(curEntry.entry) ) == ARCHIVE_OK ) {
		curEntry.filename = (char*)archive_entry_pathname( curEntry.entry );
		
		traverse( &curEntry );

		archive_read_data_skip( curEntry.arch );

	}

	/* get any trailing items */
	if( curEntry.level == 0 )
		while( arch_read_web_cb( NULL, &curEntry, &tmp ) > 0 );
	else
		while( arch_read_block_cb( NULL, &curEntry, &tmp ) > 0 );
	
	/* Output */
	if( curEntry.filesize > 0 )
		output( &curEntry );

	/* libarchive close */
	arch_close( &curEntry );

	/* hash close */
	hash_close( &curEntry );

	if( parent != NULL )
		parent->jsonArray = curEntry.jsonArray;
	else
		curl_close( &curEntry );
	
}


/*** libarchive functions ***/

/**
 * Initialises the curEntry->arch object for all compression and file formats
 */
void arch_init( struct cur_entry *curEntry ) {
	curEntry->arch = archive_read_new();
	archive_read_support_compression_all( curEntry->arch );
	archive_read_support_format_all( curEntry->arch );

	if( curEntry->level == 0 )
		archive_read_open( curEntry->arch, curEntry, NULL, arch_read_web_cb, NULL );
	else
		archive_read_open( curEntry->arch, curEntry, NULL, arch_read_block_cb, NULL );

}

/**
 * Frees the curEntry->arch object
 */
void arch_close( struct cur_entry *curEntry ) {
	archive_read_close( curEntry->arch );
	archive_read_finish( curEntry->arch );
}

/**
 * A libarchive read callback for sub/embedded archives.
 * This will all the parent's read callback up the chain to the top level
 */
ssize_t arch_read_block_cb( struct archive *arch, void *data, const void **buf ) {
	struct cur_entry *curEntry = data;
	ssize_t len;

	len = archive_read_data( curEntry->parentEntry->arch,  curEntry->buffer, BUFFER_LEN );

	if( len > 0 ) {
		*buf = curEntry->buffer;
		hash_updt( curEntry, len );
	}


	return len;
}

/**
 * A libarchive read callback for curl data.
 */
ssize_t arch_read_web_cb( struct archive *arch, void *data, const void **buf ) {
	struct cur_entry *curEntry = data;
	int handles = 1;

	curEntry->curl_buf = NULL;
	
	while( curEntry->curl_buf == NULL && handles == 1 ) {
		curl_multi_perform( curEntry->curl_multi, &handles );

	}
	
	if( curEntry->curl_buf == NULL || handles == 0 || curEntry->curl_len <= 0 )
		return 0;
	
	*buf = curEntry->curl_buf;
	hash_updt( curEntry, curEntry->curl_len );

	return curEntry->curl_len;
}


/*** hash (gcry/magic) functions ***/

/**
 * Initialises the gcry object for calculating hashes for curEntry, and will
 * initialise a libmagic object if not already done.
 * It is unnecessary for more than one libmagic object to be created per
 * program run, as the object can be continually reused.
 */
void hash_init( struct cur_entry *curEntry ) {
	gcry_error_t gcryerror;

	/* libmagic need only be made once */
	if( curEntry->magic_cookie == NULL ) {
		curEntry->magic_cookie = magic_open( MAGIC_MIME_TYPE );
		if( curEntry->magic_cookie == NULL || magic_load( curEntry->magic_cookie, NULL ) != 0 ) {
			fprintf( stderr, "Error:\tUnable to load libmagic\n" );
			return;
		}

	}

	gcryerror = gcry_md_open( &(curEntry->hash_handle), GCRY_MD_MD5, 0 );
	if( curEntry->hash_handle == NULL ) {
		fprintf( stderr, "Error:\t%s\n", gcry_strerror( gcryerror ) );
		return;
	}
	gcry_md_enable( curEntry->hash_handle, GCRY_MD_MD4 );
	gcry_md_enable( curEntry->hash_handle, GCRY_MD_SHA1 );
	gcry_md_enable( curEntry->hash_handle, GCRY_MD_SHA256 );
	gcry_md_enable( curEntry->hash_handle, GCRY_MD_WHIRLPOOL );

}

/* This feeds data to the hashers, called by the above libarchive callbacks */
void hash_updt( struct cur_entry *curEntry, ssize_t len ) {
	const char *tmp;
	const unsigned char *buffer;

	if( curEntry->level == 0 )
		buffer = curEntry->curl_buf;
	else
		buffer = curEntry->buffer;
	
	curEntry->filesize += len;

	gcry_md_write( curEntry->hash_handle, buffer, len );

	if( curEntry->filesize == len ) {
		tmp = magic_buffer( curEntry->magic_cookie, buffer, len );
		if( tmp == NULL )
			tmp = MIME_UNKNOWN;
		strncpy( curEntry->mime_type, tmp, MIME_BUFFER-1 );

		/* if applicable, init b/z decompression */
		if( !strcmp( curEntry->mime_type, "application/x-bzip2" ) ) {
			curEntry->subEntry = calloc( sizeof( struct cur_entry ), 1 );
			curEntry->subEntry->magic_cookie = curEntry->magic_cookie;
			curEntry->subEntry->level = curEntry->level + 1;
			curEntry->subEntry->parentEntry = curEntry;
			hash_init( curEntry->subEntry );
			if( BZ2_bzDecompressInit ( &(curEntry->subEntry->bzstream), 0, 0 ) == BZ_OK ) {
				curEntry->subEntry->bz = 1;
			} else
				free( curEntry->subEntry );
		 } else if( !strcmp( curEntry->mime_type, "application/x-gzip" ) ) {
			curEntry->subEntry = calloc( sizeof( struct cur_entry ), 1 );
			
			curEntry->subEntry->zstream.zalloc = Z_NULL;
			curEntry->subEntry->zstream.zfree = Z_NULL;
			curEntry->subEntry->zstream.opaque = Z_NULL;
			curEntry->subEntry->zstream.avail_in = 0;
			curEntry->subEntry->zstream.next_in = Z_NULL;

			curEntry->subEntry->magic_cookie = curEntry->magic_cookie;
			curEntry->subEntry->level = curEntry->level + 1;
			curEntry->subEntry->parentEntry = curEntry;
			hash_init( curEntry->subEntry );
				if( inflateInit2( &(curEntry->subEntry->zstream), 32+MAX_WBITS ) == Z_OK ) {
				curEntry->subEntry->z = 1;
			} else
				free( curEntry->subEntry );
		}
	}

	if( curEntry->subEntry ) {
		if( curEntry->subEntry->bz ) {
			curEntry->subEntry->bzstream.next_in = (char*)buffer;
			curEntry->subEntry->bzstream.avail_in = len;
			curEntry->subEntry->bzstream.next_out = (char*)curEntry->subEntry->buffer;
			curEntry->subEntry->bzstream.avail_out = BUFFER_LEN;

			while( curEntry->subEntry->bzstream.avail_in > 0 ) {
				BZ2_bzDecompress( &(curEntry->subEntry->bzstream) );

				gcry_md_write( curEntry->subEntry->hash_handle, 
						curEntry->subEntry->buffer, 
						BUFFER_LEN - curEntry->subEntry->bzstream.avail_out );
				curEntry->subEntry->filesize += BUFFER_LEN - curEntry->subEntry->bzstream.avail_out;

				curEntry->subEntry->bzstream.next_out = (char*)curEntry->subEntry->buffer;
				curEntry->subEntry->bzstream.avail_out = BUFFER_LEN;
			}
		} else if( curEntry->subEntry->z ) {
			curEntry->subEntry->zstream.next_in = (Bytef*)buffer;
			curEntry->subEntry->zstream.avail_in = len;
			curEntry->subEntry->zstream.next_out = curEntry->subEntry->buffer;
			curEntry->subEntry->zstream.avail_out = BUFFER_LEN;

			while( curEntry->subEntry->zstream.avail_in > 0 && curEntry->subEntry->zstream.msg == NULL) {
				inflate( &(curEntry->subEntry->zstream), 0 );

				gcry_md_write( curEntry->subEntry->hash_handle, 
						curEntry->subEntry->buffer, 
						BUFFER_LEN - curEntry->subEntry->zstream.avail_out );
				curEntry->subEntry->filesize += BUFFER_LEN - curEntry->subEntry->zstream.avail_out;

				curEntry->subEntry->zstream.next_out = curEntry->subEntry->buffer;
				curEntry->subEntry->zstream.avail_out = BUFFER_LEN;
			}
			if( curEntry->subEntry->zstream.msg ) {
				fprintf(stderr, "Error: zlib decompression error:\n%s\n", curEntry->subEntry->zstream.msg );
			}
		}
	}

}

void hash_close( struct cur_entry *curEntry ) {
	gcry_md_close( curEntry->hash_handle );
	if( curEntry->level == 0 )
		magic_close( curEntry->magic_cookie );

	if( curEntry->subEntry ) {
		gcry_md_close( curEntry->subEntry->hash_handle );
		if( curEntry->subEntry->bz ) {
			curEntry->subEntry->bz = 0;
			BZ2_bzDecompressEnd( &(curEntry->subEntry->bzstream) );
		}
		if( curEntry->subEntry->z ) {
			curEntry->subEntry->z = 0;
			inflateEnd( &(curEntry->subEntry->zstream) );
		}
		free( curEntry->subEntry );
	}

}



/*** curl functions ***/
void curl_init( struct cur_entry *curEntry ) {

	curEntry->curl_multi = curl_multi_init();
	curEntry->curl_easy = curl_easy_init();

	fgets( curEntry->url, MAX_URL_LEN, stdin );
	curEntry->url[ strlen( curEntry->url ) - 1 ] = '\0';


	curl_easy_setopt( curEntry->curl_easy, CURLOPT_URL, curEntry->url );
	curl_easy_setopt( curEntry->curl_easy, CURLOPT_WRITEFUNCTION, curl_read_cb );
	curl_easy_setopt( curEntry->curl_easy, CURLOPT_WRITEDATA, curEntry );



	curl_multi_add_handle( curEntry->curl_multi, curEntry->curl_easy );

}

void curl_close( struct cur_entry *curEntry ) {
	curl_easy_cleanup( curEntry->curl_easy );
	curl_multi_cleanup( curEntry->curl_multi );
	curl_global_cleanup();
}

/* This reads data from libcurl and stores it in the curEntry array to be read by libarchive */
size_t curl_read_cb( void *buf, size_t len, size_t nmemb, void *data ) {
	struct cur_entry *curEntry = data;

	curEntry->curl_len = len * nmemb;
	curEntry->curl_buf = buf;
	
	return curEntry->curl_len;
}


void output( struct cur_entry *curEntry ) {
	unsigned char *tmp;
	char *save;
	struct cur_entry *travEntry,*tmpEntry;
	int i;

	if( curEntry->subEntry ) {
		save = curEntry->filename;
		curEntry->filename = UNPACKED_NAME;
		output( curEntry->subEntry );
		curEntry->filename = save;
		curEntry->jsonArray = curEntry->subEntry->jsonArray;
	}

	if( !curEntry->jsonArray ) {
		printf("[\n");
		curEntry->jsonArray = 1;
	}

	printf("\t{\n");
	
	
	printf("\t\t{\n");
	if( curEntry->level == 0 )
		printf("\t\t\t\"URL\": \"%s\"\n", curEntry->url );
	else {
		for( travEntry = curEntry; travEntry->parentEntry != NULL; travEntry = travEntry->parentEntry );
		tmpEntry = travEntry;
		printf("\t\t\t\"URL\": \"%s\",\n", travEntry->url );
		while( tmpEntry != curEntry->parentEntry ) {
			for( travEntry = curEntry; travEntry->parentEntry != tmpEntry; travEntry = travEntry->parentEntry );
			printf("\t\t\t\"Sub-File\": \"%s\",\n", tmpEntry->filename );
			tmpEntry = travEntry;
		}
		printf("\t\t\t\"Sub-File\": \"%s\"\n", curEntry->parentEntry->filename );
	}

	printf("\t\t},\n");

	printf("\t\t\"Size\": %lld,\n", curEntry->filesize );
	printf("\t\t\"MIME-Type: \"%s\",\n", curEntry->mime_type );
	

	printf("\t\t\"MD5\": \"");
	tmp = gcry_md_read( curEntry->hash_handle, GCRY_MD_MD5 );
	for( i = 0; i < MD5_DIGEST_LENGTH; i++ )
		printf("%02x", tmp[i] );
	printf("\",\n");

	printf("\t\t\"MD4\": \"");
	tmp = gcry_md_read( curEntry->hash_handle, GCRY_MD_MD4 );
	for( i = 0; i < MD4_DIGEST_LENGTH; i++ )
		printf("%02x", tmp[i] );
	printf("\",\n");

	printf("\t\t\"SHA1\": \"");
	tmp = gcry_md_read( curEntry->hash_handle, GCRY_MD_SHA1 );
	for( i = 0; i < SHA_DIGEST_LENGTH; i++ )
		printf("%02x", tmp[i] );
	printf("\",\n");

	printf("\t\t\"SHA256\": \"");
	tmp = gcry_md_read( curEntry->hash_handle, GCRY_MD_SHA256 );
	for( i = 0; i < SHA256_DIGEST_LENGTH; i++ )
		printf("%02x", tmp[i] );
	printf("\",\n");

	printf("\t\t\"Whirlpool\": \"");
	tmp = gcry_md_read( curEntry->hash_handle, GCRY_MD_WHIRLPOOL );
	for( i = 0; i < WHIRLPOOL_DIGEST_LENGTH; i++ )
		printf("%02x", tmp[i] );
	printf("\"\n");

	if( curEntry->level == 0 )
		printf("\t}\n]\n");
	else
		printf("\t},\n");

}

