// Copyright (C) 2018 David Helkowski

/* Include the required headers from httpd */
//#define AP_HAVE_DESIGNATED_INITIALIZER
#include "httpd.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_log.h"
#include "parser.h"
#include "string_tree.h"
#include<apr_strings.h>
#include<apr.h>
#include<apr_time.h>
#include<apr_uuid.h>
#include<inttypes.h>

#ifdef MSCOMP
char *strndup( char *src, int len ) {
    char *dup = (char *) malloc( len );
    memcpy( dup, src, len );
    return dup;
}
#endif

/* Define prototypes of our functions in this module */
static void register_hooks(apr_pool_t *pool);
static int nanomsg_handler(request_rec *r);
static int nanomsg_post_config( apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s );
int handle_req(request_rec *r);
char *decode_err( int err );

typedef struct {
    const char *socket_out;
    const char *socket_in;
    int set;
} dir_conf;

static const char *handle_nanoSocketOut( cmd_parms *cmd, void *dirConf, const char *arg ) {
    dir_conf *conf = ( dir_conf * ) dirConf;
    conf->socket_out = arg;
    return NULL;
}

static const char *handle_nanoSocketIn( cmd_parms *cmd, void *dirConf, const char *arg ) {
    dir_conf *conf = ( dir_conf * ) dirConf;
    conf->socket_in = arg;
    return NULL;
}

static const char *handle_nanoSet( cmd_parms *cmd, void *dirConf, const char *arg ) {
    dir_conf *conf = ( dir_conf * ) dirConf;
    conf->set = atoi( arg );
    return NULL;
}

static const command_rec directive_set[] = {
  AP_INIT_TAKE1("NanoSocketOut", (const char *(*)())handle_nanoSocketOut, NULL, OR_ALL, "Nano Socket Out"),
  AP_INIT_TAKE1("NanoSocketIn" , (const char *(*)()) handle_nanoSocketIn , NULL, OR_ALL, "Nano Socket In"),
  AP_INIT_TAKE1("NanoSet"      , (const char *(*)()) handle_nanoSet      , NULL, OR_ALL, "Nano Set"), 
  { NULL }
} ;

static void *merge_dir_conf(apr_pool_t *pool, void *baseIn, void *addIn );
static void *create_dir_conf( apr_pool_t* pool, char* x );

/* Define our module as an entity and assign a function for registering hooks  */
module AP_MODULE_DECLARE_DATA   nanomsg_module =
{
    STANDARD20_MODULE_STUFF,
    create_dir_conf, // Per-directory configuration handler
    merge_dir_conf,  // Merge handler for per-directory configurations
    NULL,            // Per-server configuration handler
    NULL,            // Merge handler for per-server configurations
    directive_set,   // Any directives we may have for httpd
    register_hooks   // Our hook registering function
};
#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(nanomsg);
#endif

static void *merge_dir_conf(apr_pool_t *pool, void *baseIn, void *addIn ) {
    dir_conf *base = ( dir_conf * ) baseIn;
    dir_conf *add = ( dir_conf * ) addIn;
    dir_conf *conf = ( dir_conf * ) apr_palloc( pool, sizeof( dir_conf ) ) ;
    conf->socket_in  = add->socket_in  ? add->socket_in  : base->socket_in;
    conf->socket_out = add->socket_out ? add->socket_out : base->socket_out;
    conf->set        = add->set        ? add->set        : base->set;
    return conf;
}

static void* create_dir_conf( apr_pool_t* pool, char* x ) {
  dir_conf* conf = ( dir_conf * ) apr_pcalloc( pool, sizeof( dir_conf ) );
  /* Set up the default values for fields of dir */
  #ifdef MSCOMP
  char path[ MAX_PATH + 30 ];
  if( !GetTempPathA( MAX_PATH - 20, path ) ) return NULL;
  conf->socket_out = apr_psprintf( pool, "ipc://%s\\client_%%i.ipc", path );
  conf->socket_in = apr_psprintf( pool, "ipc://%s\\server_%%i_%%u.ipc", path ); // TODO; can %u be bigger than 20 chars? 
  #else
  // /tmp is no good because it may not be the same between systems
  conf->socket_out = (char *) "ipc:///var/www/html/wcm3/socket/client_%i.ipc";
  conf->socket_in = (char *) "ipc:///var/www/html/wcm3/socket/server_%i_%u.ipc";
  #endif
  conf->set = 1;
  return conf;
}

static void register_hooks(apr_pool_t *pool) {
    ap_hook_post_config(nanomsg_post_config,NULL,NULL,APR_HOOK_MIDDLE);
    ap_hook_handler(nanomsg_handler, NULL, NULL, APR_HOOK_LAST);
}

typedef struct thread_data_s {
    int socket_in;
    int socket_in_done;
    int socket_out;
    int socket_out_done;
    int request_num;
} thread_data;
//typedef struct thread_data_s thread_data;

typedef struct thread_entry_s {
    unsigned int thread_id;
    char setid;
    thread_data data;
} thread_entry;
//typedef struct thread_entry_s thread_entry;

int thread_entry_cnt;
thread_entry **thread_entries;
int max_thread_entries = 20;

static apr_thread_mutex_t *mutex;
static int nanomsg_post_config( apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s ) {
    thread_entry_cnt = 0;
    thread_entries = ( thread_entry ** ) malloc( sizeof( thread_entry * ) * 20 );
    max_thread_entries = 20;
    apr_thread_mutex_create( &mutex, APR_THREAD_MUTEX_DEFAULT, pconf );
    return OK;
}

static int nanomsg_handler(request_rec *r) {
    /* First off, we need to check if this is a call for the "example" handler.
     * If it is, we accept it and do our things, it not, we simply return DECLINED,
     * and Apache will try somewhere else.
     */
    if (!r->handler || strcmp(r->handler, "nanomsg-handler")) return (DECLINED);
    
    //ap_set_content_type(r, "text/html; charset=UTF-8");
    //apr_table_set( r->headers_out, "Content-Type", "text/html; charset=UTF-8" );
    
    // The first thing we will do is write a simple "Hello, world!" back to the client.
    
    //char *info = get_info(r);
    //ap_rputs(info,r);
    //free(info);
    return handle_req(r);
    
    //ap_rputs("Hello, world!<br/>", r);
    //return OK;
}

#include<nanomsg/nn.h>
#include<nanomsg/pair.h>
#include<nanomsg/pipeline.h>
#include<stdio.h>
#include<string.h>
//#include<unistd.h>
#include<errno.h>
#include<malloc.h>

thread_data *get_thread_data( request_rec *r,unsigned int thread_id,char setid );

thread_data *get_thread_data( request_rec *r,unsigned int thread_id,char setid ) {
    for( int i=0;i<thread_entry_cnt;i++ ) {
        thread_entry *entry = thread_entries[i];
        //ap_log_error( APLOG_MARK, LOG_ERR, 0, r->server, "comparing " );
        if( entry->thread_id == thread_id && entry->setid == setid ) return &entry->data;
    }
    // not found; add it
    apr_thread_mutex_lock( mutex );
    thread_entry *new_entry = (thread_entry *) malloc( sizeof( thread_entry ) );
    thread_entries[thread_entry_cnt] = new_entry;
    
    new_entry->thread_id = thread_id;
    new_entry->setid = setid;
    new_entry->data.socket_in_done = 0;
    new_entry->data.socket_out_done = 0;
    new_entry->data.request_num = 1;
    
    thread_entry_cnt++;
    if( thread_entry_cnt > max_thread_entries ) {
        int newmax = max_thread_entries * 2;
        int oldsize = sizeof( thread_entry * ) * max_thread_entries;
        thread_entry **newlist = ( thread_entry ** ) malloc( sizeof( thread_entry * ) * newmax );
        memcpy( newlist, thread_entries, oldsize );
        free( thread_entries );
        thread_entries = newlist;
    }
    apr_thread_mutex_unlock( mutex );
    
    return &new_entry->data;
}

#define BUFLEN 5000

struct str_buffer_s {
    char *data;
    char *pos;
    char *maxpos;
    int maxlen;
};
typedef struct str_buffer_s str_buffer;
str_buffer *str_buffer__new() {
    str_buffer *buffer = (str_buffer *) calloc( sizeof( str_buffer ), 1 );
    buffer->data = buffer->pos = (char *) malloc( BUFLEN );
    buffer->maxlen = BUFLEN;
    buffer->maxpos = buffer->pos + BUFLEN - 1;
    return buffer;
}
void str_buffer__delete( str_buffer *buffer ) {
    free( buffer->data );
    free( buffer );
}
void str_buffer__extend( str_buffer *buffer, int extraNeeded ) {
    int curmax = buffer->maxlen;
    int curoffset = buffer->pos - buffer->data;
    int extra = curmax;
    if( extra < ( extraNeeded + 50 ) ) {
        extra = extraNeeded + 100;
    }
    int newmax = curmax + extra;
    char *newdata = (char *) malloc( newmax );
    memcpy( newdata, buffer->data, buffer->pos - buffer->data + 1 );
    free( buffer->data );
    buffer->data = newdata;
    buffer->pos = buffer->data + curoffset;
    buffer->maxlen = newmax;
    buffer->maxpos = buffer->data + newmax - 1;
}

int header_to_xml( void *pos, const char *key, const char *val );
int body_to_xml( void *pos, const char *key, const char *val );
int json_to_xml( void *pos, const char *key, const char *val, apr_off_t len );
void str_append( str_buffer *buffer, const char *str, int len );
void str_appendZ( str_buffer *buffer, const char *str );
void val_append( str_buffer *buffer, const char *val );
void val_append_unescape( str_buffer *buffer, const char *val );

// From https://httpd.apache.org/docs/trunk/de/developer/modguide.html
static int util_read(request_rec *r, const char **rbuf, apr_off_t *size) {
    /*~~~~~~~~*/
    int rc = OK;
    /*~~~~~~~~*/

    if((rc = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR))) {
        return(rc);
    }

    if(ap_should_client_block(r)) {

        /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
        char         argsbuffer[HUGE_STRING_LEN];
        apr_off_t    rsize, len_read, rpos = 0;
        apr_off_t length = r->remaining;
        /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

        *rbuf = (const char *) apr_pcalloc(r->pool, (apr_size_t) (length + 1));
        *size = length;
        while((len_read = ap_get_client_block(r, argsbuffer, sizeof(argsbuffer))) > 0) {
            if((rpos + len_read) > length) {
                rsize = length - rpos;
            }
            else {
                rsize = len_read;
            }

            memcpy((char *) *rbuf + rpos, argsbuffer, (size_t) rsize);
            rpos += rsize;
        }
    }
    return(rc);
}

const char *new_temp_filename( request_rec *r ) {
    apr_uuid_t uuid;
    apr_uuid_get( &uuid );
    char buffer[ APR_UUID_FORMATTED_LENGTH + 1 ];
    apr_uuid_format( buffer, &uuid );
    #ifdef MSCOMP
    char path[ MAX_PATH ];
    if( !GetTempPathA( MAX_PATH - 8 - APR_UUID_FORMATTED_LENGTH, path ) ) return NULL;
    const char *filename = apr_psprintf( r->pool, "%s\\upload_%.*s", APR_UUID_FORMATTED_LENGTH, buffer );
    #else
    const char *filename = apr_psprintf( r->pool, "/tmp/upload_%.*s", APR_UUID_FORMATTED_LENGTH, buffer );
    #endif
    return filename;
}

/*
#define AP_LOG_DEBUG(rec, fmt, ...) ap_log_rerror(APLOG_MARK, APLOG_DEBUG,  0, r, fmt, ##__VA_ARGS__)
#define AP_LOG_INFO(rec, fmt, ...)  ap_log_rerror(APLOG_MARK, APLOG_INFO,   0, r, "[" HR_AUTH "] " fmt, ##__VA_ARGS__)
#define AP_LOG_WARN(rec, fmt, ...)  ap_log_rerror(APLOG_MARK, APLOG_WARNING,0, r, "[" HR_AUTH "] " fmt, ##__VA_ARGS__)
#define AP_LOG_ERR(rec, fmt, ...) ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "[" HR_AUTH "] " fmt, ##__VA_ARGS__)
*/

int request_to_xml( str_buffer **bufferOut, int thread_id, request_rec *r, int request_num ) {
    //char *str = *strPtr = malloc( BUFLEN );
    
    //char *maxpos = pos + BUFLEN - 2;
    
    // Write the thread id
    char tmp[200];
    snprintf(tmp,100,"%u,",thread_id);
    
    str_buffer *buffer = str_buffer__new();
    *bufferOut = buffer;
    str_appendZ( buffer, tmp );
    //buffer.pos = pos;
    //buffer.maxpos = maxpos;
    apr_table_do( header_to_xml, (void *) buffer, r->headers_in, NULL );
    
    //pos = buffer.pos;
    
    /*const apr_table_t* body_table;
    apr_status_t status;
    status = ap_body_to_table(r, &body_table);
    if( body_table ) apr_table_do( body_to_xml, (void *) &buffer, r->body_table, NULL );
    else {
        //ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
        //    "body_table status [%d] [%d]", status, APREQ_ERROR_NOPARSER);
    }*/
    
    if( r->method_number == M_POST ) {
        const char *type = apr_table_get( r->headers_in, "Content-Type" );
        const char *upload = apr_table_get( r->headers_in, "X-Upload" );
        if( upload ) {
            // Following code adapted from https://github.com/suzumura-ss/mod_upload/blob/master/mod_upload.c ; Apache License Copyright (C) 2010 Toshiyuki Suzumura
            const char *length_header = apr_table_get( r->headers_in, "Content-Length" );
            apr_off_t length = (length_header) ? apr_atoi64( length_header ): LLONG_MAX;
            // AP_LOG_DEBUG(rec, " Content-Length: %llu", length);
            const char *filename = new_temp_filename( r );
            #ifdef MSCOMP
            snprintf( tmp, 200, "<upfile size='%I64u'>%s</upfile>", length, filename );
            #else
            snprintf( tmp, 200, "<upfile size='%"PRId64"'>%s</upfile>", length, filename );
            #endif
            str_appendZ( buffer, tmp );
    
            apr_file_t *file = NULL;
            apr_status_t status = apr_file_open( &file, filename, APR_WRITE|APR_CREATE|APR_TRUNCATE, APR_FPROT_OS_DEFAULT, r->pool );
            apr_off_t count = 0;
            if( status != APR_SUCCESS ) goto CLEANUP;
            status = ap_setup_client_block( r, REQUEST_CHUNKED_DECHUNK );
            
            if( status == OK ) {
                char buf[ 32768 ];
                apr_size_t bytes;
            
                while( 
                    (
                        (
                            bytes = ap_get_client_block( r, buf, sizeof( buf ) )
                        )
                        > 0
                    ) 
                    && ( length > count )
                ) {
                    apr_size_t wr = 0;
                    if( count + bytes > length ) {
                        //AP_LOG_WARN( r, "Illegal Content-Length : %llu", length );
                        bytes = length - count;
                    }
                    while( wr < bytes ) {
                        apr_size_t w = bytes - wr;
                        status = apr_file_write( file, buf, &w );
                        if( status != APR_SUCCESS ) goto CLEANUP;
                        wr += w;
                    }
                    count += bytes;
                }
            }
            CLEANUP:
            if( file ) {
                apr_status_t s_close = apr_file_close( file );
                if( s_close != APR_SUCCESS ) {
                    //AP_LOG_ERR( r, "Close failed: %s : %s(%d)", filename, strerror( s_close ), s_close );
                    status = s_close;
                }
            }
            if( status != APR_SUCCESS ) {
                apr_file_remove( filename, r->pool );
                //AP_ERR_RESPONSE( r, "Write failed: %s : %s(%d)", filename, strerror( status ), status );
            } 
            else {
                ap_rprintf( r, "Saved: %s (%llu)\n", filename, count );
                //AP_LOG_DEBUG( r, "%llu bytes read.", count );
            }
        }
        else if( !strcasecmp( type, "application/json" ) ) {
            apr_off_t   size;
            const char  *buffer2;
            
            if(util_read(r, &buffer2, &size) == OK) {
                //ap_rprintf(r, "We read a request body that was %" APR_OFF_T_FMT " bytes long", size);
                json_to_xml( buffer, "json", buffer2, size );
            }
        }
        else {
            apr_array_header_t *pairs = NULL;
            //keyValuePair *kvp;
            
            int res = ap_parse_form_data( r, NULL, &pairs, -1, 8192 );
            //kvp = apr_pcalloc(r->pool, sizeof(keyValuePair) * (pairs->nelts + 1));
            if( res == OK && pairs ) {
                while (pairs && !apr_is_empty_array(pairs)) {
                    ap_form_pair_t *pair = (ap_form_pair_t *) apr_array_pop(pairs);
                    apr_off_t len;
                    apr_brigade_length(pair->value, 1, &len);
                    apr_size_t size = (apr_size_t) len;
                    char *cbuffer = (char *) apr_palloc(r->pool, size + 1);
                    apr_brigade_flatten(pair->value, cbuffer, &size);
                    cbuffer[len] = 0;
                    body_to_xml( buffer, pair->name, cbuffer );
                    //kvp[i].key = apr_pstrdup(r->pool, pair->name);
                    //kvp[i].value = buffer;
                    //i++;
                }
                //pos = buffer.pos;
            }
            else {
                //snprintf( pos, maxpos-pos,"<parsefail/>" );
                str_append( buffer, "<parsefail/>", 12 );
                //pos += strlen( pos );
            }
        }
    }
    
    //snprintf( pos, maxpos-pos,"<v>2</v>" );
    //pos += strlen( pos );
    snprintf( tmp, 100, "<rn>%i</rn>",request_num);
    str_appendZ( buffer, tmp );
    //pos += strlen( pos );
    
    snprintf( tmp, 100, "<method>%s</method>", r->method );
    str_appendZ( buffer, tmp );
    //pos += strlen( pos );
    
    apr_uri_t uri = r->parsed_uri;
    //snprintf( pos, maxpos-pos,"<uri hash='%s' host='%s' path='%s' q='%s'/>", uri.fragment, uri.hostname, uri.path, uri.query );
    str_append( buffer, "<uri path='", sizeof("<uri path='")-1 );
    val_append( buffer, uri.path );
    
    //str_append( &pos, maxpos-pos, "' hash='", sizeof("' hash='") );
    //val_append( &pos, maxpos-pos, uri.fragment );
    
    //str_append( &pos, maxpos-pos, "' host='", sizeof("' host='") );
    //val_append( &pos, maxpos-pos, uri.hostname );
    
    str_append( buffer, "' q='", sizeof("' q='")-1 );
    val_append_unescape( buffer, uri.query );
    str_append( buffer, "'/>", sizeof("'/>")-1 );
    //pos += strlen( pos );
    
    snprintf( tmp, 100, "<user ip='%s'/>", r->useragent_ip );
    //pos += strlen( pos );
    
    // Return the length of the created string
    int len = buffer->pos - buffer->data;//pos - str;
    return len;
}

void str_appendZ( str_buffer *buffer, const char *str ) {
    int len = strlen( str );
    str_append( buffer, str, len );
}

void str_append( str_buffer *buffer, const char *str, int len ) {
    char *pos = buffer->pos;
    if( ( pos + len ) > buffer->maxpos ) str_buffer__extend( buffer, ( pos + len ) - buffer->maxpos );
    //if( len > maxlen ) return;
    memcpy( buffer->pos, str, len );
    buffer->pos = buffer->pos + len;
    (buffer->pos)[0] = 0x00;
}

char hex2char( char b1, char b2 );

void unescape( str_buffer *buffer, const char *val, int len ) {
    char *pos = buffer->pos;
    if( ( pos + len ) > buffer->maxpos ) {
        str_buffer__extend( buffer, ( pos + len ) - buffer->maxpos );
        pos = buffer->pos;
    }
    
    for( int i=0;i<len;i++ ) {
        char let = val[i];
        if( let == '%' ) {
            if( ( i + 2 ) >= len ) break;
            char hex1 = val[i+1];
            char hex2 = val[i+2];
            let = hex2char( hex1, hex2 );
            i+=2;
        }
        
        if( let == '\\' ) {
            pos[0] = '\\';
            pos[1] = '\\';
            pos = pos + 2;
        }
        else if( let == '\'' ) {
            pos[0] = '\\';
            pos[1] = '\'';
            pos = pos + 2;
        }
        else if( let == '"' ) {
            pos[0] = '\\';
            pos[1] = '"';
            pos = pos + 2;
        }
        else {
           pos[0] = let;
           pos++;
        }
    }
    
    buffer->pos = pos;
}

void val_append( str_buffer *buffer, const char *val ) {
    if( !val ) return;
    char *pos = buffer->pos;
    
    int i = 0;
    while( 1 ) {
    //for( int i=0;1;i++ ) {
        if( ( pos + 2 ) >= buffer->maxpos ) {
            str_buffer__extend( buffer, 2 );
            pos = buffer->pos;
        }
        char let = val[i];
        if( !let ) {
            pos[0] = 0;
            break;
        }
        if(      let == '\\' ) { pos[0] = '\\'; pos[1] = '\\'; pos = pos + 2; }
        else if( let == '\'' ) { pos[0] = '\\'; pos[1] = '\''; pos = pos + 2; }
        else if( let == '"'  ) { pos[0] = '\\'; pos[1] = '"';  pos = pos + 2; }
        else {
            pos[0] = let;
            pos++;
        }
        i++;
    }
    buffer->pos = pos;
}
void val_append_unescape( str_buffer *buffer, const char *val ) {
    if( !val ) return;
    
    char *pos = buffer->pos;
    int i = 0;
    while(1) {
    //for( int i=0;1;i++ ) {
        if( ( pos + 2 ) >= buffer->maxpos ) {
            str_buffer__extend( buffer, 2 );
            pos = buffer->pos;
        }
        
        char let = val[i];
        if( !let ) {
            pos[0] = 0;
            break;
        }
        
        if( let == '%'  ) {
            //if( ( i + 2 ) < maxlen ) {
                char hex1 = val[i+1];
                char hex2 = val[i+2];
                let = hex2char( hex1, hex2 );
                i+=2;
            //}
        }
        
        if(      let == '\\' ) { pos[0] = '\\'; pos[1] = '\\'; pos = pos + 2; }
        else if( let == '\'' ) { pos[0] = '\\'; pos[1] = '\''; pos = pos + 2; }
        else if( let == '"'  ) { pos[0] = '\\'; pos[1] = '"';  pos = pos + 2; }
        else {
            pos[0] = let;
            pos++;
        }
        
        i++;
    }
    buffer->pos = pos;
}
/*void val_append_lim( char **pos, int maxlen, const char *val, int vallen ) {
    if( maxlen < vallen ) val_append( pos, maxlen, val );
    else val_append( pos, vallen, val );
}*/

void cookies_to_xml( str_buffer *buffer, const char *cookieStr );

int header_to_xml( void *posV, const char *key, const char *val ) {
    str_buffer *buffer = (str_buffer *) posV;
    
    if( !strncmp( key, "Cookie", sizeof("Cookie")-1 ) ) {
        cookies_to_xml( buffer, val );
        return 1;
    }
    //snprintf( buffer->pos, buffer->maxpos - buffer->pos, "<header key='%s' val='%s'/>", key, val );
    //buffer->pos += strlen( buffer->pos );
    str_append( buffer, "<header key='", sizeof("<header key='")-1 );
    val_append( buffer, key );
    str_append( buffer, "' val='", sizeof("' val='")-1 );
    val_append( buffer, val );
    str_append( buffer, "'/>", sizeof("'/>")-1 );
    
    return 1;
}

int body_to_xml( void *posV, const char *key, const char *val ) {
    str_buffer *buffer = (str_buffer *) posV;
    
    //snprintf( buffer->pos, buffer->maxpos - buffer->pos, "<header key='%s' val='%s'/>", key, val );
    //buffer->pos += strlen( buffer->pos );
    str_append( buffer, "<body key='", sizeof("<body key='")-1 );
    val_append( buffer, key );
    str_append( buffer, "' val='", sizeof("' val='")-1 );
    val_append( buffer, val );
    str_append( buffer, "'/>", sizeof("'/>")-1 );
    
    return 1;
}

int json_to_xml( void *posV, const char *key, const char *val, apr_off_t len ) {
    str_buffer *buffer = (str_buffer *) posV;
    
    //snprintf( buffer->pos, buffer->maxpos - buffer->pos, "<header key='%s' val='%s'/>", key, val );
    //buffer->pos += strlen( buffer->pos );
    str_append( buffer, "<body key='", sizeof("<body key='")-1 );
    val_append( buffer, key );
    str_append( buffer, "'><val><![CDATA[", sizeof("'><val><![CDATA[")-1 );
    str_append( buffer, val, len );
    str_append( buffer, "]]></val></body>", sizeof("]]></val></body>")-1 );
    
    return 1;
}

void cookie_to_xml( str_buffer *buffer, const char *start, const char *end );

void cookies_to_xml( str_buffer *buffer, const char *cookieStr ) {
    const char *start = cookieStr;
    const char *end = cookieStr;
    for( int i=0;i<5000;i++ ) {
        char let = cookieStr[i];
        if( !let ) {
            end = &cookieStr[i-1];
            cookie_to_xml( buffer, start, end );
            return;
        }
        if( let == ';' ) {
            end = &cookieStr[i-1];
            if( start != end ) cookie_to_xml( buffer, start, end );
            if( cookieStr[i+1] == ' ' ) {
                start = &cookieStr[i+2];
                i++;
                continue;
            }
        }
    }
}

void cookie_to_xml( str_buffer *buffer, const char *start, const char *end ) {
    //str_append( &buffer->pos, buffer->maxpos-buffer->pos, "<cookie key='", sizeof("<cookie key='") );
    str_append( buffer, "<cookie key='", sizeof("<cookie key='")-1 );
    
    const char *keyend = start;
    char *eqPos = strchr( (char *) start, '=' );
    if( eqPos ) {
        str_append( buffer, start, eqPos - start );
    }
    else {
        return;
    }
    
    /*for( int i=0;i<5000;i++ ) {
        char let = start[i];
        if( let == '=' ) {
            keyend = &start[i];// position of the equal character
            //str_append( &buffer->pos, buffer->maxpos-buffer->pos, start, keyend-start+1 );
            str_append( buffer, start, i );//keyend-start-1 );
            break;
        }
    }*/
    //val_append_lim( &buffer->pos, buffer->maxpos-buffer->pos, start, ( end - start + 1 ) );
    
    //str_append( &buffer->pos, buffer->maxpos-buffer->pos, "' val='", sizeof("' val='") );
    str_append( buffer, "' val='", sizeof("' val='")-1 );
    const char *val = eqPos + 1;
    if( val > end ) {
        //str_append( &buffer->pos, buffer->maxpos-buffer->pos, "'/>", sizeof("'/>") );
        str_append( buffer, "'/>", sizeof("'/>")-1 );
        return;
    }
    int len = end - val + 1;
    
    unescape( buffer, val, len );
    
    //str_append( &buffer->pos, buffer->maxpos-buffer->pos, "'/>", sizeof("'/>") );
    str_append( buffer, "'/>", sizeof("'/>")-1 );
}

char hex2char( char b1, char b2 ) {
    char ret = 0x00;
    if( b1 >= '0' && b1 <= '9' ) {
        ret += b1 - '0';
    }
    else if( b1 >= 'A' && b1 <= 'F' ) {
        ret += b1 - 'A' + 10;
    }
    else {
        // invalid
    }
    ret *= 16;
    if( b2 >= '0' && b2 <= '9' ) {
        ret += b2 - '0';
    }
    else if( b2 >= 'A' && b2 <= 'F' ) {
        ret += b2 - 'A' + 10;
    }
    else {
        // invalid
    }
    return ret;
}

int process_results( request_rec *r, nodec *root, int resLen, int requestNum );

int handle_req(request_rec *r) {
    char strOut[BUFLEN]; // only used for short strings
    //char *socket_address_in = (char *) "tcp://127.0.0.1:1289";
    //char *socket_address_out = (char *) "tcp://127.0.0.1:1288";
    
    dir_conf *conf = ( dir_conf * ) ap_get_module_config( r->per_dir_config, &nanomsg_module );
    
    char *socket_address_in = (char *) conf->socket_in;//(char *) "ipc:///var/www/html/wcm3/socket/server_%u.ipc";
    char *socket_address_out = (char *) conf->socket_out;//(char *) "ipc:///var/www/html/wcm3/socket/client.ipc";
    char setid = conf->set;
    
    unsigned int thread_id = (unsigned int) getpid();//r->server->process;//apr_os_thread_current();
    
    //printf("Will get response on %s\n",socket_address_in);
    thread_data *data = get_thread_data(r,thread_id,setid);
    int request_num = data->request_num++;
    
    if( !data->socket_in_done ) {
        sprintf( strOut, socket_address_in, setid, thread_id );
        data->socket_in = nn_socket( AF_SP, NN_PULL );
        int bind_res = nn_bind( data->socket_in, strOut );
        if( bind_res < 0 ) {
            int err = errno;
            char *errStr = decode_err( err );
            //sprintf( strOut, "failed to bind: %s\n",errStr );
            ap_log_perror( APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, NULL, r->pool, "Failed to bind: %s", errStr );
            free( errStr );
            if( err != EADDRINUSE ) return OK;// strdup( strOut );
        }
        ap_log_perror( APLOG_MARK, APLOG_NOTICE, NULL, r->pool, "Bound thread %u to socket %s", thread_id, strOut );
        data->socket_in_done = 1;
        int rcv_timeout = 2000;
        nn_setsockopt( data->socket_in, NN_SOL_SOCKET, NN_RCVTIMEO, &rcv_timeout, sizeof(rcv_timeout) );
    }
    
    if( !data->socket_out_done ) {
        sprintf( strOut, socket_address_out, setid );
        data->socket_out = nn_socket( AF_SP, NN_PUSH );
        int connect_res = nn_connect( data->socket_out, strOut );
        if( connect_res < 0 ) {
            return OK;// strdup("fail to connect");
        }
        data->socket_out_done = 1;
        int snd_timeout = 200;
        nn_setsockopt( data->socket_out, NN_SOL_SOCKET, NN_SNDTIMEO, &snd_timeout, sizeof(snd_timeout) );
    }
    
    int socket_in = data->socket_in;
    int socket_out = data->socket_out;
    
    //char *xml;
    str_buffer *xmlbuffer;
    request_to_xml( &xmlbuffer, thread_id, r, request_num );
    char *xml = xmlbuffer->data;
    //sprintf(strOut,"R:%u,%i",thread_id,1);
    //int strOutLen = strlen(strOut)+1;
    int strOutLen = xmlbuffer->pos - xmlbuffer->data + 1;
    int sent_bytes = nn_send(socket_out, xml, strOutLen, 0 );
    str_buffer__delete( xmlbuffer );
    if( !sent_bytes ) {
        return OK;// strdup("fail to send");
    }
    #ifdef MSCOMP
    Sleep(2);
    #else
    usleep(200);
    #endif
    
    while( 1 ) {
        char *buf = NULL;
        int bytes = nn_recv(socket_in, &buf, NN_MSG, 0);
        if( bytes < 0 ) {
           int err = errno;
           char *errStr = decode_err( err );
           
           char ptrStr[20];
           sprintf(ptrStr, "%p", (void *)data );//PRIx64
           ap_rprintf( r, "failed to receive: %s - threadid:%u - data:%s - entries:%i\n",errStr,thread_id,ptrStr,thread_entry_cnt );
           ap_set_content_type(r,"text/html" );
           free( errStr );
           return OK;// strndup( strOut, bytes );
        }
        else {
            //printf("Bytes: %i, Buffer:%s\n", bytes, buf );
            //char *dup = strndup( (char *) buf, bytes );
            parserc parser;
            nodec *root = parser.parse( buf );
            if( !root ) {
                ap_set_content_type(r, "text/html; charset=UTF-8");
                ap_rprintf( r, "Could not parse returned nano results" );
                return OK;
            }
            nodec *rn_node = root->getnode("rn");
            int request_num_verify = -1;
            if( rn_node ) {
                char *nullStr = strndup( rn_node->value, rn_node->vallen );
                request_num_verify = atoi( nullStr );        
                free( nullStr );
            }
            if( request_num_verify < request_num ) {
                nn_freemsg( buf );
                continue;
            }
            
            int res = process_results( r, root, bytes, request_num );
            nn_freemsg( buf );
            return res;// dup;
        }
        break;
    }
    return OK;// should never reach here
}

#include <string>
#include <cstring>

static const char* B64chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const int B64index [256] = { 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 62, 63, 62, 62, 63, 52, 53, 54, 55,
   56, 57, 58, 59, 60, 61,  0,  0,  0,  0,  0,  0,  0,  0,  1,  2,  3,  4,  5,  6,
    7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,  0,
    0,  0,  0, 63,  0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
   41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51 };

std::string b64encode(const void* data, const size_t len)
{
    unsigned char* p = (unsigned char*)data;
    size_t d = len % 3;
    std::string str64(4 * (int(d > 0) + len / 3), '=');

    for (size_t i = 0, j = 0; i < len - d; i += 3)
    {
        int n = int(p[i]) << 16 | int(p[i + 1]) << 8 | p[i + 2];
        str64[j++] = B64chars[n >> 18];
        str64[j++] = B64chars[n >> 12 & 0x3F];
        str64[j++] = B64chars[n >> 6 & 0x3F];
        str64[j++] = B64chars[n & 0x3F];
    }
    if (d--)    /// padding
    {
        int n = d ? int(p[len - 2]) << 8 | p[len - 1] : p[len - 1];
        str64[str64.size() - 2] = d ? B64chars[(n & 0xF) << 2] : '=';
        str64[str64.size() - 3] = d ? B64chars[n >> 4 & 0x03F] : B64chars[(n & 3) << 4];
        str64[str64.size() - 4] = d ? B64chars[n >> 10] : B64chars[n >> 2];
    }
    return str64;
}

std::string b64decode(const void* data, const size_t len)
{
    unsigned char* p = (unsigned char*)data;
    int pad = len > 0 && (len % 4 || p[len - 1] == '=');
    const size_t L = ((len + 3) / 4 - pad) * 4;
    std::string str(L / 4 * 3 + pad, '\0');

    for (size_t i = 0, j = 0; i < L; i += 4)
    {
        int n = B64index[p[i]] << 18 | B64index[p[i + 1]] << 12 | B64index[p[i + 2]] << 6 | B64index[p[i + 3]];
        str[j++] = n >> 16;
        str[j++] = n >> 8 & 0xFF;
        str[j++] = n & 0xFF;
    }
    if (pad)
    {
        int n = B64index[p[L]] << 18 | B64index[p[L + 1]] << 12;
        str[str.size() - 1] = n >> 16;

        if (len > L + 2 && p[L + 2] != '=')
        {
            n |= B64index[p[L + 2]] << 6;
            str.push_back(n >> 8 & 0xFF);
        }
    }
    return str;
}

char * b64decode2(const void* data, const size_t len, size_t *lenout)
{
    unsigned char* p = (unsigned char*)data;
    int pad = len > 0 && (len % 4 || p[len - 1] == '=');
    const size_t L = ((len + 3) / 4 - pad) * 4;
    //std::string str(L / 4 * 3 + pad, '\0');
    char *str = new char[ L / 4 * 3 + pad ];

    size_t j;
    size_t i;
    for (i = 0, j = 0; i < L; i += 4)
    {
        int n = B64index[p[i]] << 18 | B64index[p[i + 1]] << 12 | B64index[p[i + 2]] << 6 | B64index[p[i + 3]];
        str[j++] = n >> 16;
        str[j++] = n >> 8 & 0xFF;
        str[j++] = n & 0xFF;
    }
    *lenout = j;
    if (pad)
    {
        int n = B64index[p[L]] << 18 | B64index[p[L + 1]] << 12;
        str[j++] = n >> 16;

        if (len > L + 2 && p[L + 2] != '=')
        {
            n |= B64index[p[L + 2]] << 6;
            
            //str.push_back(n >> 8 & 0xFF);
            str[j++] = ( n >> 8 & 0xFF );
        }
    }
    *lenout = j;
    return str;
}

std::string b64decode(const std::string& str64)
{
    return b64decode(str64.c_str(), str64.size());
}


// from https://en.wikibooks.org/wiki/Algorithm_Implementation/Miscellaneous/Base64
#define WHITESPACE 64
#define EQUALS     65
#define INVALID    66

static const unsigned char d[] = {
    66,66,66,66,66,66,66,66,66,66,
    64,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,
    66,66,66,62,66,66,66,63,52,53,
    54,55,56,57,58,59,60,61,66,66,
    66,65,66,66,66, 0, 1, 2, 3, 4,
    5 , 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,
    25,66,66,66,66,66,66,26,27,28,
    29,30,31,32,33,34,35,36,37,38,
    39,40,41,42,43,44,45,46,47,48,
    49,50,51,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66
};

int Base64Decode (char *in, size_t inLen, unsigned char *out, size_t *outLen, request_rec *r)
{
    char *incopy = in;
    char *end = in + inLen;
    char iter = 0;
    size_t buf = 0, len = 0;

    while (in < end) {
        unsigned char c = d[(int)*in++];

        switch (c) {
        case WHITESPACE: continue;   /* skip whitespace */
        case INVALID:
            ap_rprintf( r, "Invalid character in base64 at pos %i, char:%c<br>", in-incopy, c );
            return 1;   /* invalid input, return error */
        case EQUALS:                 /* pad character, end of data */
            in = end;
            continue;
        default:
            buf = buf << 6 | c;
            iter++; // increment the number of iteration
            /* If the buffer is full, split it into bytes */
            if (iter == 4) {
                if ((len += 3) > *outLen) return 2; /* buffer overflow */
                *(out++) = (buf >> 16) & 255;
                *(out++) = (buf >> 8) & 255;
                *(out++) = buf & 255;
                buf = 0; iter = 0;

            }
        }
    }

    if (iter == 3) {
        if ((len += 2) > *outLen) return 1; /* buffer overflow */
        *(out++) = (buf >> 10) & 255;
        *(out++) = (buf >> 2) & 255;
    }
    else if (iter == 2) {
        if (++len > *outLen) return 1; /* buffer overflow */
        *(out++) = (buf >> 4) & 255;
    }

    *outLen = len; /* modify to reflect the actual output size */
    return 0;
}

int process_results( request_rec *r, nodec *root, int resLen, int request_num ) {
    //parserc parser;
    //ap_rputs( res, r );
    //nodec *root = parser.parse( res );
    
    /*nodec *rn_node = root->getnode("rn");
    int request_num_verify = -1;
    if( rn_node ) {
        char *nullStr = strndup( rn_node->value, rn_node->vallen );
        request_num_verify = atoi( nullStr );        
        free( nullStr );
    }
    
    if( request_num_verify != request_num ) {
        ap_set_content_type(r, "text/html; charset=UTF-8");
        ap_rprintf( r, "Received response for request %i; wanted response for request %i", request_num_verify, request_num );
        return OK;
    }*/
    
    nodec *redirect = root->getnode("redirect");
    
    arrc *cookies = root->getnodes("cookie");
    if( cookies ) {
        for( int i=0;i<cookies->count;i++ ) {
            nodec *cookie = ( nodec * ) cookies->items[ i ];
            
            char *outputCookie;
            char *name = NULL;
            char *value = NULL;
            //char name[200];
            //char value[200];
            //int nameok = 0;
            //int valok = 0;
            
            attc *nameNode = cookie->getatt("key");
            if( nameNode ) {
                //nameok = 1;
                //snprintf( name, 200, "%.*s", nameNode->vallen, nameNode->value );
                name = apr_psprintf(r->pool, "%.*s", nameNode->vallen, nameNode->value );
            }
            
            attc *valNode = cookie->getatt("val");
            if( valNode ) {
                //valok = 1;
                //snprintf( value, 200, "%.*s", valNode->vallen, valNode->value );
                value = apr_psprintf(r->pool, "%.*s", valNode->vallen, valNode->value );
            }
            
            if( name && value ) {
                outputCookie = apr_psprintf(r->pool,"%s=%s", name, value );
            }
            else {
                continue; // invalid cookie addition
            }  
            
            nodec *pathNode = cookie->getnode("path");
            if( pathNode ) {
                outputCookie = apr_psprintf(r->pool,"%s; Path=%.*s",
                    outputCookie, pathNode->vallen, pathNode->value );
            }
            else {
                outputCookie = apr_psprintf(r->pool,"%s; Path=/", outputCookie );
            }
            
            nodec *expNode = cookie->getnode("expires");
            if( expNode ) {
                const char *zStr = apr_psprintf( r->pool, "%.*s", expNode->vallen, expNode->value );
                //long int seconds = atol( zStr );
                char *end;
                
                apr_int64_t offsetSeconds = apr_strtoi64( zStr, &end, 0 );
                //microS *= 1000000; // convert seconds to microseconds
                apr_time_t offset = apr_time_make( offsetSeconds, 0 );
                
                apr_time_t now = apr_time_now();
                char *rfc822 = (char *) apr_palloc( r->pool, APR_RFC822_DATE_LEN );
                apr_rfc822_date( rfc822, now + offset );
                
                //char *curCookie = apr_pstrdup( r->pool, outputCookie );
                outputCookie = apr_psprintf( r->pool, "%s; Expires=%s", outputCookie, rfc822 );
            }
            
            if( redirect ) {
                apr_table_add(r->err_headers_out, "Set-Cookie", outputCookie );
            }
            else {
                apr_table_add(r->headers_out, "Set-Cookie", outputCookie );
            }
        }
    }
    
    if( redirect ) {
        apr_table_add(r->err_headers_out, "Cache-Control" , "no-cache" );
    }
    else {
        apr_table_add(r->headers_out, "Cache-Control" , "no-cache" );
    }
    
    if( redirect ) {
        char loc[500];
        snprintf( loc, 500, "%.*s", redirect->vallen, redirect->value );
        apr_table_add(r->headers_out, "Location", loc );
        return HTTP_MOVED_TEMPORARILY;
    }
    nodec *content_type = root->getnode("content_type");
    if( content_type ) {
        //char type[200];
        //snprintf( type, 200, "%.*s", content_type->vallen, content_type->value );
        char *type;
        type = apr_psprintf( r->pool, "%.*s", content_type->vallen, content_type->value );
        ap_set_content_type(r, type);
    }
    else {
        ap_set_content_type(r, "text/html; charset=UTF-8");
    }
    nodec *binary = root->getnode( "binary" );
    nodec *body = root->getnode( "body" );
    if( body ) {
        if( binary ) {
            char *nullStr = strndup( binary->value, binary->vallen );
            size_t binlen = atoi( nullStr );        
            free( nullStr );
                
            //std::string data = b64decode( body->value, body->vallen );
            size_t len = binlen;
            unsigned char *data = new unsigned char[ binlen ];
            //char *data = b64decode2( body->value, body->vallen, &len);
            int result = Base64Decode( body->value, body->vallen, data, &len, r );
            if( result || len != binlen ) {
                ap_rprintf( r, "Result of b64 decode: %i<br>", result );
                ap_rprintf( r, "Received base64:[%.*s]<br>", body->vallen, body->value ); 
                ap_rprintf( r, "Decoded length unequal; should: %i, is: %i<br>", binlen, len  );
                ap_set_content_type(r,"text/html" );
            }
            else {
                //ap_rwrite( data.c_str(), data.size(), r );
                ap_rwrite( data, len, r );
            }
            delete data;
        }
        else {
            //ap_rputs( body->value, r );
            //ap_rprintf( r, "%.*s", body->vallen, body->value );
            ap_rwrite( body->value, body->vallen, r );
        }
    }
    return OK;
}

char *decode_err( int err ) {
    char *buf;
    if( err == ENOENT ) { return strdup("ENOENT"); }
    if( err == EBADF ) { return strdup("EBADF"); }
    if( err == EMFILE ) { return strdup("EMFILE"); }
    if( err == EINVAL ) { return strdup("EINVAL"); }
    if( err == ENAMETOOLONG ) { return strdup("ENAMETOOLONG"); }
    if( err == EPROTONOSUPPORT ) { return strdup("EPROTONOSUPPORT"); }
    if( err == EADDRNOTAVAIL ) { return strdup("EADDRNOTAVAIL"); }
    if( err == ENODEV ) { return strdup("ENODEV"); }
    if( err == EADDRINUSE ) { return strdup("EADDRINUSE"); }
    if( err == ETERM ) { return strdup("ETERM"); }
    if( err == ENOTSUP ) { return strdup("ENOTSUP"); }
    if( err == EFSM ) { return strdup("EFSM"); }
    if( err == EAGAIN ) { return strdup("EAGAIN"); }
    if( err == EINTR ) { return strdup("EINTR"); }
    if( err == ETIMEDOUT ) { return strdup("ETIMEDOUT"); }
    buf = (char *) malloc(100);
    sprintf(buf,"Err number: %i", err );
    return buf;
}