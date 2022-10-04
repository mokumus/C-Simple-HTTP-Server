#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <microhttpd.h>
#include <frozen.h>

#define METHOD_ERROR "<html><head><title>Illegal request</title></head><body>Go away.</body></html>"
#define NOT_FOUND_ERROR "<html><head><title>Not found</title></head><body>Go away.</body></html>"

#define COOKIE_NAME "session" // Name of our cookie.
#define MAX_JSON_BUFFER 4096
#define MAX_STR 128
#define MAX_FIELD 7



// State we keep for each user/session/browser.
struct Session
{
  struct Session *next;            // We keep all sessions in a linked list.
  char sid[33];                    // Unique ID for this session.
  unsigned int rc;                 // Reference counter giving the number of connections currently using this session.
  time_t start;                    // Time when this session was last active.
  char values[MAX_FIELD][MAX_STR]; // uploaded data
};

// Data kept per request.
struct Request
{
  struct Session *session;      // Associated session.
  struct MHD_PostProcessor *pp; // Post processor handling form data (IF this is a POST request).
  const char *post_url;         // URL to serve in response to this POST (if this request was a 'POST')
};

typedef enum MHD_Result (*PageHandler)(const void *cls, const char *mime, struct Session *session, struct MHD_Connection *connection);

struct Page
{
  const char *url;         // Acceptable URL for this page.
  const char *mime;        // Mime type to set for the page.
  PageHandler handler;     // Handler to call to generate response.
  const void *handler_cls; // Extra argument to handler.
};

char *field_keys[] = {"ETH0", "ETH1", "MAIN_RTSP", "SECOND_RTSP", "DATA_CH1", "DATA_CH2", "TEST"};
static struct Session *sessions; // Linked list of all active sessions.

// Prototypes
static enum MHD_Result save_device_config(const void *cls, const char *mime, struct Session *session, struct MHD_Connection *connection);
static enum MHD_Result not_found_page(const void *cls, const char *mime, struct Session *session, struct MHD_Connection *connection);
static enum MHD_Result post_iterator(void *cls, enum MHD_ValueKind kind, const char *key, const char *filename, const char *content_type, const char *transfer_encoding, const char *data, uint64_t off, size_t size);
static enum MHD_Result create_response(void *cls, struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **req_cls);
static struct Session *get_session(struct MHD_Connection *connection);
static void add_session_cookie(struct Session *session, struct MHD_Response *response);
static void request_completed_callback(void *cls, struct MHD_Connection *connection, void **req_cls, enum MHD_RequestTerminationCode toe);
static void expire_sessions(void);
char *parse_form2json(char form_data[MAX_FIELD][MAX_STR], char **local_keys, int n_keys, size_t n);

static struct Page pages[] = {
    {"/save", "application/json", &save_device_config, NULL},
    {NULL, NULL, &not_found_page, NULL} /* 404 */
};

/**
 * Handler that adds the 'v1' value to the given HTML code.
 *
 * @param cls unused
 * @param mime mime type to use
 * @param session session handle
 * @param connection connection to use
 */
static enum MHD_Result save_device_config(const void *cls, const char *mime, struct Session *session, struct MHD_Connection *connection)
{
  enum MHD_Result ret;
  size_t slen = 0;
  char *reply;
  struct MHD_Response *response;
  (void)cls; /* Unused. Silent compiler warning. */

  for (int i = 0; i < MAX_FIELD; i++)
  {
    slen += strlen(session->values[i]);
  }

  reply = parse_form2json(session->values, field_keys, MAX_FIELD, MAX_JSON_BUFFER);
  printf("reply:\n%s\n", reply);

  /* return static form */
  response = MHD_create_response_from_buffer_with_free_callback(strlen(reply), (void *)reply, &free);
  if (NULL == response)
  {
    printf("null response\n");
    free(reply);
    return MHD_NO;
  }
  add_session_cookie(session, response);
  MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_ENCODING, mime);
  ret = MHD_queue_response(connection, 404, response);
  MHD_destroy_response(response);
  return ret;
}

/**
 * Handler used to generate a 404 reply.
 *
 * @param cls a 'const char *' with the HTML webpage to return
 * @param mime mime type to use
 * @param session session handle
 * @param connection connection to use
 */
static enum MHD_Result not_found_page(const void *cls, const char *mime, struct Session *session, struct MHD_Connection *connection)
{
  enum MHD_Result ret;
  struct MHD_Response *response;
  (void)cls;     /* Unused. Silent compiler warning. */
  (void)session; /* Unused. Silent compiler warning. */

  /* unsupported HTTP method */
  response =
      MHD_create_response_from_buffer_static(strlen(NOT_FOUND_ERROR), (const void *)NOT_FOUND_ERROR);
  if (NULL == response)
    return MHD_NO;

  ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
  MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_ENCODING, mime);
  MHD_destroy_response(response);

  return ret;
}

/**
 * Iterator over key-value pairs where the value
 * maybe made available in increments and/or may
 * not be zero-terminated.  Used for processing
 * POST data.
 *
 * @param cls user-specified closure
 * @param kind type of the value
 * @param key 0-terminated key for the value
 * @param filename name of the uploaded file, NULL if not known
 * @param content_type mime-type of the data, NULL if not known
 * @param transfer_encoding encoding of the data, NULL if not known
 * @param data pointer to size bytes of data at the
 *              specified offset
 * @param off offset of data in the overall value
 * @param size number of bytes in data available
 * @return MHD_YES to continue iterating,
 *         MHD_NO to abort the iteration
 */
static enum MHD_Result post_iterator(void *cls, enum MHD_ValueKind kind, const char *key, const char *filename, const char *content_type, const char *transfer_encoding, const char *data, uint64_t off, size_t size)
{
  struct Request *request = cls;
  struct Session *session = request->session;

  if (0 == strcmp("DONE", key))
  {
    fprintf(stdout, "Session `%s' submitted `%s', `%s'\n", session->sid, session->values[0], session->values[1]);
    return MHD_YES;
  }

  for (int i = 0; i < MAX_FIELD; i++)
  {
    char reply[MAX_STR];
    snprintf(reply, MAX_STR, field_keys[i], i);
    if (0 == strcmp(reply, key))
    {

      if (size + off >= sizeof(session->values[i]))
        size = sizeof(session->values[i]) - off - 1;

      memcpy(&session->values[i][off], data, size);
      session->values[i][size + off] = '\0';

      // return MHD_YES;
    }
  }

  // fprintf (stderr,"Unsupported form value `%s'\n", key);
  return MHD_YES;
}

/**
 * Main MHD callback for handling requests.
 *
 * @param cls argument given together with the function
 *        pointer when the handler was registered with MHD
 * @param connection handle identifying the incoming connection
 * @param url the requested url
 * @param method the HTTP method used ("GET", "PUT", etc.)
 * @param version the HTTP version string (i.e. "HTTP/1.1")
 * @param upload_data the data being uploaded (excluding HEADERS,
 *        for a POST that fits into memory and that is encoded
 *        with a supported encoding, the POST data will NOT be
 *        given in upload_data and is instead available as
 *        part of MHD_get_connection_values; very large POST
 *        data *will* be made available incrementally in
 *        upload_data)
 * @param upload_data_size set initially to the size of the
 *        upload_data provided; the method must update this
 *        value to the number of bytes NOT processed;
 * @param req_cls pointer that the callback can set to some
 *        address and that will be preserved by MHD for future
 *        calls for this request; since the access handler may
 *        be called many times (i.e., for a PUT/POST operation
 *        with plenty of upload data) this allows the application
 *        to easily associate some request-specific state.
 *        If necessary, this state can be cleaned up in the
 *        global "MHD_RequestCompleted" callback (which
 *        can be set with the MHD_OPTION_NOTIFY_COMPLETED).
 *        Initially, <tt>*req_cls</tt> will be NULL.
 * @return MHS_YES if the connection was handled successfully,
 *         MHS_NO if the socket must be closed due to a serious
 *         error while handling the request
 */
static enum MHD_Result create_response(void *cls, struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **req_cls)
{
  struct MHD_Response *response;
  struct Request *request;
  struct Session *session;
  enum MHD_Result ret;
  unsigned int i;
  (void)cls;     /* Unused. Silent compiler warning. */
  (void)version; /* Unused. Silent compiler warning. */

  request = *req_cls;
  if (NULL == request)
  {
    request = calloc(1, sizeof(struct Request));
    if (NULL == request)
    {
      fprintf(stderr, "calloc error: %s\n", strerror(errno));
      return MHD_NO;
    }
    *req_cls = request;
    if (0 == strcmp(method, MHD_HTTP_METHOD_POST))
    {
      request->pp = MHD_create_post_processor(connection, 1024, &post_iterator, request);
      if (NULL == request->pp)
      {
        fprintf(stderr, "Failed to setup post processor for `%s'\n", url);
        return MHD_NO; /* internal error */
      }
    }
    return MHD_YES;
  }
  if (NULL == request->session)
  {
    request->session = get_session(connection);
    if (NULL == request->session)
    {
      fprintf(stderr, "Failed to setup session for `%s'\n", url);
      return MHD_NO; /* internal error */
    }
  }

  session = request->session;
  session->start = time(NULL);

  if (0 == strcmp(method, MHD_HTTP_METHOD_POST))
  {
    /* evaluate POST data */
    MHD_post_process(request->pp, upload_data, *upload_data_size);

    if (0 != *upload_data_size)
    {
      *upload_data_size = 0;
      return MHD_YES;
    }

    /* done with POST data, serve response */
    MHD_destroy_post_processor(request->pp);
    request->pp = NULL;
    method = MHD_HTTP_METHOD_GET; /* fake 'GET' */
    if (NULL != request->post_url)
      url = request->post_url;
  }

  if ((0 == strcmp(method, MHD_HTTP_METHOD_GET)) || (0 == strcmp(method, MHD_HTTP_METHOD_HEAD)))
  {
    /* find out which page to serve */
    i = 0;
    while ((pages[i].url != NULL) && (0 != strcmp(pages[i].url, url)))
      i++;

    ret = pages[i].handler(pages[i].handler_cls, pages[i].mime, session, connection);

    if (ret != MHD_YES)
      fprintf(stderr, "Failed to create page for `%s'\n", url);

    return ret;
  }
  /* unsupported HTTP method */
  response = MHD_create_response_from_buffer_static(strlen(METHOD_ERROR), (const void *)METHOD_ERROR);
  ret = MHD_queue_response(connection, MHD_HTTP_NOT_ACCEPTABLE, response);
  MHD_destroy_response(response);

  return ret;
}

/**
 * Return the session handle for this connection, or
 * create one if this is a new user.
 */
static struct Session *get_session(struct MHD_Connection *connection)
{
  struct Session *ret;
  const char *cookie;

  cookie = MHD_lookup_connection_value(connection, MHD_COOKIE_KIND, COOKIE_NAME);
  if (cookie != NULL)
  {
    /* find existing session */
    ret = sessions;
    while (NULL != ret)
    {
      if (0 == strcmp(cookie, ret->sid))
        break;
      ret = ret->next;
    }
    if (NULL != ret)
    {
      ret->rc++;
      return ret;
    }
  }
  /* create fresh session */
  ret = calloc(1, sizeof(struct Session));
  if (NULL == ret)
  {
    fprintf(stderr, "calloc error: %s\n", strerror(errno));
    return NULL;
  }
  /* not a super-secure way to generate a random session ID,
     but should do for a simple example... */
  snprintf(ret->sid, sizeof(ret->sid), "%X%X%X%X", (unsigned int)rand(), (unsigned int)rand(), (unsigned int)rand(), (unsigned int)rand());
  ret->rc++;
  ret->start = time(NULL);
  ret->next = sessions;
  sessions = ret;
  return ret;
}

/**
 * Add header to response to set a session cookie.
 *
 * @param session session to use
 * @param response response to modify
 */
static void add_session_cookie(struct Session *session, struct MHD_Response *response)
{
  char cstr[256];
  snprintf(cstr, sizeof(cstr), "%s=%s", COOKIE_NAME, session->sid);
  if (MHD_NO == MHD_add_response_header(response, MHD_HTTP_HEADER_SET_COOKIE, cstr))
  {
    fprintf(stderr, "Failed to set session cookie header!\n");
  }
}

/**
 * Callback called upon completion of a request.
 * Decrements session reference counter.
 *
 * @param cls not used
 * @param connection connection that completed
 * @param req_cls session handle
 * @param toe status code
 */
static void request_completed_callback(void *cls, struct MHD_Connection *connection, void **req_cls, enum MHD_RequestTerminationCode toe)
{
  struct Request *request = *req_cls;
  (void)cls;        /* Unused. Silent compiler warning. */
  (void)connection; /* Unused. Silent compiler warning. */
  (void)toe;        /* Unused. Silent compiler warning. */

  if (NULL == request)
    return;
  if (NULL != request->session)
    request->session->rc--;
  if (NULL != request->pp)
    MHD_destroy_post_processor(request->pp);
  free(request);
}

/**
 * Clean up handles of sessions that have been idle for
 * too long.
 */
static void expire_sessions(void)
{
  struct Session *pos;
  struct Session *prev;
  struct Session *next;
  time_t now;

  now = time(NULL);
  prev = NULL;
  pos = sessions;
  while (NULL != pos)
  {
    next = pos->next;
    if (now - pos->start > 60 * 60)
    {
      /* expire sessions after 1h */
      if (NULL == prev)
        sessions = pos->next;
      else
        prev->next = next;
      free(pos);
    }
    else
      prev = pos;

    pos = next;
  }
}

char *parse_form2json(char form_data[MAX_FIELD][MAX_STR], char **local_keys, int n_keys, size_t n)
{
  size_t buffer_size = n * sizeof(char);

  char *buffer = malloc(buffer_size);
  char *pretty_buffer = malloc(buffer_size);

  struct json_out jout = JSON_OUT_BUF(buffer, buffer_size);
  struct json_out pretty_result = JSON_OUT_BUF(pretty_buffer, buffer_size);

  json_printf(&jout, "{");

  for (int i = 0; i < n_keys; i++)
  {
    // TODO: Add logic for parsing according to data type
    json_printf(&jout, "%Q: %Q,", local_keys[i], form_data[i]);
  }
  json_printf(&jout, "}");
  json_prettify(buffer, MAX_JSON_BUFFER, &pretty_result);
  free(buffer);
  return pretty_buffer;
}

/**
 * Call with the port number as the only argument.
 * Never terminates (other than by signals, such as CTRL-C).
 */
int main(int argc, char *const *argv)
{
  struct MHD_Daemon *d;
  struct timeval tv;
  struct timeval *tvp;
  fd_set rs;
  fd_set ws;
  fd_set es;
  MHD_socket max;
  uint64_t mhd_timeout;
  int port;

  if (argc != 2)
  {
    printf("%s PORT\n", argv[0]);
    return 1;
  }
  port = atoi(argv[1]);
  if ((1 > port) || (port > 65535))
  {
    fprintf(stderr,
            "Port must be a number between 1 and 65535.\n");
    return 1;
  }
  /* initialize PRNG */
  srand((unsigned int)time(NULL));
  d = MHD_start_daemon(MHD_USE_ERROR_LOG,
                       (uint16_t)port,
                       NULL, NULL,
                       &create_response, NULL,
                       MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int)15,
                       MHD_OPTION_NOTIFY_COMPLETED,
                       &request_completed_callback, NULL,
                       MHD_OPTION_END);
  if (NULL == d)
    return 1;
  while (1)
  {
    expire_sessions();
    max = 0;
    FD_ZERO(&rs);
    FD_ZERO(&ws);
    FD_ZERO(&es);
    if (MHD_YES != MHD_get_fdset(d, &rs, &ws, &es, &max))
      break; /* fatal internal error */
    if (MHD_get_timeout64(d, &mhd_timeout) == MHD_YES)
    {
#if !defined(_WIN32) || defined(__CYGWIN__)
      tv.tv_sec = (time_t)(mhd_timeout / 1000LL);
#else  /* Native W32 */
      tv.tv_sec = (long)(mhd_timeout / 1000LL);
#endif /* Native W32 */
      tv.tv_usec = ((long)(mhd_timeout % 1000)) * 1000;
      tvp = &tv;
    }
    else
      tvp = NULL;
    if (-1 == select((int)max + 1, &rs, &ws, &es, tvp))
    {
      if (EINTR != errno)
        abort();
    }
    MHD_run(d);
  }
  MHD_stop_daemon(d);
  return 0;
}
