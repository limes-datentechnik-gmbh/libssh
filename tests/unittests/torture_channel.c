#include "config.h"

#define LIBSSH_STATIC
#include <libssh/libssh.h>
#include <libssh/misc.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "torture.h"
#include "channels.c"

static void torture_channel_select(void **state)
{
    fd_set readfds;
    int fd;
    int rc;
    int i;

    (void)state; /* unused */

    ZERO_STRUCT(readfds);

    fd = open("/dev/null", 0);
    assert_true(fd > 2);

    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);

    for (i = 0; i < 10; i++) {
        ssh_channel cin[1] = { NULL, };
        ssh_channel cout[1] = { NULL, };
        struct timeval tv = { .tv_sec = 0, .tv_usec = 1000 };

        rc = ssh_select(cin, cout, fd + 1, &readfds, &tv);
        assert_int_equal(rc, SSH_OK);
    }

    close(fd);
}

/* Defines for expected callback types */
#define CALLBACK_DATA       1
#define CALLBACK_LASTDATA   2
#define CALLBACK_EXITSTATUS 3
#define CALLBACK_EOF        4
#define CALLBACK_CLOSE      5

/* Struct containing the expected callback calls */
#define CB_EXPECT_ITEMS_MAX 8
struct cb_expect_item {
    int         return_val;
    uint32_t    expect_type;
    const void* expect_data;
    uint32_t    expect_len;
    int         expect_stderr;
    int         expect_exitstatus;
};
struct cb_expect {
    uint32_t    pos;
    uint32_t    len;
    struct cb_expect_item items[CB_EXPECT_ITEMS_MAX];
};

/* Holds initial state for channel callback tests */
struct cb_state {
    ssh_session session;
    uint32_t    channel_id;
    ssh_channel channel;
    ssh_buffer  packet;
    struct ssh_channel_callbacks_struct callbacks;
    struct cb_expect expect;
};

/* Helpers for managing expected callback calls */

static void cb_expect_init(struct cb_expect* expect) {
    memset(expect, 0, sizeof(struct cb_expect));
}

static void cb_expect_done(struct cb_expect* expect) {
    assert_int_equal(expect->pos, expect->len);
}

static void cb_expect_add(struct cb_expect* expect, uint32_t type) {
    assert_in_range(expect->len, 0, CB_EXPECT_ITEMS_MAX-1);
    expect->items[expect->len].expect_type = type;
    expect->len++;
}

static void cb_expect_add_data(struct cb_expect* expect, uint32_t type, uint32_t len, const void* data, int stderr, int processed) {
    assert_in_range(expect->len, 0, CB_EXPECT_ITEMS_MAX-1);
    expect->items[expect->len].expect_type = type;
    expect->items[expect->len].expect_data = data;
    expect->items[expect->len].expect_len = len;
    expect->items[expect->len].expect_stderr = stderr;
    expect->items[expect->len].return_val = processed;
    expect->len++;
}

static void cb_expect_add_exitstatus(struct cb_expect* expect, uint32_t type, int exitstatus) {
    assert_in_range(expect->len, 0, CB_EXPECT_ITEMS_MAX-1);
    expect->items[expect->len].expect_type = type;
    expect->items[expect->len].expect_exitstatus = exitstatus;
    expect->len++;
}

/* Channel callback verification functions */

static int rcv_data_cb(ssh_session session, ssh_channel channel, void *data,
        uint32_t len, int is_stderr, void *userdata, uint32_t type)
{
    struct cb_expect* cb_data = (struct cb_expect*)userdata;
    struct cb_expect_item* cb_item;
    (void)session;
    (void)channel;

    // was this callback call expected?
    assert_in_range(cb_data->pos, 0, cb_data->len - 1);
    cb_item = &cb_data->items[cb_data->pos];
    assert_int_equal(cb_item->expect_type, type);

    assert_int_equal(is_stderr, cb_item->expect_stderr);
    assert_int_equal(len, cb_item->expect_len);
    if (cb_item->expect_data != NULL)
        assert_memory_equal(data, cb_item->expect_data, len);

    cb_data->pos++;

    return cb_item->return_val;
}

static void rcv_type_cb(ssh_session session, ssh_channel channel,
        void *userdata, uint32_t type)
{
    struct cb_expect* cb_data = (struct cb_expect*)userdata;
    struct cb_expect_item* cb_item;
    (void)session;
    (void)channel;

    // was this callback call expected?
    assert_in_range(cb_data->pos, 0, cb_data->len - 1);
    cb_item = &cb_data->items[cb_data->pos];
    assert_int_equal(cb_item->expect_type, type);

    cb_data->pos++;
}

static void rcv_exit_status_cb(ssh_session session, ssh_channel channel,
        int exit_status, void *userdata)
{
    struct cb_expect* cb_data = (struct cb_expect*)userdata;
    struct cb_expect_item* cb_item;
    (void)session;
    (void)channel;

    // was this callback call expected?
    assert_in_range(cb_data->pos, 0, cb_data->len - 1);
    cb_item = &cb_data->items[cb_data->pos];
    assert_int_equal(cb_item->expect_type, CALLBACK_EXITSTATUS);

    cb_data->pos++;
}

static int rcv_packetdata_cb(ssh_session session, ssh_channel channel, void *data,
        uint32_t len, int is_stderr, void *userdata)
{
    return rcv_data_cb(session, channel, data, len, is_stderr, userdata,
            CALLBACK_DATA);
}
static int rcv_lastdata_cb(ssh_session session, ssh_channel channel, void *data,
        uint32_t len, int is_stderr, void *userdata)
{
    return rcv_data_cb(session, channel, data, len, is_stderr, userdata,
            CALLBACK_LASTDATA);
}

static void rcv_eof_cb(ssh_session session, ssh_channel channel, void *userdata)
{
    rcv_type_cb(session, channel, userdata, CALLBACK_EOF);
}

static void rcv_close_cb(ssh_session session, ssh_channel channel, void *userdata)
{
    rcv_type_cb(session, channel, userdata, CALLBACK_CLOSE);
}

static int setup_channel_callbacks(void **state)
{
    struct cb_state *s;
    struct ssh_iterator *it;

    s = calloc(1, sizeof(struct cb_state));
    assert_non_null(s);

    ssh_callbacks_init(&s->callbacks);
    s->callbacks.channel_data_function = rcv_packetdata_cb;
    s->callbacks.channel_exit_status_function = rcv_exit_status_cb;
    s->callbacks.channel_lastdata_function = rcv_lastdata_cb;
    s->callbacks.channel_eof_function = rcv_eof_cb;
    s->callbacks.channel_close_function = rcv_close_cb;
    s->callbacks.userdata = &s->expect;

    s->session = ssh_new();
    assert_non_null(s->session);

    s->channel = ssh_channel_new(s->session);
    assert_non_null(s->channel);

    s->channel_id = 42;
    s->channel->local_channel = s->channel_id;
    assert_ssh_return_code(s->session, ssh_add_channel_callbacks(s->channel, &s->callbacks));

    it = ssh_list_find(s->channel->callbacks, &s->callbacks);
    assert_non_null(it);

    s->packet = ssh_buffer_new();
    assert_non_null(s->packet);

    *state = s;

    return 0;
}

static int teardown_channel_callbacks(void **state)
{
    struct cb_state *s = *state;

    ssh_channel_free(s->channel);
    ssh_free(s->session);
    free(*state);

    return 0;
}

static void torture_channel_rcv_data(void **state)
{
    int rc;
    struct cb_state *s = *state;
    uint32_t data_len;
    const char *data;

    // Simulate an incoming data packet on stdout
    data = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B";
    data_len = strlen(data);

    rc = ssh_buffer_pack(s->packet, "ds", s->channel_id, data);
    assert_ssh_return_code(s->session, rc);

    cb_expect_init(&s->expect);
    cb_expect_add_data(&s->expect, CALLBACK_DATA, data_len, data, 0, data_len-5);
    cb_expect_add_data(&s->expect, CALLBACK_DATA, 5, data+data_len-5, 0, 3);
    cb_expect_add_data(&s->expect, CALLBACK_DATA, 2, data+data_len-2, 0, 2);

    rc = channel_rcv_data(s->session, SSH2_MSG_CHANNEL_DATA, s->packet, NULL);
    assert_ssh_return_code_equal(s->session, rc, SSH_PACKET_USED);

    cb_expect_done(&s->expect);

    // Simulate an incoming data packet on stderr
    data = "\x11\x22\x33\x44\x55\x66\x77\x88\x99";
    data_len = strlen(data);

    rc = ssh_buffer_pack(s->packet, "dds", s->channel_id, 1, data);
    assert_ssh_return_code(s->session, rc);

    cb_expect_init(&s->expect);
    cb_expect_add_data(&s->expect, CALLBACK_DATA, data_len, data, 1, data_len);

    rc = channel_rcv_data(s->session, SSH2_MSG_CHANNEL_EXTENDED_DATA,
            s->packet, NULL);
    assert_ssh_return_code_equal(s->session, rc, SSH_PACKET_USED);

    cb_expect_done(&s->expect);
}

static void torture_channel_rcv_eof(void **state)
{
    int rc;
    struct cb_state *s = *state;
    uint32_t data_len;
    const char *data;

    // Simulate an incoming data packet on stdout which is not fully consumed
    data = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B";
    data_len = strlen(data);

    rc = ssh_buffer_pack(s->packet, "ds", s->channel_id, data);
    assert_ssh_return_code(s->session, rc);

    cb_expect_init(&s->expect);
    cb_expect_add_data(&s->expect, CALLBACK_DATA, data_len, data, 0, data_len-3);
    cb_expect_add_data(&s->expect, CALLBACK_DATA, 3, data+data_len-3, 0, 0);

    rc = channel_rcv_data(s->session, SSH2_MSG_CHANNEL_DATA, s->packet, NULL);
    assert_ssh_return_code_equal(s->session, rc, SSH_PACKET_USED);

    cb_expect_done(&s->expect);

    // Simulate an incoming EOF packet and check that the lastdata callback is called
    rc = ssh_buffer_pack(s->packet, "d", s->channel_id);
    assert_ssh_return_code(s->session, rc);

    cb_expect_init(&s->expect);
    cb_expect_add_data(&s->expect, CALLBACK_LASTDATA, 3, data+data_len-3, 0, 2);
    cb_expect_add_data(&s->expect, CALLBACK_LASTDATA, 1, data+data_len-1, 0, 1);
    cb_expect_add(&s->expect, CALLBACK_EOF);

    rc = channel_rcv_eof(s->session, SSH2_MSG_CHANNEL_EOF, s->packet, NULL);
    assert_ssh_return_code_equal(s->session, rc, SSH_PACKET_USED);

    cb_expect_done(&s->expect);
}

static void torture_channel_rcv_data_eof(void **state)
{
    int rc;
    struct cb_state *s = *state;
    uint32_t data_len;
    const char *data;

    // Simulate an incoming data packet on stdout which is not fully consumed
    data = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B";
    data_len = strlen(data);

    rc = ssh_buffer_pack(s->packet, "ds", s->channel_id, data);
    assert_ssh_return_code(s->session, rc);

    cb_expect_init(&s->expect);
    cb_expect_add_data(&s->expect, CALLBACK_DATA, data_len, data, 0, data_len-3);
    cb_expect_add_data(&s->expect, CALLBACK_DATA, 3, data+data_len-3, 0, 0);

    rc = channel_rcv_data(s->session, SSH2_MSG_CHANNEL_DATA, s->packet, NULL);
    assert_ssh_return_code_equal(s->session, rc, SSH_PACKET_USED);

    cb_expect_done(&s->expect);

    // Simulate an incoming EOF packet and check that the lastdata callback is called
    rc = ssh_buffer_pack(s->packet, "d", s->channel_id);
    assert_ssh_return_code(s->session, rc);

    cb_expect_init(&s->expect);
    cb_expect_add_data(&s->expect, CALLBACK_LASTDATA, 3, data+data_len-3, 0, 2);
    cb_expect_add_data(&s->expect, CALLBACK_LASTDATA, 1, data+data_len-1, 0, 1);
    cb_expect_add(&s->expect, CALLBACK_EOF);

    rc = channel_rcv_eof(s->session, SSH2_MSG_CHANNEL_EOF, s->packet, NULL);
    assert_ssh_return_code_equal(s->session, rc, SSH_PACKET_USED);

    cb_expect_done(&s->expect);
}

static void torture_channel_rcv_close(void **state)
{
    int rc;
    struct cb_state *s = *state;

    // Simulate an incoming close packet and check that no lastdata callback is called
    rc = ssh_buffer_pack(s->packet, "d", s->channel_id);
    assert_ssh_return_code(s->session, rc);

    cb_expect_init(&s->expect);
    cb_expect_add(&s->expect, CALLBACK_CLOSE);

    rc = channel_rcv_close(s->session, SSH2_MSG_CHANNEL_CLOSE, s->packet, NULL);
    assert_ssh_return_code_equal(s->session, rc, SSH_PACKET_USED);

    cb_expect_done(&s->expect);
}

static void torture_channel_rcv_data_close(void **state)
{
    int rc;
    struct cb_state *s = *state;
    uint32_t data_len;
    const char *data;

    // Simulate an incoming data packet on stdout which is not fully consumed
    data = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B";
    data_len = strlen(data);

    rc = ssh_buffer_pack(s->packet, "ds", s->channel_id, data);
    assert_ssh_return_code(s->session, rc);

    cb_expect_init(&s->expect);
    cb_expect_add_data(&s->expect, CALLBACK_DATA, data_len, data, 0, data_len-3);
    cb_expect_add_data(&s->expect, CALLBACK_DATA, 3, data+data_len-3, 0, 0);

    rc = channel_rcv_data(s->session, SSH2_MSG_CHANNEL_DATA, s->packet, NULL);
    assert_ssh_return_code_equal(s->session, rc, SSH_PACKET_USED);

    cb_expect_done(&s->expect);

    // Simulate an incoming close packet and check that the lastdata callback is called
    rc = ssh_buffer_pack(s->packet, "d", s->channel_id);
    assert_ssh_return_code(s->session, rc);

    cb_expect_init(&s->expect);
    cb_expect_add_data(&s->expect, CALLBACK_LASTDATA, 3, data+data_len-3, 0, 3);
    cb_expect_add(&s->expect, CALLBACK_CLOSE);

    rc = channel_rcv_close(s->session, SSH2_MSG_CHANNEL_CLOSE, s->packet, NULL);
    assert_ssh_return_code_equal(s->session, rc, SSH_PACKET_USED);

    cb_expect_done(&s->expect);
}

static void torture_channel_rcv_data_exit_eof_close(void **state)
{
    int rc;
    struct cb_state *s = *state;
    uint32_t data_len;
    const char *data;

    // Simulate an incoming data packet on stdout which is not fully consumed
    data = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B";
    data_len = strlen(data);

    rc = ssh_buffer_pack(s->packet, "ds", s->channel_id, data);
    assert_ssh_return_code(s->session, rc);

    cb_expect_init(&s->expect);
    cb_expect_add_data(&s->expect, CALLBACK_DATA, data_len, data, 0, data_len-3);
    cb_expect_add_data(&s->expect, CALLBACK_DATA, 3, data+data_len-3, 0, 0);

    rc = channel_rcv_data(s->session, SSH2_MSG_CHANNEL_DATA, s->packet, NULL);
    assert_ssh_return_code_equal(s->session, rc, SSH_PACKET_USED);

    cb_expect_done(&s->expect);

    /* Simulate incoming exit-status, EOF and close packets (end of normal
     * commmand channel) and check that the lastdata callback is called before
     * the exit-status callback */
    cb_expect_init(&s->expect);
    cb_expect_add_data(&s->expect, CALLBACK_LASTDATA, 3, data+data_len-3, 0, 3);
    cb_expect_add_exitstatus(&s->expect, CALLBACK_EXITSTATUS, 23);
    cb_expect_add(&s->expect, CALLBACK_EOF);
    cb_expect_add(&s->expect, CALLBACK_CLOSE);

    rc = ssh_buffer_pack(s->packet, "dsbd", s->channel_id, "exit-status", 0, 23);
    assert_ssh_return_code(s->session, rc);
    rc = channel_rcv_request(s->session, SSH2_MSG_CHANNEL_REQUEST, s->packet, NULL);
    assert_ssh_return_code_equal(s->session, rc, SSH_PACKET_USED);

    rc = ssh_buffer_pack(s->packet, "d", s->channel_id);
    assert_ssh_return_code(s->session, rc);
    rc = channel_rcv_eof(s->session, SSH2_MSG_CHANNEL_EOF, s->packet, NULL);
    assert_ssh_return_code_equal(s->session, rc, SSH_PACKET_USED);

    rc = ssh_buffer_pack(s->packet, "d", s->channel_id);
    assert_ssh_return_code(s->session, rc);
    rc = channel_rcv_close(s->session, SSH2_MSG_CHANNEL_CLOSE, s->packet, NULL);
    assert_ssh_return_code_equal(s->session, rc, SSH_PACKET_USED);

    cb_expect_done(&s->expect);
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test(torture_channel_select),
        cmocka_unit_test_setup_teardown(torture_channel_rcv_data,
                setup_channel_callbacks, teardown_channel_callbacks),
        cmocka_unit_test_setup_teardown(torture_channel_rcv_eof,
                setup_channel_callbacks, teardown_channel_callbacks),
        cmocka_unit_test_setup_teardown(torture_channel_rcv_data_eof,
                setup_channel_callbacks, teardown_channel_callbacks),
        cmocka_unit_test_setup_teardown(torture_channel_rcv_close,
                setup_channel_callbacks, teardown_channel_callbacks),
        cmocka_unit_test_setup_teardown(torture_channel_rcv_data_close,
                setup_channel_callbacks, teardown_channel_callbacks),
        cmocka_unit_test_setup_teardown(torture_channel_rcv_data_exit_eof_close,
                setup_channel_callbacks, teardown_channel_callbacks),
    };

    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();

    return rc;
}
