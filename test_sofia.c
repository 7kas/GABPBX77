/* Simple Sofia-SIP test */
#include <stdio.h>
#include <sofia-sip/su.h>
#include <sofia-sip/nua.h>
#include <sofia-sip/sip_status.h>
#include <sofia-sip/soa.h>
#include <sofia-sip/url.h>
#include <sofia-sip/sip_header.h>

static void event_callback(nua_event_t event,
                          int status, char const *phrase,
                          nua_t *nua, void *nua_magic,
                          nua_handle_t *nh, void *nh_magic,
                          sip_t const *sip,
                          tagi_t tags[])
{
    printf("Event: %s (%d) - %s\n", nua_event_name(event), status, phrase ? phrase : "");
    
    if (event == nua_i_register) {
        printf("REGISTER received!\n");
        nua_respond(nh, SIP_200_OK, TAG_END());
    }
    
    if (event == nua_r_shutdown) {
        su_root_break((su_root_t *)nua_magic);
    }
}

int main(void)
{
    su_root_t *root;
    nua_t *nua;
    
    printf("Initializing Sofia-SIP...\n");
    su_init();
    
    root = su_root_create(NULL);
    if (!root) {
        printf("Failed to create root\n");
        return 1;
    }
    
    printf("Creating NUA on port 5061...\n");
    nua = nua_create(root, event_callback, root,
                     NUTAG_URL("sip:*:5061"),
                     NUTAG_APPL_METHOD("REGISTER"),
                     TAG_END());
    
    if (!nua) {
        printf("Failed to create NUA\n");
        su_root_destroy(root);
        return 1;
    }
    
    printf("Sofia-SIP listening on port 5061. Press Ctrl+C to stop.\n");
    su_root_run(root);
    
    nua_destroy(nua);
    su_root_destroy(root);
    su_deinit();
    
    return 0;
}