// SPDX-License-Identifier: AGPL-3.0-only
// Application registry adapted from Pico Keys SDK main.c; Copyright (c) 2022 Pol Henarejos
#include "picokeys.h"
#include "apdu.h"

app_t apps[16];
uint8_t num_apps = 0;

app_t *current_app = NULL;

const uint8_t *ccid_atr = NULL;

bool app_exists(const_byte_array_t aid) {
    for (int a = 0; a < num_apps; a++) {
        if (aid.len >= apps[a].aid[0] && !memcmp(apps[a].aid + 1, aid.data, apps[a].aid[0])) {
            return true;
        }
    }
    return false;
}

int register_app(int (*select_aid)(app_t *, uint8_t), const uint8_t *aid) {
    if (app_exists(CONST_BYTE_ARRAY(aid + 1, aid[0]))) {
        return 1;
    }
    if (num_apps < sizeof(apps) / sizeof(app_t)) {
        apps[num_apps].select_aid = select_aid;
        apps[num_apps].aid = aid;
        num_apps++;
        return 1;
    }
    return 0;
}

static void clear_selection(void) {
    currentEF = currentDF = NULL;
    selected_applet = NULL;
    isUserAuthenticated = false;
    card_terminated = false;
}
int select_app(const_byte_array_t aid) {
    if (!aid.data || !aid.len) return PICOKEYS_ERR_FILE_NOT_FOUND;
    for (uint8_t a = 0; a < num_apps; ++a) {
        app_t *next = &apps[a];
        if (aid.len < next->aid[0] || memcmp(next->aid + 1, aid.data, next->aid[0])) continue;
        if (current_app == next) {
            return next->select_aid(next, 0);
        }
        if (current_app && current_app->unload) current_app->unload();
        current_app = NULL;
        clear_selection();
        file_namespace_select(next->file_namespace);
        int result = next->select_aid(next, 1);
        if (result != PICOKEYS_OK) {
            if (next->unload) next->unload();
            clear_selection();
            file_namespace_select(0);
            return result;
        }
        current_app = next;
        return PICOKEYS_OK;
    }
    return PICOKEYS_ERR_FILE_NOT_FOUND;
}
