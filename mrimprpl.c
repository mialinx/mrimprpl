#define PURPLE_PLUGINS

#include <glib.h>

#include "notify.h"
#include "plugin.h"
#include "version.h"

#define MRIMPRPL_ID "prpl-mialinx-mrim"
#define MRIMPRPL_NAME "Mail.Ru protocol"
#define MRIMPRPL_VERSION "1.0"
#define MRIMPRPL_AUTHOR "Dmitry Smal <mialinx@gmail.com>"
#define MRIMPRPL_WEBSITE ""
#define MRIMPRPL_SUMMARY "Mail.Ru agent protocol support plugin"
#define MRIMPRPL_DESCRIPTION MRIMPRPL_SUMMARY

static gboolean
plugin_load(PurplePlugin *plugin) 
{
    purple_notify_message(plugin, PURPLE_NOTIFY_MSG_INFO, "Hello World!",
                        "This is the Hello World! plugin :)", NULL, NULL, NULL);

    return TRUE;
}

static gboolean
plugin_unload(PurplePlugin *plugin)
{
    return TRUE;
}

void
plugin_destroy(PurplePlugin *plugin)
{
}

static PurplePluginInfo info = {
    PURPLE_PLUGIN_MAGIC,
    PURPLE_MAJOR_VERSION,
    PURPLE_MINOR_VERSION,
    PURPLE_PLUGIN_STANDARD,
    NULL,
    0,
    NULL,
    PURPLE_PRIORITY_DEFAULT,

    MRIMPRPL_ID,
    MRIMPRPL_NAME,
    MRIMPRPL_VERSION,

    MRIMPRPL_SUMMARY,
    MRIMPRPL_DESCRIPTION,
    MRIMPRPL_AUTHOR,
    MRIMPRPL_WEBSITE,

    plugin_load,
    plugin_unload,
    plugin_destroy,

    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};                               
    
static void                        
init_plugin(PurplePlugin *plugin)
{                                  
}

PURPLE_INIT_PLUGIN(hello_world, init_plugin, info)
