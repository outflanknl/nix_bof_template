#include <dlfcn.h>
#include <objc/message.h>
#include <objc/objc.h>
#include <stddef.h>
#include <sys/stat.h>
#include <CoreFoundation/CoreFoundation.h>
#include "../../beacon.h"

int libSystem$stat(const char* pathname, struct stat* statbuf);
char* libSystem$strcasestr(const char* haystack, const char* needle);
id libobjc$objc_getClass(const char* name);
SEL libobjc$sel_registerName(const char* str);
id libobjc$objc_msgSend(id self, SEL op, ...);
void* libobjc$objc_autoreleasePoolPush(void);
void libobjc$objc_autoreleasePoolPop(void* pool);
CFIndex CoreFoundation$CFArrayGetCount(CFArrayRef theArray);
const void* CoreFoundation$CFArrayGetValueAtIndex(CFArrayRef theArray, CFIndex idx);

bool file_exists(const char* path) {
    struct stat stat_data;
    return libSystem$stat(path, &stat_data) == 0;
}

void report_finding(bool flag, char* message) {
    if (!flag) {
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, message);
}

void go(char* args, int alen) {
    id workspace_class = NULL;
    id workspace = NULL;
    id running_apps = NULL;
    unsigned long count = 0;

    // https://github.com/cedowens/SwiftBelt/blob/b84c0ed5d993f1628e9776c0ea8cef81aaf8bfe5/Sources/SwiftBelt/main.swift#L43
    // https://github.com/its-a-feature/HealthInspector/blob/20af1ce805144ad96c0b1bbdaa56959aa5423cfc/HealthInspector.js#L1059
    bool has_carbon_black = file_exists("/Applications/CarbonBlack/CbOsxSensorService");
    bool has_cb_defense = file_exists("/Applications/Confer.app");
    bool has_eset = file_exists("/Library/Application Support/com.eset.remoteadministrator.agent");
    bool has_little_snitch = file_exists("/Library/Little Snitch/");
    bool has_fireeye_hx = file_exists("/Library/FireEye/xagt");
    bool has_crowdstrike_falcon = file_exists("/Library/CS/falcond") || file_exists("/Applications/Falcon.app/Contents/Resources");
    bool has_opendns = file_exists("/Library/Application Support/OpenDNS Roaming Client/dns-updater");
    bool has_sentinelone = false;
    bool has_globalprotect = file_exists("/Library/Logs/PaloAltoNetworks/GlobalProtect") || file_exists("/Library/PaloAltoNetworks");
    bool has_pulse_vpn = file_exists("/Applications/Pulse Secure.app");
    bool has_cisco_amp = file_exists("/opt/cisco/amp");
    bool has_jamf = file_exists("/usr/local/bin/jamf") || file_exists("/usr/local/jamf");
    bool has_malwarebytes = file_exists("/Library/Application Support/Malwarebytes");
    bool has_osquery = file_exists("/usr/local/bin/osqueryi");
    bool has_sophos = file_exists("/Library/Sophos Anti-Virus/");
    bool has_lulu = file_exists("/Library/Objective-See/Lulu") || file_exists("/Applications/LuLu.app");
    bool has_dnd = file_exists("/Library/Objective-See/DND") || file_exists("/Applications/Do Not Disturb.app/");
    bool has_whats_your_sign = file_exists("/Applications/WhatsYourSign.app");
    bool has_knock_knock = file_exists("/Applications/KnockKnock.app");
    bool has_reikey = file_exists("/Applications/ReiKey.app");
    bool has_oversight = file_exists("/Applications/OverSight.app");
    bool has_kextviewr = file_exists("/Applications/KextViewr.app");
    bool has_blockblock = file_exists("/Applications/BlockBlock Helper.app");
    bool has_netiquette = file_exists("/Applications/Netiquette.app");
    bool has_processmonitor = file_exists("/Applications/ProcessMonitor.app");
    bool has_filemonitor = file_exists("/Applications/FileMonitor.app");

    void* autorelease_pool = libobjc$objc_autoreleasePoolPush();

    void* appkit = dlopen("AppKit", RTLD_LAZY);
    if (!appkit) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to load AppKit framework");
        goto cleanup;
    }

    workspace_class = libobjc$objc_getClass("NSWorkspace");
    if (!workspace_class) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to get NSWorkspace class");
        goto cleanup;
    }

    workspace = libobjc$objc_msgSend(workspace_class, libobjc$sel_registerName("sharedWorkspace"));
    if (!workspace) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to get shared workspace");
        goto cleanup;
    }

    running_apps = libobjc$objc_msgSend(workspace, libobjc$sel_registerName("runningApplications"));
    if (!running_apps) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to get running applications");
        goto cleanup;
    }

    count = CoreFoundation$CFArrayGetCount((CFArrayRef)running_apps);
    for (unsigned long i = 0; i < count; i++) {
        id app = (id)CoreFoundation$CFArrayGetValueAtIndex((CFArrayRef)running_apps, i);
        id localized_name = libobjc$objc_msgSend(app, libobjc$sel_registerName("localizedName"));
        char* name = (char*)libobjc$objc_msgSend(localized_name, libobjc$sel_registerName("UTF8String"));
        if (!name) {
            continue;
        }
    
        if (libSystem$strcasestr(name, "CbOsxSensorService")) {
            has_carbon_black = true;
        }
        else if (libSystem$strcasestr(name, "CbDefense")) {
            has_cb_defense = true;
        }
        else if (libSystem$strcasestr(name, "Snitch")) {
            has_little_snitch = true;
        }
        else if (libSystem$strcasestr(name, "xagt")) {
            has_fireeye_hx = true;
        }
        else if (libSystem$strcasestr(name, "falcond")) {
            has_crowdstrike_falcon = true;
        }
        else if (libSystem$strcasestr(name, "OpenDNS")) {
            has_opendns = true;
        }
        else if (libSystem$strcasestr(name, "SentinelOne")) {
            has_sentinelone = true;
        }
        else if (libSystem$strcasestr(name, "GlobalProtect") || libSystem$strcasestr(name, "PanGPS")) {
            has_globalprotect = true;
        }
        else if (libSystem$strcasestr(name, "HostChecker") || libSystem$strcasestr(name, "pulsesecure") || libSystem$strcasestr(name, "Pulse-Secure")) {
            has_pulse_vpn = true;
        }
        else if (libSystem$strcasestr(name, "AMP-for-Endpoints")) {
            has_cisco_amp = true;
        }
        else if (libSystem$strcasestr(name, "lulu")) {
            has_lulu = true;
        }
        else if (libSystem$strcasestr(name, "dnd")) {
            has_dnd = true;
        }
        else if (libSystem$strcasestr(name, "WhatsYourSign")) {
            has_whats_your_sign = true;
        }
        else if (libSystem$strcasestr(name, "KnockKnock")) {
            has_knock_knock = true;
        }
        else if (libSystem$strcasestr(name, "reikey")) {
            has_reikey = true;
        }
        else if (libSystem$strcasestr(name, "OverSight")) {
            has_oversight = true;
        }
        else if (libSystem$strcasestr(name, "KextViewr")) {
            has_kextviewr = true;
        }
        else if (libSystem$strcasestr(name, "blockblock")) {
            has_blockblock = true;
        }
        else if (libSystem$strcasestr(name, "Netiquette")) {
            has_netiquette = true;
        }
        else if (libSystem$strcasestr(name, "processmonitor")) {
            has_processmonitor = true;
        }
        else if (libSystem$strcasestr(name, "filemonitor")) {
            has_filemonitor = true;
        }
    }

    report_finding(has_carbon_black, "Carbon Black Sensor installed\n");
    report_finding(has_cb_defense, "CB Defense A/V installed\n");
    report_finding(has_eset, "ESET A/V installed\n");
    report_finding(has_little_snitch, "Little Snitch firewall found\n");
    report_finding(has_fireeye_hx, "FireEye HX agent found\n");
    report_finding(has_crowdstrike_falcon, "CrowdStrike Falcon agent found\n");
    report_finding(has_opendns, "OpenDNS client found\n");
    report_finding(has_sentinelone, "SentinelOne agent found\n");
    report_finding(has_globalprotect, "GlobalProtect PAN VPN client found\n");
    report_finding(has_pulse_vpn, "Pulse VPN client found\n");
    report_finding(has_cisco_amp, "Cisco AMP for endpoints found\n");
    report_finding(has_jamf, "JAMF found on this host\n");
    report_finding(has_malwarebytes, "Malwarebytes A/V found\n");
    report_finding(has_osquery, "osquery found\n");
    report_finding(has_sophos, "Sophos A/V found\n");
    report_finding(has_lulu, "Objective See LuLu firewall found\n");
    report_finding(has_dnd, "Objective See Do Not Disturb 'lid open' event monitor found\n");
    report_finding(has_whats_your_sign, "Objective See Whats Your Sign code signature info tool found\n");
    report_finding(has_knock_knock, "Objective See Knock Knock persistence detection tool found\n");
    report_finding(has_reikey, "Objective See ReiKey keyboard event taps detection tool found\n");
    report_finding(has_oversight, "Objective See OverSight microphone and camera monitoring tool found\n");
    report_finding(has_kextviewr, "Objective See KextViewr kernel module detection tool found\n");
    report_finding(has_blockblock, "Objective See Block Block persistence location monitoring tool found\n");
    report_finding(has_netiquette, "Objective See Netiquette network monitoring tool found\n");
    report_finding(has_processmonitor, "Objective See Process Monitor tool found\n");
    report_finding(has_filemonitor, "Objective See File Monitor tool found\n");

cleanup:
    if (autorelease_pool) {
        libobjc$objc_autoreleasePoolPop(autorelease_pool);
    }

    if (appkit) {
        dlclose(appkit);
    }
}
