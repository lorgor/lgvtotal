# Volatility
#
# Author: lorgor    toto897 -aT- gmail.com
#
#
# Credits
#
# This code was shamelessly hacked from the printkey.py plugin (author
# Brendan Dolan-Gavitt).  It is based on the RegRipper tool (author
# Harlan Carvey), especially the RR plugins (authors H Carvey, Brendan
# Coles, and others). See http://regripper.net/
#
# Of course, the plugin author takes full credit for all technical
# errors, lack of respect of Volatility coding principles, and bugs.
# ---------------------------------------------------------
#
# GNU license
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#

#pylint: disable-msg=C0111

import volatility.win32.hive as hivemod
import volatility.win32.rawreg as rawreg
import volatility.debug as debug
import volatility.utils as utils
import volatility.commands as commands
import volatility.plugins.registry.hivelist as hivelist
import volatility.obj as obj

from time import gmtime, strftime



#------------------------------------------------
# Developer's notes
#------------------------------------------------

# First of all, should mention that this is a basic "forklift" port of
# Regripper to Volatility 1.4. At time of writing (2011-4-18) haven't
# had time to do extensive research as to how the various keys are used
# in the various Windows OS's.
#
#
#
# Like PrintKey, this plugin class is based on HiveList. The HiveList
# plugin produces a list of the hives in memory. This plugin uses that
# list as a basis for extraction of specific keys in each hive.
#
# Since RegList is indirectly based on commands.command, the RegList
# plugin is automagically registered as a plugin as well.
#
# The HiveList plugin does not appear to support a user-specified
# offset. So the printkey.py plugin used "User Specified" as the hive
# name.
#
# The RegList plugin uses the hive name to determine which keys to
# list. If the hive name cannot be determined, then all keys are
# listed (if they exist in the given hive of course).
#
# Note that the hive "address space" is implemented by hive.py (in
# volatility/win32). The registry key objects are accessed by
# rawreg.py (also in volatility/win32).
# 
# The definition of the registry object is the _CM_KEY_NODE overlay in
# the corresponding OS overlay (eg
# plugins/overlays/windows/xp_sp2_x86.vtypes.py).  These overlays
# define the attributes for the "key" object that is returned by
# rawreg.open_key. Typical attributes would be: "LastWriteTime",
# "SubKeyCounts", "Name"
#
# In keeping with Volatility plugin structure, the RegList plugin
# function is divided into a "calculate" section, and a "render_text"
# section. The "calculate" section progressively opens each hive in
# turn, then opens specific keys for the given hive. The results are
# returned using a python "yield" stmt which feeds into the next
# section.
#
# The render_text is called by Volatility for each "yield"
# value. Relevant data from the key is extracted and then printed.
#
# The render_key function is driven for the chk_defn dictionary. A
# string of actions is used to determine what formatting to do. Note
# that there is an implicit "for each" between each subsequent tuple.
#
# So the following:
#     [LIST_SUBKEYS, None, PRT_VALUE, ["Vendor","FriendlyName"]]
# means:
#     List all subkeys. For each subkey, print the values "Vendor" and
#     "FriendlyName".

# To get the WinTimeStamp to print out, a temporary Volatility object
# redefining the _CM_KEY_VALUE object was used.
#
# As in printkey.py, unicode strings etc are decoded "on the fly" without
# defining / redefining Volatility objects for all the various permutations
# and combinations of registry key values in all the flavours of Windows.
#
# Most of the above is explained in detail in the relevant Volatility
# developer documentation.
#


#------------------------------------------------
# Lists of key checks to do by OS
#------------------------------------------------

regchk_by_os = {"WinXP" : 
    {"system" : ["compname", "shutdown", "shutdowncount",
                 "timezone", "termserv", "mountdev",
                 "network", "nic2", "fw_config",
                 "devclass_dsk", "devclass_vol",
                 "ide", "shares", "services",
                 "imagedev", "usbstor", "usb"
                 ],

    "ntuser.dat" : ["logonusername", "acmru", "adoberdr",
                    "aim", "applets", "fileexts", "comdlg32",
                    "compdesc", "listsoft", "logon_xp_run",
                    "mmc", "mndmru", "mp2", "mpmru",
                    "officedocs", "officedocs_a",
                    "recentdocs",
                    "realplayer6",
                    "runmru", "tsclient", "typedurls",
                    "typedpaths", "muicache",
                    "userassist", "user_run",
                    "vncviewer", "winzip", "warcraft",
                    "user_win", "winrar", "wallpaper"
                    ],
     "software" : ["apppaths", "cmd_shell",
                   "soft_run",
                   "networkcards", 
                   "appinitdlls", "bho", "imagefile",
                   "winlogon",
                   "uninstall", "profilelist", "win_cv",
                   "mrt", "assoc"
                   ]
     },
     "Win7" :
    {"system" : ["compname", "shutdown", "shutdowncount",
                 "timezone", "termserv", "mountdev",
                 "network", "nic2", "fw_config",
                 "devclass_dsk", "devclass_vol",
                 "ide", "shares", "services",
                 "imagedev", "usbstor",  "usb"],
    "ntuser.dat" : ["logonusername", "acmru", "adoberdr",
                    "aim", "applets", "fileexts",
                    "compdesc", "listsoft",
                    "mmc", "mndmru", "mp2", "mpmru",
                    "officedocs", "officedocs_a",
                    "recentdocs",
                    "realplayer6",
                    "runmru", "tsclient", "typedurls",
                    "typedpaths", "muicache",
                    "userassist", "user_run",
                    "vncviewer", "warcraft",
                    "winzip", "user_win", "winrar", "wallpaper"
                    ],
     "software" : ["apppaths", 
                   "soft_run",
                   "networkcards",
                   "appinitdlls", "bho", "imagefile",
                   "removedev", "winlogon",
                   "profilelist", "win_cv",
                   "mrt", "assoc"
                   ]
     } }



#------------------------------------------------ 
# Definitions for individual checks:
#------------------------------------------------

#     Actions when processing a specific registry key

PRT_VALUE = 1      # Print out value subfields (need to specify the field's name)
LIST_SUBKEYS = 2   # List all the subkeys
PRT_WINTIME = 3    # Print a Windows Timestamp
PRT_SRVC = 4       # Print windows services
PRT_DEV = 5        # Print mounted devices
PRT_CMD = 6        # Print shell\\open\\command subkey value
PRT_UNI = 7        # Print null-terminated Unicode strings
PRT_USRAS = 8      # Print Explorer UserAssist subkey names
PRT_BINTIME = 9    # Print 2 word binary timestamp

#     Definition of Tuple fields
#
#               ccs_flag (true if prefix key with ccs),
#               key,
CHK_MSG = 2   # msg text,
CHK_ACTION =3 # action

# "action" field:
#  (action to do, selection criteria, recursion)

# Note that in the selection criteria sub-field of "action":
#    "all"   accept any value
#    "+"     accept the following values
#    "-"     exclude the following values


chk_defn = {
    # 2011-4-20 not tested yet lg
    "acmru" : (
        False,
        ['Software\\Microsoft\\Search Assistant\\ACMru'],
        "acmru: Microsoft Search Assistant values",
        [LIST_SUBKEYS, ["all"],
         [PRT_VALUE, ["all"]]] # list all subkeys, print all values
        ),
    # 2011-4-20 not tested yet lg
    "adoberdr" : (
        False,
        ["Software\\Adobe\\Acrobat Reader"],
        "Adobe Reader cRecentFiles values, Adobe Rdr version",
        [LIST_SUBKEYS, ["all"],
         [LIST_SUBKEYS, ["+", "AVGeneral"],
          [LIST_SUBKEYS, ["+", "cRecentFiles"],
           [LIST_SUBKEYS, ["all"],
            [PRT_VALUE, ["+", "sDI"]
            ]]]]],
        ),
    # 2011-4-20 not tested yet lg
    "aim" : (
        False, 
        ['Software\\America Online\\AOL Instant Messenger (TM)\\CurrentVersion\\Users'],
        "AOL Instant Messenger information",
        [LIST_SUBKEYS, ["all"],
         [PRT_VALUE, ["all"]]] # list all subkeys, print all values
        ),
    "appinitdlls" : (
        False, 
        ['Microsoft\\Windows NT\\CurrentVersion\\Windows'],
        "Gets contents of AppInit_DLLs value",
        [PRT_VALUE, ["+", "AppInit_DLLs"]]
        ),
    "apppaths" : (
        False, 
        ['Microsoft\\Windows\\CurrentVersion\\App Paths'],
        "Gets content of App Paths key",
        [LIST_SUBKEYS, ["all"],
         [PRT_VALUE, ["+", ""]]]
        ),    
    # 2011-4-20 not tested yet lg
    "applets" : (
        False,
        ["Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\Paint\\Recent File List",
         "Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\Regedit\\LastKey"
         ],
        "Applets: MS Paint recently used files, regedit last key",
        [PRT_VALUE, ["all"]]
        ),
    "assoc" : (
        False, 
        ['Classes'],
        "Gets content of file assoc keys",
        [PRT_VALUE, ["all"]]
        ),
    "bho" : (
        False,
        ["Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects"],
        "Gets Browser Helper Objects from Software hive",
        [PRT_VALUE, ["+", ""], 
         LIST_SUBKEYS, ["+", "InprocServer32"],
         [PRT_VALUE, ["+", ""]]]
        ),
    "cmd_shell" : (
        False,
        ["Classes\\exefile\\shell\\open\\command",
         "Classes\\cmdfile\\shell\\open\\command",
         "Classes\\batfile\\shell\\open\\command",
         "Classes\\csfile\\shell\\open\\command",
         "Classes\\htafile\\shell\\open\\command",
         "Classes\\piffile\\shell\\open\\command",
         ],
        "Gets shell open cmds for various file types",
        [PRT_VALUE, ["+", ""]]
        ),

    # 2011-4-20 not tested yet lg
    "comdlg32" : (
        False,
        ["Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedMRU"],
        "comdlg32: Explorer MRU files for XP",
        [PRT_VALUE, ["all"],
         LIST_SUBKEYS, ["all"],
         [PRT_VALUE, ["all"]]]
        ),
    # 2011-4-20 not tested yet lg
    "compdesc" : (
        False,
        ["Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComputerDescriptions"],
        "user's ComputerDescriptions key",
        [PRT_VALUE, ["all"]]
        ),
    "compname" : (
        True,
        ["Control\\ComputerName\\ComputerName"],
        "ComputerName value from System hive",
        [PRT_VALUE, ["+", "ComputerName"]]
        ),
    "controlpanel" : (
        False,
        ["Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ControlPanel"], 
        "Look for RecentTask* values in ControlPanel key \n"
        "Analysis Tip: The RecentTask* entries appear to only be populated through the"
        "choices in the Control Panel Home view (in Vista).  As each new choice is"
        "selected, the most recent choice is added as RecentTask1, and each "
        "RecentTask* entry is incremented and pushed down in the stack."
        ),
    "devclass_dsk" : (
        True,
        ["Control\\DeviceClasses\\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"],
        "Get disk device info from the DeviceClasses key. Can find USBs mounted.",
        [LIST_SUBKEYS, ["all"], False]
        ),
    "devclass_vol" : (
        True,
        ["Control\\DeviceClasses\\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}"],
        "Get vol info from DeviceClasses key. Can find removeable media mounted.",
        [LIST_SUBKEYS, ["all"], False]
        ),
    "fileexts" : (
        False,
        ["Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts"],
        "Get user's file extension values.",
        [LIST_SUBKEYS, ["all"],
         [LIST_SUBKEYS, ["+", "OpenWithList"],
          [PRT_VALUE, ["all"]]]]
        ),
    "fw_config" : (
        True,
        ["Services\\SharedAccess\\Parameters\\FirewallPolicy"
             "\\DomainProfile\\AuthorizedApplications\\List",
         "Services\\SharedAccess\\Parameters\\FirewallPolicy"
             "\\DomainProfile\\GloballyOpenPorts\\List",
         "Services\\SharedAccess\\Parameters\\FirewallPolicy"
             "\\DomainProfile\\IcmpSettings",
         "Services\\SharedAccess\\Parameters\\FirewallPolicy"
             "\\DomainProfile\\RemoteAdminSettings",
        "Services\\SharedAccess\\Parameters\\FirewallPolicy"
             "\\StandardProfile\\AuthorizedApplications\\List",
         "Services\\SharedAccess\\Parameters\\FirewallPolicy"
             "\\StandardProfile\\GloballyOpenPorts\\List",
         "Services\\SharedAccess\\Parameters\\FirewallPolicy"
             "\\StandardProfile\\IcmpSettings",
         "Services\\SharedAccess\\Parameters\\FirewallPolicy"
             "\\StandardProfile\\RemoteAdminSettings"
         ],
        "Gets the Windows Firewall config from the System hive",
        [PRT_VALUE, ["all"]]       # print all values for each key
        ),
    "ide" : (
        True,
        ["Enum\\IDE"],
        "Get IDE device info. See also devclass output.",
        [LIST_SUBKEYS, ["all"], False]
        ),
    "imagedev" : (
        True,
        ["Control\\Class\\{6BDD1FC6-810F-11D0-BEC7-08002BE2092F}"],
        "imagedev: Get Still image capture devices",
        [LIST_SUBKEYS, ["all"],
         [PRT_VALUE, ["+", "Vendor", "FriendlyName"]]]
        ),
    "imagefile" : (
        False,
        ["Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"],
        "Gets Image File Execution Options subkeys w/ Debugger value",
        [LIST_SUBKEYS, ["+", "Your Image File Name Here without a path"],
         [PRT_VALUE, ["+", "Debugger"]]]
        ),
    "listsoft" : (
        False,
        ["Software"],
        "Lists contents of user's Software key",
        [LIST_SUBKEYS, ["all"], False] 
        ),
    # 2011-4-20 not tested yet lg
    "logon_xp_run" : (
        False,
        ["SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\Explorer\\Run"],
        "Autostart - Get XP user logon Run key contents from NTUSER\.DAT hive",
        [PRT_VALUE, ["all"]]
        ),
    "logonusername" : (
        False,
        ['Software\\Microsoft\\Windows\\CurrentVersion\\Explorer'],
        "Get user's Logon User Name value",
        [PRT_VALUE, ["+", "Logon User Name"]]
        ),
    "mmc" : (
        False,
        ['Software\\Microsoft\\Microsoft Management Console\\Recent File List'],
        "Get contents of user's MS Mgmt Console \\Recent File List key",
        [PRT_VALUE, ["all"]]
        ),
    # 2011-4-20 not tested yet lg
    "mndmru" : (
        False,
        ['Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Map Network Drive MRU'],
        "Get contents of user's Map Network Drive MRU",
        [PRT_VALUE, ["all"]]
        ),
    "mountdev" : (
        False,
        ['MountedDevices'],
        "Return contents of System hive MountedDevices key.",
        [PRT_DEV]
        ),
    "mp2" : (
        False,
        ["Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2"],
        "Gets user's MountPoints2 key contents",
        [LIST_SUBKEYS, ["all"],
         [PRT_VALUE, ["-", "BaseClass", "_AutorunStatus"]]]
        ),
    # 2011-4-20 not tested yet lg
    "mpmru" : (
        False,
        ['Software\\Microsoft\\MediaPlayer\\Player\\RecentFileList'],
        "Gets user's Media Player RecentFileList values",
        [PRT_VALUE, ["all"]]
        ),
   "mrt" : (
        False,
        ['Microsoft\\RemovalTools\\MRT'],
        "MS Removal Tool Version key information: see http://support.microsoft.com/kb/890830/ ",
        [PRT_VALUE, ["+", "Version"]]
        ), 
   "mspaper" : (
        False,
        ['Software\\Microsoft'],
        "Gets images listed in user's MSPaper key"
        ), # $TODO lg
    "muicache" : (
        False,
        ['Software\\Microsoft\\Windows\\ShellNoRoam\\MUICache'],
        "Gets EXEs from user's MUICache key",
        [PRT_VALUE, ["all"]]
        ),
    "network" : (
        True,
        ["Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"],
        "network: Lists active network interfaces. See nic2 output for IP addr",
        [LIST_SUBKEYS, ["-", "Descriptions"],
         [LIST_SUBKEYS, ["+", "Connection"],
          [PRT_VALUE, ["all"]]]]
        ),
    "networkcards" : (
        False,
        ["Microsoft\\Windows NT\\CurrentVersion\\NetworkCards"],
        "Get NetworkCards registry key",
        [LIST_SUBKEYS, ["all"],
         [PRT_VALUE, ["+", "ServiceName", "Description"]]]
        ),
    "nic2" : (
        True,
        ["Services\\Tcpip\\Parameters\\Interfaces"],
        "Gets IP address information for NICs",
        [LIST_SUBKEYS, ["all"],
         [PRT_VALUE, ["all"]]]
        ),
    # 2011-4-20 not tested yet lg
    "officedocs" : (
        False,
        ["Software\\Microsoft\\Office"],
        "Gets contents of user's Office doc MRU keys. Not valid for Office 14 aka 2010",
        [LIST_SUBKEYS, ["all"], 
         [LIST_SUBKEYS, ["+", "Common"],
          [LIST_SUBKEYS, ["+", "Open Find"],
           [LIST_SUBKEYS, ["+", "Microsoft Office Word"],
            [LIST_SUBKEYS, ["+", "Settings"],
             [LIST_SUBKEYS, ["+", "Save As","File Save"],
              [LIST_SUBKEYS, ["+", "File Name MRU"],
               [PRT_VALUE, ["all"]
                ]]]]]]]]
        ),
    # 2011-4-20 not tested yet lg
    "officedocs_a" : (
        False,
        ["Software\\Microsoft\\Office"],
        "Gets contents of user's Office doc MRU keys. Not valid for Office 14 aka 2010",
        [LIST_SUBKEYS, ["all"], 
         [LIST_SUBKEYS, ["+", "Excel", "PowerPoint"],
          [LIST_SUBKEYS, ["+", "Recent Files", "Recent File List"],
           [PRT_VALUE, ["all"]
            ]]]]
        ),
    "profilelist" : (
        False,
        ["Microsoft\\Windows NT\\CurrentVersion\\ProfileList"],
        "Get content of ProfileList key",
        [LIST_SUBKEYS, ["all"],
         [PRT_VALUE, ["+", "ProfileImagePath"],
          PRT_BINTIME, ["ProfileLoadTimeLow", "ProfileLoadTimeHigh"]]]

        ),
    # 2011-4-20 not tested yet lg
    "realplayer6" : (
        False,
        ["Software\\RealNetworks\\RealPlayer\\6.0\\Preferences"],
        "Gets user's RealPlayer v6 MostRecentClips\(Default) values",
        [LIST_SUBKEYS, ["all"],
         [PRT_VALUE, ["all"]]]        
        ),
    "recentdocs" : (
        False,
        ["Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"],
        "Gets contents of user's RecentDocs key",
        [PRT_UNI,
         LIST_SUBKEYS, ["all"],
         [PRT_UNI]]
        ),
    "removedev" : (
        False,
        ["Microsoft\\Windows Portable Devices\\Devices"],
        "Get historical information about drive letter assigned to removeable devices",
        [LIST_SUBKEYS, ["all"],
         [PRT_VALUE, ["+", "FriendlyName"]]]
        ),
    "runmru" : (
        False,
        ['Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU'],
        "Gets contents of user's RunMRU key. MRUList lists entries in order.",
        [PRT_VALUE, ["all"]]
        ),
    "services" : (
        True,
        ["Services"],
        "Lists services/drivers in Services key",
        [PRT_SRVC]
        ),
    "soft_run" : (
        False,
        ["Microsoft\\Windows\\CurrentVersion\\Run"],
        "Autostart - get Run key contents from Software hive",
        [LIST_SUBKEYS, ["all"], False,
         PRT_VALUE, ["all"]]
        ),
    "shares" : (
        True,
        ["Services\\lanmanserver\\Shares"],
        "Get list of shares.",
        [PRT_VALUE, ["all"]]
        ),
    "shutdown" : (
        True,
        ["Control\\Windows"],
        "Gets ShutdownTime value from System hive",
        [PRT_WINTIME, ["ShutdownTime"]]
        ),
    "shutdowncount" : (
        True,
        ["Control\\Watchdog\\Display"],
        "Retrieves ShutDownCount value",
        [PRT_VALUE, ["+", "ShutdownCount"]]
        ),

    "termserv" : (
        True,
        ["Control\\Terminal Server"],
        "Gets Terminal Server fDenyTSConnections value from System hive",
        [PRT_VALUE, ["+", "fDenyTSConnections"]]
        ),
    "timezone" : (
        True,
        ["Control\\TimeZoneInformation"],
        "Get TimeZoneInformation key contents. Note that Bias is in minutes.",
        [PRT_VALUE,  ["+", "TimeZoneKeyName",
                      "StandardName",
                      "DaylightName",
                      "Bias",
                      "ActiveTimeBias"]]
        ),
    # 2011-4-20 not tested yet lg
    "tsclient" : (
        False,
        ['Software\\Microsoft\\Terminal Server Client\\Default'],
        "Displays contents of user's Terminal Server Client\\Default key",
        [PRT_VALUE, ["all"]]
        ),
    # 2011-4-20 not tested yet lg
    "typedpaths" : (
        False,
        ["Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths"],
        "Returns contents of user's TypedURLs key.",
        [PRT_VALUE, ["all"]]
        ),
    "typedurls" : (
        False,
        ['Software\\Microsoft\\Internet Explorer\\TypedURLs'],
        "Returns contents of user's TypedURLs key.",
        [PRT_VALUE, ["all"]]
        ),
    "uninstall" : (
        False,
        ['Microsoft\\Windows\\CurrentVersion\\Uninstall'],
        "Gets contents of Uninstall key from Software hive",
        [LIST_SUBKEYS, ["all"],
         [PRT_VALUE, ["+", "DisplayName"]]]
        ),
    "usb" : (
        True,
        ["Enum\\USB"],
        "Get USB subkeys info",
        [LIST_SUBKEYS, ["all"],
         [LIST_SUBKEYS, ["all"],
          [PRT_VALUE, ["+", "ParentIdPrefix",
                       "FriendlyName",
                       "LocationInformation",
                       "Mfg"
          ]]]]
        ),
    "usbstor" : (
        True,
        ["Enum\\USBStor"],
        "Get USBStor key info",
        [LIST_SUBKEYS, ["all"],
         [LIST_SUBKEYS, ["all"],
          [PRT_VALUE, ["+","ParentIdPrefix", "FriendlyName"]]]]
        ),
    # 2011-4-20 not tested yet lg
   "user_run" : (
        False,
        ["Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
        "Autostart - get Run key contents from NTUSER\.DAT hive",
        [LIST_SUBKEYS, ["all"], False,
         PRT_VALUE, ["all"]]
        ),
    # 2011-4-20 not tested yet lg
    "user_win" : (
        False,
        ["Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows"],
        "Load and run values should be blank, anything listed runs when user logs in",
         [PRT_VALUE, ["+", "load", "run"]]
        ),
    "userassist" : (
        False,
        ['Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist'],
        "Displays contents of UserAssist Active Desktop key",
        [LIST_SUBKEYS, ["all"],
         [LIST_SUBKEYS, ["+", "Count"],
          [PRT_USRAS]]]
        ),
    # 2011-4-20 not tested yet lg
    "vncviewer" : (
        False,
        ["Software\\ORL\\VNCviewer\\MRU"],
        "Get VNCViewer system list",
        [PRT_VALUE, ["all"]]
        ),
    "wallpaper" : (
        False,
        ["Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Wallpaper\\MRU"],
        "Parses Wallpaper MRU Entries",
        [PRT_UNI]
        ),
    # 2011-4-20 not tested yet lg
    "warcraft" : (
        False,
        ["Software\\Blizzard Entertainment\\Warcraft III\\String"],
        "Extract usernames for Warcraft 3.",
        [PRT_VALUE, ["+", "userbnet", "userlocal"]]
        ),
    "winlogon" : (
        False,
        ["Microsoft\\Windows NT\\CurrentVersion\\Winlogon"],
        "userinit: My Documents open at startup - \n"
        "          should be %SystemDrive%\\system32\\userinit.exe\n"
        "          shell: executed when user logs on",
        [PRT_VALUE, ["all"]]
        ),
    "win_cv" : (
        False,
        ["Microsoft\\Windows NT\\CurrentVersion",
         "Microsoft\\Windows\\CurrentVersion"],
        "Display the contents of the Windows CurrentVersion keys",
        [PRT_VALUE, ["all"]]
         # PRT_WINTIME, ["InstallDate"]]  doesn't seem to work
        ),
    # 2011-4-20 not tested yet lg
    "winrar" : (
        False,
        ["Software\\WinRAR\\ArcHistory"],
        "Get WinRAR\\ArcHistory entries",
        [PRT_VALUE, ["all"]]
        ),
    # 2011-4-20 not tested yet lg
    "winzip" : (
        False,
        ["Software\\Nico Mak Computing\\WinZip"],
        "Get WinZip extract and filemenu values",
        [LIST_SUBKEYS, ["+", "extract", "filemenu"],
         [PRT_VALUE, ["all"]]]
        )
    }


#------------------------------------------------
# Definitions of values in Service registry key
#------------------------------------------------

serv_types = {0x001 : "Kernel driver",
              0x002 : "File system driver",
              0x010 : "Own_Process",
              0x020 : "Share_Process",
              0x100 : "Interactive"
              }

serv_starts = {0x00 : "Boot Start",
               0x01 : "System Start",
               0x02 : "Auto Start",
               0x03 : "Manual",
               0x04 : "Disabled"
               }

#------------------------------------------------------------------
# Utility functions
#------------------------------------------------------------------

def vol(k):
    return bool(k.obj_offset & 0x80000000)

FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])

def hd(src, length = 16):
    N = 0
    result = ''
    while src:
        s, src = src[:length], src[length:]
        hexa = ' '.join(["{0:02X}".format(ord(k)) for k in s])
        s = s.translate(FILTER)
        result += "{0:04X}   {2:{1}}   {3}\n".format(N, length * 3, hexa, s)
        N += length
    return result


#------------------------------------------------------------------
# Main plugin class
#------------------------------------------------------------------


class RegList(hivelist.HiveList):
    """
    Registry Lister
    -----------------------------

    Formats selected registry keys from the registry hives in memory. Sets of keys are 
    organized by hive. User can specify which sets of keys to list and which hives to use.

    Default is to dump all sets of keys from all relevant hives.
    """

    def __init__(self, config, *args):
        hivelist.HiveList.__init__(self, config, *args)
        config.add_option('HIVE-OFFSET', short_option = 'o', default=None,
                          help = 'Hive offset (virtual not physical addr)', type = 'int')
        config.add_option('HIVE-NAME', short_option = 'H', default=None,
                          help = 'Name of hive to process', type = 'str')
        config.add_option('CHK', short_option = 'C', default=None,
                          help = 'Specific check to perform', type = 'str')


    def hive_name(self, hive):
        try:
            return hive.FileFullPath.v() or hive.FileUserName.v() or hive.HiveRootPath.v() or "[no name]"
        except AttributeError:
            return "[no name]"

#------------------------------------------------------------------
# Plugin main scanning loop
#------------------------------------------------------------------

    def calculate(self):
        addr_space = utils.load_as(self._config)
        config = self._config

        # Determine OS

#        myos = config.PROFILE[:5]

        profile = addr_space.profile

        if profile.metadata.get('os', 0) == 'windows':
            if profile.metadata.get('major', 0) == 5 and \
                profile.metadata.get('minor', 0) == 1:
                myos = "WinXP"
            elif profile.metadata.get('major', 0) == 6 and \
                profile.metadata.get('minor', 0) == 1:
                myos = "Win7"
        else:
            debug.error("OS not supported")

        assert myos in regchk_by_os

        
        # Determine which checks to do

        if not config.CHK:         

            checklist = []
            # Default action: Do everything
            if not config.HIVE_NAME:
                myhives = regchk_by_os[myos].keys()
            else:
                # User has specified a specific hive to process
                htmp = ''.join(config.HIVE_NAME).lower()
                if not htmp in regchk_by_os[ myos ]:
                    debug.error("Invalid Hive Name specified.")
                else:
                    myhives = [ htmp ]

        # Specific check asked for            
        else:
            check = ''.join(config.CHK).lower()
            if not check in chk_defn:
                debug.error("Invalid check specified.")
            
            # Only 1 check to do
            checklist = [ check ]

            # determine which hive this check refers to (to avoid wasting time on the other hives)
            
            for htmp1, chktmp in regchk_by_os[ myos ].iteritems():
                if check in chktmp:
                    htmp = htmp1

            myhives = [ htmp ]
            config.remove_option("HIVE-NAME")
            
                
        # If user hasn't given a specific hive offset, then default is to try to process all the hives

        if not config.HIVE_OFFSET:
            hive_offsets = [(self.hive_name(h), h.obj_offset) for h in hivelist.HiveList.calculate(self)]
        else:
            hive_offsets = [("User Specified", config.HIVE_OFFSET)]


        # Try to process each hive in turn

        for hname, hoff in set(hive_offsets):
            h = hivemod.HiveAddressSpace(addr_space, config, hoff)
            root = rawreg.get_root(h)

            if not root:
                if config.HIVE_OFFSET:
                    debug.error("Unable to find root key. Is the hive offset correct?")
            
            # Find out which hive this is        
            hive_last_name = hname.lower().split("\\")[-1]


            # see if the current hive is on the list of hives the user wants to process
            for myhive in myhives:

                if not hive_last_name in (myhive, "[no name]", "user specified"):
                    continue

                # Determine current controlset (if the key actually exists in this hive)

                ccs_key = rawreg.open_key(root, [ "CurrentControlSet" ] )
                if ccs_key:
                    ccs_v = rawreg.values(ccs_key)[ 0 ]


                    ccs_tp, ccs_dat = rawreg.value_data(ccs_v)
                    ccs = ccs_dat.encode("ascii", 'backslashreplace').split("\\")[-1] + "\\"
                    # Sanity check
                    if not ccs.lower().startswith("controlset00"):
                        debug.error("CurrentControlSet key found but has invalid value.")
                else:
                    ccs = ""

               # Set checklist to run the checks for this hive
               # If the user just wants to do 1 check then checklist has already been
               # set.

                if not config.CHK:
                    checklist = regchk_by_os[ myos ][ myhive ]

                for check in checklist:
                    chk_ccsflag, chk_key_lst, chk_msg, chk_action_list = chk_defn[check]
                    for chk_key in chk_key_lst:
                        if chk_ccsflag:
                            chk_key = ccs + chk_key
                                    

                        if check == "bho":
                            # Do specific processing for Browser Helper Objects
                            key = rawreg.open_key(root, chk_key.split('\\'))
                            if key:
                                # Pull out the class reg key for each GUID
                                for s in rawreg.subkeys(key):
                                    # pull out the clsid for the BHO
                                    clsid = str(s.Name)
                                    if clsid == None:
                                        pass
                                   # Next read the classid reg key
                                    clsid = "Classes\\CLSID\\" + clsid
                                    yield hname, \
                                        rawreg.open_key(root, clsid.split('\\')), \
                                        check, \
                                        clsid

                        elif check == "assoc":
                            # Do specific processing for file associations
                            key = rawreg.open_key(root, chk_key.split('\\'))
                            if key:
                                # Pull out the file association values
                                assoc_cache = {}
                                for s in rawreg.subkeys(key):
                                    s_name = str(s.Name)

                                    # First look for an association key
                                    if s_name.startswith(r"."):

                                        # Next find the filename value for this association

                                        for v in rawreg.values(s):
                                            # force conversion to string from String object
                                            v_name = str(v.Name)
                                            if not v_name == "":
                                                continue

                                            # Have found the default value key. Now read the datafile value
                                            tp, dat = rawreg.value_data( v )
                                            assert tp == "REG_SZ"
                                            fname = dat.encode("ascii", 'backslashreplace').rstrip("\0")

                                            # Check for cache hit
                                            if not fname in assoc_cache:

                                                # Find the filename key (which has the actual cmd shell value)
                                                cmd_shell_key = "Classes\\" + fname + "\\shell\\open\\command"              
                                                assoc_cache[fname] = [
                                                rawreg.open_key(root, cmd_shell_key.split('\\')),
                                                "{0}, File extension: {1}".format(cmd_shell_key, s_name)
                                                ]
                                                   
                                            yield hname, assoc_cache[fname][0], check, assoc_cache[fname][1]
                                            break
                        else:
                            yield hname, \
                               rawreg.open_key(root, chk_key.split('\\')), \
                               check, \
                               chk_key


#------------------------------------------------------------------
# Plugin output
#------------------------------------------------------------------


    #-----                        
    # Utility functions
    #-----                        

    def voltext(self, key):
        return "(V)" if vol(key) else "(S)"


    def prt_val(self, outfd, key_value):
        tp, dat = rawreg.value_data( key_value )
        if tp == 'REG_BINARY':
            dat = "\n" +hd(dat, length = 16)
        elif tp in ['REG_SZ', 'REG_EXPAND_SZ', 'REG_LINK']:
            dat = dat.encode("ascii", 'backslashreplace')
        elif tp == 'REG_MULTI_SZ':
            for i in range(len(dat)):
                dat[i] = dat[i].encode("ascii", 'backslashreplace')
        outfd.write("   {0:15} : {1:3s} {2:13} {3}\n".format(key_value.Name,
                                                               self.voltext(key_value),
                                                               tp,
                                                               dat))


    #-----                        
    # Extract specific information from a key and print it
    #-----                        
         
    def render_key(self, outfd, key, actions):


        if len(actions) > 0:
            action = actions[0]
        else:
            return
    
        if action == PRT_VALUE:
            valname = actions[1]
            for v in rawreg.values(key):
                # force conversion to string from String object
                v_name = str(v.Name) 

                # Determine whether to print this value
                if valname[0] == "all":
                    pass

                # include specified values
                elif valname[0] == "+":
                    if not v_name in valname:
                        continue
                # exclude specified values
                elif valname[0] == "-":
                    if v_name in valname:
                        continue
                else:
                    debug.error("Pgm Error - Invalid valname render_key PRT_VALUE")

                self.prt_val(outfd, v)
                
            actions = actions[2:]
                           
        elif action == LIST_SUBKEYS:
            subkey_1st = True
            valname = actions[1]
            for s in rawreg.subkeys(key):
                s_name = str(s.Name)

                # Determine whether to list this subkey
                if valname[0] == "all":
                    pass

                # include specified keys
                elif valname[0] == "+":
                    if not s_name in valname:
                        continue

                # exclude specified keys
                elif valname[0] == "-":
                    if s_name in valname:
                        continue
 
                # include subkey if starts with specified value
                elif valname[0] == "s":
                    if not s_name.startswith( valname[1] ):
                        continue

                else:
                    debug.error("Pgm Error - Invalid valname render_key LIST_SUBKEYS")

                if subkey_1st:
                    outfd.write("   Subkeys:\n")
                    subkey_1st = False
                if s_name == None:
                    outfd.write("  Unknown subkey: " + s_name.reason + "\n")
                else:
                    outfd.write("  {1:3s} {0}\n".format(s_name, self.voltext(s)))

                # If there is a recursive action specified for each subkey, then do it
                if actions[2]:
                    self.render_key(outfd, s, actions[2])
                    outfd.write("\n")

            actions = actions[3:]

        # Print Windows Services
        elif action == PRT_SRVC:
            for s in rawreg.subkeys(key):
                v_type, v_start, v_display, v_path = ('','','','')
                for v in rawreg.values(s):
                    v_name = str(v.Name)
                    if v_name in ["Type", 
                                  "DisplayName",
                                  "ImagePath",
                                  "Start"
                                  ]:
                        tp, dat = rawreg.value_data(v)
                        if v_name == "Type":
                            if dat in serv_types:
                                v_type = serv_types[dat]
                        elif v_name == "Start":
                            if dat in serv_starts:
                                v_start = serv_starts[dat]
                        elif v_name == "ImagePath":
                            v_path = dat
                        else:
                            v_display = dat

                outfd.write("\n   {0:s} {1} {2:10s} {3}".format(s.Name,
                                                         v_display,
                                                         self.voltext(s),
                                                         s.LastWriteTime))
                outfd.write("\n           {0} Start= {1}, Type= {2}\n".format( v_path, v_start, v_type))            
            actions = actions[1:]
            
        # Data field is a Windows TimeStamp
        elif action == PRT_WINTIME:
            valname = actions[1]
            for v in rawreg.values(key):
                v_name = v.Name    
                if v_name in valname:
                    v_ts = obj.Object("WinTimeStamp", v.Data.v(), v.obj_vm)
                    outfd.write("   {0} {1} \n".format(v_name, v_ts))

            actions = actions[2:]

        # Data field is MountedDevices key value
        elif action == PRT_DEV:
            for v in rawreg.values(key):
                tp, dat = rawreg.value_data(v)
                assert tp == 'REG_BINARY'
                if v.DataLength == 12:
                    hexa = ' '.join(["{0:02X}".format(ord(k)) for k in dat[:4]])
                    outfd.write("\n   {0:15} : {1:3s}\n      Drive Signature: {2}\n".format(v.Name,
                                                                       self.voltext(v),
                                                                       hexa))                    
                elif v.DataLength > 12:
                    dat = dat.encode("ascii", 'backslashreplace')
                    outfd.write("\n   {0:15} : {1:3s}\n      {2}\n".format(v.Name,
                                                                       self.voltext(v),
                                                                       dat))
            actions = actions[1:]
                        
        # Access and print "shell\\open\\command" subkey value


        # Print value which is null-terminated Unicode string
        elif action == PRT_UNI:
            for v in rawreg.values(key):
                v_name = str(v.Name)
                if v_name.startswith("MRUList"):
                    continue
                tp, dat = rawreg.value_data( v )
                assert( tp == "REG_BINARY")

                # grab up to (but not including) the first null byte
                xx = dat.decode('utf-16-le', "ignore").split("\0")[0]
                # convert unicode to ascii
                yy = xx.encode("ascii", 'backslashreplace')
                outfd.write("   {0} {1}\n".format(v_name, yy))

            actions = actions[1:]

        # Print Explorer UserAssist Active Desktop key
        elif action == PRT_USRAS:
            for v in rawreg.values(key):
                v_name = str(v.Name)
                if v_name.startswith("HRZR"):
                    # Python decodes rot13 to unicode so need to convert to ascii
                    ad_ent = v_name.decode('rot13', "ignore").encode("ascii", 'backslashreplace')
                    outfd.write("   {0}\n".format(ad_ent)) 
            actions = actions[1:]

        # Print a binary timestamp stored as low value / high value
        # Assumes that low value key field is specified first, followed by high value
        elif action == PRT_BINTIME:
            valname = actions[1]
            v_ts_lo = 0
            v_ts_hi = 0
            for v in rawreg.values(key):
                v_name = v.Name    
                if v_name == valname[0]: 
                    tp, v_ts_lo = rawreg.value_data( v )
                    assert tp == "REG_DWORD"
                elif v_name == valname[1]:
                    tp, v_ts_hi = rawreg.value_data( v )
                    assert tp == "REG_DWORD"                    
            if not v_ts_lo == 0:

                # Format the time for display

                windows_ts = (v_ts_hi << 32) | v_ts_lo
                if(windows_ts == 0):
                    unix_time =0
                else:
                    unix_time = windows_ts / 10000000 # nano-sec since 16
                    unix_time = unix_time - 11644473600

                if unix_time < 0:
                    unix_time = 0

                try:     
                    utc_display = strftime("%a %b %d %H:%M:%S %Y UTC", gmtime( unix_time ))
                except ValueError, e:
                    utc_display = "Datetime conversion failure: " + str(e)

                outfd.write("  {0} : {1} \n".format(valname, utc_display))

            actions = actions[2:]



        else:
            debug.error("Pgm error: render_key invalid action string")


        # If there are more actions, then do each one in turn
        if len( actions ) > 0:
            self.render_key(outfd, key, actions)
            outfd.write("\n")


    #-----                        
    # Main print function
    #-----                        

    def render_text(self, outfd, data):


        outfd.write("Legend: (S) = Stable   (V) = Volatile\n\n")
        keyfound = False
        last_check = ""
        last_hive = ""
        for hname, key, check, chk_key in data:
            if key:
                keyfound = True
                if not (last_check == check and last_hname == hname):
                    outfd.write("----------------------------\n")
                    outfd.write("Registry: {0}\n".format(hname))
                    outfd.write("   Key: {0} {1:3s}".format(chk_key, self.voltext(key)))
                    outfd.write("      Last updated: {0}\n".format(key.LastWriteTime))
                    outfd.write("\n   Check: {0}\n\n".format(chk_defn[ check ][ CHK_MSG ]))
                    last_check = check
                    last_hname = hname
                else:
                    outfd.write("\n   Key: {0} {1:3s}".format(chk_key, self.voltext(key)))
                    outfd.write("      Last updated: {0}\n".format(key.LastWriteTime))


                self.render_key(outfd, key, chk_defn[ check ][CHK_ACTION ])

        if not keyfound:
            outfd.write("The requested key could not be found in the hive(s) searched\n")
