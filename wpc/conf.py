# Not a class, just a bunch of constants
import _winreg
import ntsecuritycon
import win32con
import win32netcon
import win32service

remote_server = None
executable_file_extensions = ('exe', 'com', 'bat', 'dll', 'pl', 'rb', 'py', 'php', 'inc', 'asp', 'aspx', 'ocx', 'vbs', 'sys')
version = None
cache = None
on64bitwindows = None
max_password_age = 365 * 24 * 60 * 60

screensaver_max_timeout_secs = 600

reg_keys = {
    'Devices: Unsigned driver installation behavior': 'HKEY_LOCAL_MACHINE\Software\Microsoft\Driver Signing\Policy',
    'Recovery console: Allow automatic administrative logon ': 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SecurityLevel',
    'Recovery console: Allow floppy copy and access to all drives and all folders': 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SetCommand',
    'Devices: Restrict CD-ROM access to locally logged-on user only': 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateCDRoms',
    'Devices: Allowed to format and eject removable media': 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateDASD',
    'Devices: Restrict floppy access to locally logged-on user only': 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateFloppies',
    'Interactive logon: Number of previous logons to cache (in case domain controller is not available)': 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount ',
    'Interactive logon: Require Domain Controller authentication to unlock workstation': 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon',
    'Interactive logon: Prompt user to change password before expiration': 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning',
    'Interactive logon: Smart card removal behavior': 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption',
    'Interactive Logon: Display user information when session is locked': 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System, value=DontDisplayLockedUserId',
    'Interactive logon: Do not require CTRL+ALT+DELETE': 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD',
    'Interactive logon: Do not display last user name': 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName',
    'Network security: Configure encryption types allowed for Kerberos': 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes',
    'Interactive logon: Message title for users attempting to logon': 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption',
    'Interactive logon: Message text for users attempting to logon': 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText',
    'Interactive logon: Require smart card': 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ScForceOption',
    'Shutdown: Allow system to be shut down without having to log on': 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon',
    'Devices: Allow undock without having to log on': 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\UndockWithoutLogon',
    'System Cryptography: Force strong key protection for user keys stored on the computer': 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Cryptography\ForceKeyProtection',
    'DCOM: HKEY_LOCAL_MACHINE Access Restrictions in Security Descriptor Definition Language (SDDL) syntax': 'HKEY_LOCAL_MACHINE\SOFTWARE\policies\Microsoft\windows NT\DCOM\MachineAccessRestriction',
    'DCOM: HKEY_LOCAL_MACHINE Launch Restrictions in Security Descriptor Definition Language (SDDL) syntax': 'HKEY_LOCAL_MACHINE\SOFTWARE\policies\Microsoft\windows NT\DCOM\MachineLaunchRestriction',
    'System settings: Use Certificate Rules on Windows Executables for Software Restriction Policies': 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers\AuthenticodeEnabled',
    'Audit: Audit the accesss of global system objects': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\AuditBaseObjects',
    'Audit: Shut down system immediately if unable to log security audits': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail',
    'Network access: Do not allow storage of credentials or .NET Passports for network authentication': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds',
    'Network access: Let Everyone permissions apply to anonymous users': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous',
    'System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy',
    'Network access: Sharing and security model for local accounts': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest',
    'Audit: Audit the use of Backup and Restore privilege': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\FullPrivilegeAuditing',
    'Accounts: Limit local account use of blank passwords to console logon only': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse',
    'Network security: LAN Manager authentication level': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel',
    'Network security: Allow LocalSystem NULL session fallback': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\allownullsessionfallback',
    'Network security: Restrict NTLM: Audit Incoming NTLM Traffic': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\AuditReceivingNTLMTraffic',
    'Network security: Restrict NTLM: Add remote server exceptions for NTLM authentication': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\ClientAllowedNTLMServers',
    'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec',
    'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec',
    'Network security: Restrict NTLM: Incoming NTLM traffic': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\RestrictReceivingNTLMTraffic',
    'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic',
    'System objects: Default owner for objects created by members of the Administrators group': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\NoDefaultAdminOwner',
    'Network security: Do not store LAN Manager hash value on next password change': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash',
    'Network security: Allow PKU2U authentication requests to this computer to use online identities.': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\pku2u\AllowOnlineID',
    'Network access: Do not allow anonymous enumeration of SAM accounts and shares': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous',
    'Network access: Do not allow anonymous enumeration of SAM accounts': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM',
    'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy',
    'Domain controller: Allow server operators to schedule tasks': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\SubmitControl',
    'Network security: Allow Local System to use computer identity for NTLM': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\UseMachineId',
    'Devices: Prevent users from installing printer drivers': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers',
    'Network access: Remotely accessible registry paths': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine',
    'Network access: Remotely accessible registry paths and subpaths': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine',
    'System objects: Require case insensitivity for non-Windows subsystems': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\ObCaseInsensitive',
    'Shutdown: Clear virtual memory pagefile': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management\ClearPageFileAtShutdown',
    'System objects: Strengthen default permissions of internal system objects (e.g., Symbolic Links) ': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\ProtectionMode',
    'System settings: Optional subsystems': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\SubSystems\optional',
    'Microsoft network server: Amount of idle time required before suspending session': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect',
    'Microsoft network server: Disconnect clients when logon hours expire': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableForcedLogOff',
    'Microsoft network server: Digitally sign communications (if client agrees)': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature',
    'Network access: Named Pipes that can be accessed anonymously': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes',
    'Network access: Restrict anonymous access to Named Pipes and Shares': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares',
    'Network access: Shares that can be accessed anonymously': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares ',
    'Microsoft network server: Digitally sign communications (always)': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature',
    'Microsoft network server: Server SPN target name validation level': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\SmbServerNameHardeningLevel',
    'Microsoft network client: Send unencrypted password to third-party SMB servers': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword',
    'Microsoft network client: Digitally sign communications (if server agrees) ': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature',
    'Microsoft network client: Digitally sign communications (always)': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature',
    'Network security: LDAP client signing requirements': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity',
    'Network security: Restrict NTLM: Audit NTLM authentication in this domain': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\AuditNTLMInDomain',
    'Network security: Restrict NTLM: Add server exceptions in this domain': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DCAllowedNTLMServers',
    'Domain member: Disable HKEY_LOCAL_MACHINE account password changes': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange',
    'Domain member: Maximum HKEY_LOCAL_MACHINE account password age': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge',
    'Domain controller: Refuse HKEY_LOCAL_MACHINE account password changes': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RefusePasswordChange',
    'Domain member: Digitally encrypt or sign secure channel data (always)': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal',
    'Domain member: Require strong (Windows 2000 or later) session key': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey',
    '"Network security: Restrict NTLM:  NTLM authentication in this domain': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RestrictNTLMInDomain',
    'Domain member: Digitally encrypt secure channel data (when possible)': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel',
    'Domain member: Digitally sign secure channel data (when possible) ': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel',
    'Domain controller: LDAP server signing requirements': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity',
}

msexploitstring = '''
   aix/rpc_cmsd_opcode21                                          2009-10-07       great      AIX Calendar Manager Service Daemon (rpc.cmsd) Opcode 21 Buffer Overflow
   aix/rpc_ttdbserverd_realpath                                   2009-06-17       great      ToolTalk rpc.ttdbserverd _tt_internal_realpath Buffer Overflow (AIX)
   apple_ios/browser/safari_libtiff                               2006-08-01       good       Apple iOS MobileSafari LibTIFF Buffer Overflow
   apple_ios/email/mobilemail_libtiff                             2006-08-01       good       Apple iOS MobileMail LibTIFF Buffer Overflow
   apple_ios/ssh/cydia_default_ssh                                2007-07-02       excellent  Apple iOS Default SSH Password Vulnerability
   bsdi/softcart/mercantec_softcart                               2004-08-19       great      Mercantec SoftCart CGI Overflow
   dialup/multi/login/manyargs                                    2001-12-12       good       System V Derived /bin/login Extraneous Arguments Buffer Overflow
   freebsd/ftp/proftp_telnet_iac                                  2010-11-01       great      ProFTPD 1.3.2rc3 - 1.3.3b Telnet IAC Buffer Overflow (FreeBSD)
   freebsd/local/mmap                                             2013-06-18       great      FreeBSD 9 Address Space Manipulation Privilege Escalation
   freebsd/samba/trans2open                                       2003-04-07       great      Samba trans2open Overflow (*BSD x86)
   freebsd/tacacs/xtacacsd_report                                 2008-01-08       average    XTACACSD <= 4.1.2 report() Buffer Overflow
   freebsd/telnet/telnet_encrypt_keyid                            2011-12-23       great      FreeBSD Telnet Service Encryption Key ID Buffer Overflow
   hpux/lpd/cleanup_exec                                          2002-08-28       excellent  HP-UX LPD Command Execution
   irix/lpd/tagprinter_exec                                       2001-09-01       excellent  Irix LPD tagprinter Command Execution
   linux/browser/adobe_flashplayer_aslaunch                       2008-12-17       good       Adobe Flash Player ActionScript Launch Command Execution Vulnerability
   linux/ftp/proftp_sreplace                                      2006-11-26       great      ProFTPD 1.2 - 1.3.0 sreplace Buffer Overflow (Linux)
   linux/ftp/proftp_telnet_iac                                    2010-11-01       great      ProFTPD 1.3.2rc3 - 1.3.3b Telnet IAC Buffer Overflow (Linux)
   linux/games/ut2004_secure                                      2004-06-18       good       Unreal Tournament 2004 "secure" Overflow (Linux)
   linux/http/alcatel_omnipcx_mastercgi_exec                      2007-09-09       manual     Alcatel-Lucent OmniPCX Enterprise masterCGI Arbitrary Command Execution
   linux/http/ddwrt_cgibin_exec                                   2009-07-20       excellent  DD-WRT HTTP Daemon Arbitrary Command Execution
   linux/http/dlink_diagnostic_exec_noauth                        2013-03-05       excellent  DLink DIR-645 / DIR-815 diagnostic.php Command Execution
   linux/http/dlink_dir615_up_exec                                2013-02-07       excellent  D-Link DIR615h OS Command Injection
   linux/http/dolibarr_cmd_exec                                   2012-04-06       excellent  Dolibarr ERP & CRM 3 Post-Auth OS Command Injection
   linux/http/dreambox_openpli_shell                              2013-02-08       great      OpenPLI Webif Arbitrary Command Execution
   linux/http/esva_exec                                           2012-08-16       excellent  E-Mail Security Virtual Appliance learn-msg.cgi Command Injection
   linux/http/gpsd_format_string                                  2005-05-25       average    Berlios GPSD Format String Vulnerability
   linux/http/groundwork_monarch_cmd_exec                         2013-03-08       excellent  GroundWork monarch_scan.cgi OS Command Injection
   linux/http/hp_system_management                                2012-09-01       normal     HP System Management Anonymous Access Code Execution
   linux/http/linksys_apply_cgi                                   2005-09-13       great      Linksys WRT54 Access Point apply.cgi Buffer Overflow
   linux/http/linksys_e1500_apply_exec                            2013-02-05       excellent  Linksys E1500/E2500 apply.cgi Remote Command Injection
   linux/http/linksys_wrt160nv2_apply_exec                        2013-02-11       excellent  Linksys WRT160nv2 apply.cgi Remote Command Injection
   linux/http/linksys_wrt54gl_apply_exec                          2013-01-18       manual     Linksys WRT54GL apply.cgi Command Execution
   linux/http/mutiny_frontend_upload                              2013-05-15       excellent  Mutiny 5 Arbitrary File Upload
   linux/http/netgear_dgn1000b_setup_exec                         2013-02-06       excellent  Netgear DGN1000B setup.cgi Remote Command Execution
   linux/http/netgear_dgn2200b_pppoe_exec                         2013-02-15       manual     Netgear DGN2200B pppoe.cgi Remote Command Execution
   linux/http/nginx_chunked_size                                  2013-05-07       normal     Nginx HTTP Server 1.3.9-1.4.0 Chunked Encoding Stack Buffer Overflow
   linux/http/openfiler_networkcard_exec                          2012-09-04       excellent  Openfiler v2.x NetworkCard Command Execution
   linux/http/peercast_url                                        2006-03-08       average    PeerCast <= 0.1216 URL Handling Buffer Overflow (linux)
   linux/http/piranha_passwd_exec                                 2000-04-04       excellent  RedHat Piranha Virtual Server Package passwd.php3 Arbitrary Command Execution
   linux/http/symantec_web_gateway_exec                           2012-05-17       excellent  Symantec Web Gateway 5.0.2.8 ipchange.php Command Injection
   linux/http/symantec_web_gateway_file_upload                    2012-05-17       excellent  Symantec Web Gateway 5.0.2.8 Arbitrary PHP File Upload Vulnerability
   linux/http/symantec_web_gateway_lfi                            2012-05-17       excellent  Symantec Web Gateway 5.0.2.8 relfile File Inclusion Vulnerability
   linux/http/symantec_web_gateway_pbcontrol                      2012-07-23       excellent  Symantec Web Gateway 5.0.2.18 pbcontrol.php Command Injection
   linux/http/vcms_upload                                         2011-11-27       excellent  V-CMS PHP File Upload and Execute
   linux/http/wanem_exec                                          2012-08-12       excellent  WAN Emulator v2.3 Command Execution
   linux/http/webcalendar_settings_exec                           2012-04-23       excellent  WebCalendar 1.2.4 Pre-Auth Remote Code Injection
   linux/http/webid_converter                                     2011-07-05       excellent  WeBid converter.php Remote PHP Code Injection
   linux/http/zen_load_balancer_exec                              2012-09-14       excellent  ZEN Load Balancer Filelog Command Execution
   linux/http/zenoss_showdaemonxmlconfig_exec                     2012-07-30       good       Zenoss 3 showDaemonXMLConfig Command Execution
   linux/ids/snortbopre                                           2005-10-18       good       Snort Back Orifice Pre-Preprocessor Buffer Overflow
   linux/imap/imap_uw_lsub                                        2000-04-16       good       UoW IMAP server LSUB Buffer Overflow
   linux/local/hp_smhstart                                        2013-03-30       normal     HP System Management Homepage Local Privilege Escalation
   linux/local/kloxo_lxsuexec                                     2012-09-18       normal     Kloxo Local Privilege Escalation
   linux/local/sock_sendpage                                      2009-08-13       great      Linux Kernel Sendpage Local Privilege Escalation
   linux/local/udev_netlink                                       2009-04-16       great      Linux udev Netlink Local Privilege Escalation
   linux/local/zpanel_zsudo                                       2013-06-07       excellent  ZPanel zsudo Local Privilege Escalation Exploit
   linux/madwifi/madwifi_giwscan_cb                               2006-12-08       average    Madwifi SIOCGIWSCAN Buffer Overflow
   linux/misc/accellion_fta_mpipe2                                2011-02-07       excellent  Accellion File Transfer Appliance MPIPE2 Command Execution
   linux/misc/drb_remote_codeexec                                 2011-03-23       excellent  Distributed Ruby Send instance_eval/syscall Code Execution
   linux/misc/gld_postfix                                         2005-04-12       good       GLD (Greylisting Daemon) Postfix Buffer Overflow
   linux/misc/hp_data_protector_cmd_exec                          2011-02-07       excellent  HP Data Protector 6 EXEC_CMD Remote Code Execution
   linux/misc/hplip_hpssd_exec                                    2007-10-04       excellent  HPLIP hpssd.py From Address Arbitrary Command Execution
   linux/misc/ib_inet_connect                                     2007-10-03       good       Borland InterBase INET_connect() Buffer Overflow
   linux/misc/ib_jrd8_create_database                             2007-10-03       good       Borland InterBase jrd8_create_database() Buffer Overflow
   linux/misc/ib_open_marker_file                                 2007-10-03       good       Borland InterBase open_marker_file() Buffer Overflow
   linux/misc/ib_pwd_db_aliased                                   2007-10-03       good       Borland InterBase PWD_db_aliased() Buffer Overflow
   linux/misc/lprng_format_string                                 2000-09-25       normal     LPRng use_syslog Remote Format String Vulnerability
   linux/misc/mongod_native_helper                                2013-03-24       normal     MongoDB nativeHelper.apply Remote Code Execution
   linux/misc/nagios_nrpe_arguments                               2013-02-21       excellent  Nagios Remote Plugin Executor Arbitrary Command Execution
   linux/misc/netsupport_manager_agent                            2011-01-08       average    NetSupport Manager Agent Remote Buffer Overflow
   linux/misc/novell_edirectory_ncp_bof                           2012-12-12       normal     Novell eDirectory 8 Buffer Overflow
   linux/misc/zabbix_server_exec                                  2009-09-10       excellent  Zabbix Server Arbitrary Command Execution
   linux/mysql/mysql_yassl_getname                                2010-01-25       good       MySQL yaSSL CertDecoder::GetName Buffer Overflow
   linux/mysql/mysql_yassl_hello                                  2008-01-04       good       MySQL yaSSL SSL Hello Message Buffer Overflow
   linux/pop3/cyrus_pop3d_popsubfolders                           2006-05-21       normal     Cyrus IMAPD pop3d popsubfolders USER Buffer Overflow
   linux/postgres/postgres_payload                                2007-06-05       excellent  PostgreSQL for Linux Payload Execution
   linux/pptp/poptop_negative_read                                2003-04-09       great      Poptop Negative Read Overflow
   linux/proxy/squid_ntlm_authenticate                            2004-06-08       great      Squid NTLM Authenticate Overflow
   linux/samba/chain_reply                                        2010-06-16       good       Samba chain_reply Memory Corruption (Linux x86)
   linux/samba/lsa_transnames_heap                                2007-05-14       good       Samba lsa_io_trans_names Heap Overflow
   linux/samba/setinfopolicy_heap                                 2012-04-10       normal     Samba SetInformationPolicy AuditEventsInfo Heap Overflow
   linux/samba/trans2open                                         2003-04-07       great      Samba trans2open Overflow (Linux x86)
   linux/smtp/exim4_dovecot_exec                                  2013-05-03       excellent  Exim and Dovecot Insecure Configuration Command Injection
   linux/ssh/f5_bigip_known_privkey                               2012-06-11       excellent  F5 BIG-IP SSH Private Key Exposure
   linux/ssh/symantec_smg_ssh                                     2012-08-27       excellent  Symantec Messaging Gateway 9.5 Default SSH Password Vulnerability
   linux/telnet/telnet_encrypt_keyid                              2011-12-23       great      Linux BSD-derived Telnet Service Encryption Key ID Buffer Overflow
   linux/upnp/miniupnpd_soap_bof                                  2013-03-27       normal     MiniUPnPd 1.0 Stack Buffer Overflow Remote Code Execution
   multi/browser/firefox_escape_retval                            2009-07-13       normal     Firefox 3.5 escape() Return Value Memory Corruption
   multi/browser/firefox_queryinterface                           2006-02-02       normal     Firefox location.QueryInterface() Code Execution
   multi/browser/firefox_svg_plugin                               2013-01-08       excellent  Firefox 17.0.1 Flash Privileged Code Injection
   multi/browser/firefox_xpi_bootstrapped_addon                   2007-06-27       excellent  Mozilla Firefox Bootstrapped Addon Social Engineering Code Execution
   multi/browser/itms_overflow                                    2009-06-01       great      Apple OS X iTunes 8.1.1 ITMS Overflow
   multi/browser/java_atomicreferencearray                        2012-02-14       excellent  Java AtomicReferenceArray Type Violation Vulnerability
   multi/browser/java_calendar_deserialize                        2008-12-03       excellent  Sun Java Calendar Deserialization Privilege Escalation
   multi/browser/java_getsoundbank_bof                            2009-11-04       great      Sun Java JRE getSoundbank file:// URI Buffer Overflow
   multi/browser/java_jre17_driver_manager                        2013-01-10       excellent  Java Applet Driver Manager Privileged toString() Remote Code Execution
   multi/browser/java_jre17_exec                                  2012-08-26       excellent  Java 7 Applet Remote Code Execution
   multi/browser/java_jre17_glassfish_averagerangestatisticimpl   2012-10-16       excellent  Java Applet AverageRangeStatisticImpl Remote Code Execution
   multi/browser/java_jre17_jaxws                                 2012-10-16       excellent  Java Applet JAX-WS Remote Code Execution
   multi/browser/java_jre17_jmxbean                               2013-01-10       excellent  Java Applet JMX Remote Code Execution
   multi/browser/java_jre17_jmxbean_2                             2013-01-19       excellent  Java Applet JMX Remote Code Execution
   multi/browser/java_jre17_method_handle                         2012-10-16       excellent  Java Applet Method Handle Remote Code Execution
   multi/browser/java_jre17_provider_skeleton                     2013-06-18       great      Java Applet ProviderSkeleton Insecure Invoke Method
   multi/browser/java_jre17_reflection_types                      2013-01-10       excellent  Java Applet Reflection Type Confusion Remote Code Execution
   multi/browser/java_rhino                                       2011-10-18       excellent  Java Applet Rhino Script Engine Remote Code Execution
   multi/browser/java_rmi_connection_impl                         2010-03-31       excellent  Java RMIConnectionImpl Deserialization Privilege Escalation
   multi/browser/java_setdifficm_bof                              2009-11-04       great      Sun Java JRE AWT setDiffICM Buffer Overflow
   multi/browser/java_signed_applet                               1997-02-19       excellent  Java Signed Applet Social Engineering Code Execution
   multi/browser/java_trusted_chain                               2010-03-31       excellent  Java Statement.invoke() Trusted Method Chain Privilege Escalation
   multi/browser/java_verifier_field_access                       2012-06-06       excellent  Java Applet Field Bytecode Verifier Cache Remote Code Execution
   multi/browser/mozilla_compareto                                2005-07-13       normal     Mozilla Suite/Firefox InstallVersion->compareTo() Code Execution
   multi/browser/mozilla_navigatorjava                            2006-07-25       normal     Mozilla Suite/Firefox Navigator Object Code Execution
   multi/browser/opera_configoverwrite                            2007-03-05       excellent  Opera 9 Configuration Overwrite
   multi/browser/opera_historysearch                              2008-10-23       excellent  Opera historysearch XSS
   multi/browser/qtjava_pointer                                   2007-04-23       excellent  Apple QTJava toQTPointer() Arbitrary Memory Access
   multi/fileformat/adobe_u3d_meshcont                            2009-10-13       good       Adobe U3D CLODProgressiveMeshDeclaration Array Overrun
   multi/fileformat/maple_maplet                                  2010-04-26       excellent  Maple Maplet File Creation and Command Execution
   multi/fileformat/peazip_command_injection                      2009-06-05       excellent  PeaZip <= 2.6.1 Zip Processing Command Injection
   multi/ftp/wuftpd_site_exec_format                              2000-06-22       great      WU-FTPD SITE EXEC/INDEX Format String Vulnerability
   multi/handler                                                                   manual     Generic Payload Handler
   multi/http/activecollab_chat                                   2012-05-30       excellent  Active Collab "chat module" <= 2.3.8 Remote PHP Code Injection Exploit
   multi/http/ajaxplorer_checkinstall_exec                        2010-04-04       excellent  AjaXplorer checkInstall.php Remote Command Execution
   multi/http/apprain_upload_exec                                 2012-01-19       excellent  appRain CMF Arbitrary PHP File Upload Vulnerability
   multi/http/auxilium_upload_exec                                2012-09-14       excellent  Auxilium RateMyPet Arbitrary File Upload Vulnerability
   multi/http/axis2_deployer                                      2010-12-30       excellent  Axis2 / SAP BusinessObjects Authenticated Code Execution (via SOAP)
   multi/http/cuteflow_upload_exec                                2012-07-27       excellent  CuteFlow v2.11.2 Arbitrary File Upload Vulnerability
   multi/http/eaton_nsm_code_exec                                 2012-06-26       excellent  Network Shutdown Module (sort_values) Remote PHP Code Injection
   multi/http/extplorer_upload_exec                               2012-12-31       excellent  eXtplorer v2.1 Arbitrary File Upload Vulnerability
   multi/http/familycms_less_exec                                 2011-11-29       excellent  Family Connections less.php Remote Command Execution
   multi/http/freenas_exec_raw                                    2010-11-06       great      FreeNAS exec_raw.php Arbitrary Command Execution
   multi/http/gitorious_graph                                     2012-01-19       excellent  Gitorious Arbitrary Command Execution
   multi/http/glassfish_deployer                                  2011-08-04       excellent  Sun/Oracle GlassFish Server Authenticated Code Execution
   multi/http/glossword_upload_exec                               2013-02-05       excellent  Glossword v1.8.8 - 1.8.12 Arbitrary File Upload Vulnerability
   multi/http/horde_href_backdoor                                 2012-02-13       excellent  Horde 3.3.12 Backdoor Arbitrary PHP Code Execution
   multi/http/hp_sitescope_uploadfileshandler                     2012-08-29       good       HP SiteScope Remote Code Execution
   multi/http/jboss_bshdeployer                                   2010-04-26       excellent  JBoss JMX Console Beanshell Deployer WAR Upload and Deployment
   multi/http/jboss_deploymentfilerepository                      2010-04-26       excellent  JBoss Java Class DeploymentFileRepository WAR Deployment
   multi/http/jboss_invoke_deploy                                 2007-02-20       excellent  JBoss DeploymentFileRepository WAR Deployment (via JMXInvokerServlet)
   multi/http/jboss_maindeployer                                  2007-02-20       excellent  JBoss JMX Console Deployer Upload and Execute
   multi/http/jenkins_script_console                              2013-01-18       good       Jenkins Script-Console Java Execution
   multi/http/kordil_edms_upload_exec                             2013-02-22       excellent  Kordil EDMS v2.2.60rc3 Unauthenticated Arbitrary File Upload Vulnerability
   multi/http/lcms_php_exec                                       2011-03-03       excellent  LotusCMS 3.0 eval() Remote Command Execution
   multi/http/log1cms_ajax_create_folder                          2011-04-11       excellent  Log1 CMS writeInfo() PHP Code Injection
   multi/http/manageengine_search_sqli                            2012-10-18       excellent  ManageEngine Security Manager Plus 5.5 build 5505 SQL Injection
   multi/http/mobilecartly_upload_exec                            2012-08-10       excellent  MobileCartly 1.0 Arbitrary File Creation Vulnerability
   multi/http/movabletype_upgrade_exec                            2013-01-07       normal     Movable Type 4.2x, 4.3x Web Upgrade Remote Code Execution
   multi/http/mutiny_subnetmask_exec                              2012-10-22       excellent  Mutiny Remote Command Execution
   multi/http/netwin_surgeftp_exec                                2012-12-06       good       Netwin SurgeFTP Remote Command Execution
   multi/http/op5_license                                         2012-01-05       excellent  OP5 license.php Remote Command Execution
   multi/http/op5_welcome                                         2012-01-05       excellent  OP5 welcome Remote Command Execution
   multi/http/openfire_auth_bypass                                2008-11-10       excellent  Openfire Admin Console Authentication Bypass
   multi/http/php_cgi_arg_injection                               2012-05-03       excellent  PHP CGI Argument Injection
   multi/http/php_volunteer_upload_exec                           2012-05-28       excellent  PHP Volunteer Management System v1.0.2 Arbitrary File Upload Vulnerability
   multi/http/phpldapadmin_query_engine                           2011-10-24       excellent  phpLDAPadmin <= 1.2.1.1 (query_engine) Remote PHP Code Injection
   multi/http/phpmyadmin_3522_backdoor                            2012-09-25       normal     phpMyAdmin 3.5.2.2 server_sync.php Backdoor
   multi/http/phpmyadmin_preg_replace                             2013-04-25       excellent  phpMyAdmin Authenticated Remote Code Execution via preg_replace()
   multi/http/phpscheduleit_start_date                            2008-10-01       excellent  phpScheduleIt PHP reserve.php start_date Parameter Arbitrary Code Injection
   multi/http/phptax_exec                                         2012-10-08       excellent  PhpTax pfilez Parameter Exec Remote Code Injection
   multi/http/plone_popen2                                        2011-10-04       excellent  Plone and Zope XMLTools Remote Command Execution
   multi/http/pmwiki_pagelist                                     2011-11-09       excellent  PmWiki <= 2.2.34 pagelist.php Remote PHP Code Injection Exploit
   multi/http/polarcms_upload_exec                                2012-01-21       excellent  PolarBear CMS PHP File Upload Vulnerability
   multi/http/qdpm_upload_exec                                    2012-06-14       excellent  qdPM v7 Arbitrary PHP File Upload Vulnerability
   multi/http/rails_json_yaml_code_exec                           2013-01-28       excellent  Ruby on Rails JSON Processor YAML Deserialization Code Execution
   multi/http/rails_xml_yaml_code_exec                            2013-01-07       excellent  Ruby on Rails XML Processor YAML Deserialization Code Execution
   multi/http/sflog_upload_exec                                   2012-07-06       excellent  Sflog! CMS 1.0 Arbitrary File Upload Vulnerability
   multi/http/sit_file_upload                                     2011-11-10       excellent  Support Incident Tracker <= 3.65 Remote Command Execution
   multi/http/snortreport_exec                                    2011-09-19       excellent  Snortreport nmap.php/nbtscan.php Remote Command Execution
   multi/http/sonicwall_gms_upload                                2012-01-17       excellent  SonicWALL GMS 6 Arbitrary File Upload
   multi/http/splunk_mappy_exec                                   2011-12-12       excellent  Splunk Search Remote Code Execution
   multi/http/splunk_upload_app_exec                              2012-09-27       good       Splunk 5.0 Custom App Remote Code Execution
   multi/http/spree_search_exec                                   2011-10-05       excellent  Spreecommerce 0.60.1 Arbitrary Command Execution
   multi/http/spree_searchlogic_exec                              2011-04-19       excellent  Spreecommerce < 0.50.0 Arbitrary Command Execution
   multi/http/struts_code_exec                                    2010-07-13       good       Apache Struts < 2.2.0 Remote Command Execution
   multi/http/struts_code_exec_exception_delegator                2012-01-06       excellent  Apache Struts <= 2.2.1.1 Remote Command Execution
   multi/http/struts_code_exec_parameters                         2011-10-01       excellent  Apache Struts ParametersInterceptor Remote Code Execution
   multi/http/struts_include_params                               2013-05-24       great      Apache Struts includeParams Remote Code Execution
   multi/http/stunshell_eval                                      2013-03-23       great      STUNSHELL Web Shell Remote PHP Code Execution
   multi/http/stunshell_exec                                      2013-03-23       great      STUNSHELL Web Shell Remote Code Execution
   multi/http/sun_jsws_dav_options                                2010-01-20       great      Sun Java System Web Server WebDAV OPTIONS Buffer Overflow
   multi/http/testlink_upload_exec                                2012-08-13       excellent  TestLink v1.9.3 Arbitrary File Upload Vulnerability
   multi/http/tomcat_mgr_deploy                                   2009-11-09       excellent  Apache Tomcat Manager Application Deployer Authenticated Code Execution
   multi/http/traq_plugin_exec                                    2011-12-12       excellent  Traq admincp/common.php Remote Code Execution
   multi/http/v0pcr3w_exec                                        2013-03-23       great      v0pCr3w Web Shell Remote Code Execution
   multi/http/vbseo_proc_deutf                                    2012-01-23       excellent  vBSEO <= 3.6.0 proc_deutf() Remote PHP Code Injection
   multi/http/webpagetest_upload_exec                             2012-07-13       excellent  WebPageTest Arbitrary PHP File Upload
   multi/http/wikka_spam_exec                                     2011-11-30       excellent  WikkaWiki 1.3.2 Spam Logging PHP Injection
   multi/http/zenworks_control_center_upload                      2013-03-22       great      Novell ZENworks Configuration Management Remote Execution
   multi/ids/snort_dce_rpc                                        2007-02-19       good       Snort 2 DCE/RPC preprocessor Buffer Overflow
   multi/misc/batik_svg_java                                      2012-05-11       excellent  Squiggle 1.7 SVG Browser Java Code Execution
   multi/misc/hp_vsa_exec                                         2011-11-11       excellent  HP StorageWorks P4000 Virtual SAN Appliance Command Execution
   multi/misc/indesign_server_soap                                2012-11-11       excellent  Adobe IndesignServer 5.5 SOAP Server Arbitrary Script Execution
   multi/misc/java_rmi_server                                     2011-10-15       excellent  Java RMI Server Insecure Default Configuration Java Code Execution
   multi/misc/openview_omniback_exec                              2001-02-28       excellent  HP OpenView OmniBack II Command Execution
   multi/misc/pbot_exec                                           2009-11-02       excellent  PHP IRC Bot pbot eval() Remote Code Execution
   multi/misc/ra1nx_pubcall_exec                                  2013-03-24       great      Ra1NX PHP Bot PubCall Authentication Bypass Remote Code Execution
   multi/misc/veritas_netbackup_cmdexec                           2004-10-21       excellent  VERITAS NetBackup Remote Command Execution
   multi/misc/wireshark_lwres_getaddrbyname                       2010-01-27       great      Wireshark LWRES Dissector getaddrsbyname_request Buffer Overflow
   multi/misc/wireshark_lwres_getaddrbyname_loop                  2010-01-27       great      Wireshark LWRES Dissector getaddrsbyname_request Buffer Overflow (loop)
   multi/misc/zend_java_bridge                                    2011-03-28       great      Zend Server Java Bridge Arbitrary Java Code Execution
   multi/ntp/ntp_overflow                                         2001-04-04       good       NTP daemon readvar Buffer Overflow
   multi/php/php_unserialize_zval_cookie                          2007-03-04       average    PHP 4 unserialize() ZVAL Reference Counter Overflow (Cookie)
   multi/realserver/describe                                      2002-12-20       great      RealServer Describe Buffer Overflow
   multi/samba/nttrans                                            2003-04-07       average    Samba 2.2.2 - 2.2.6 nttrans Buffer Overflow
   multi/samba/usermap_script                                     2007-05-14       excellent  Samba "username map script" Command Execution
   multi/sap/sap_mgmt_con_osexec_payload                          2011-03-08       excellent  SAP Management Console OSExecute Payload Execution
   multi/sap/sap_soap_rfc_sxpg_call_system_exec                   2013-03-26       great      SAP SOAP RFC SXPG_CALL_SYSTEM Remote Command Execution
   multi/sap/sap_soap_rfc_sxpg_command_exec                       2012-05-08       great      SAP SOAP RFC SXPG_COMMAND_EXECUTE Remote Command Execution
   multi/ssh/sshexec                                              1999-01-01       manual     SSH User Code Execution
   multi/svn/svnserve_date                                        2004-05-19       average    Subversion Date Svnserve
   multi/upnp/libupnp_ssdp_overflow                               2013-01-29       normal     Portable UPnP SDK unique_service_name() Remote Code Execution
   multi/wyse/hagent_untrusted_hsdata                             2009-07-10       excellent  Wyse Rapport Hagent Fake Hserver Command Execution
   netware/smb/lsass_cifs                                         2007-01-21       average    Novell NetWare LSASS CIFS.NLM Driver Stack Buffer Overflow
   netware/sunrpc/pkernel_callit                                  2009-09-30       good       NetWare 6.5 SunRPC Portmapper CALLIT Stack Buffer Overflow
   osx/afp/loginext                                               2004-05-03       average    AppleFileServer LoginExt PathName Overflow
   osx/arkeia/type77                                              2005-02-18       average    Arkeia Backup Client Type 77 Overflow (Mac OS X)
   osx/browser/mozilla_mchannel                                   2011-05-10       normal     Mozilla Firefox 3.6.16 mChannel Use-After-Free
   osx/browser/safari_file_policy                                 2011-10-12       normal     Apple Safari file:// Arbitrary Code Execution
   osx/browser/safari_metadata_archive                            2006-02-21       excellent  Safari Archive Metadata Command Execution
   osx/browser/software_update                                    2007-12-17       excellent  Apple OS X Software Update Command Execution
   osx/email/mailapp_image_exec                                   2006-03-01       manual     Mail.app Image Attachment Command Execution
   osx/ftp/webstar_ftp_user                                       2004-07-13       average    WebSTAR FTP Server USER Overflow
   osx/http/evocam_webserver                                      2010-06-01       average    MacOS X EvoCam HTTP GET Buffer Overflow
   osx/local/setuid_tunnelblick                                   2012-08-11       excellent  Setuid Tunnelblick Privilege Escalation
   osx/local/setuid_viscosity                                     2012-08-12       excellent  Viscosity setuid-set ViscosityHelper Privilege Escalation
   osx/mdns/upnp_location                                         2007-05-25       average    Mac OS X mDNSResponder UPnP Location Overflow
   osx/misc/ufo_ai                                                2009-10-28       average    UFO: Alien Invasion IRC Client Buffer Overflow
   osx/rtsp/quicktime_rtsp_content_type                           2007-11-23       average    MacOS X QuickTime RTSP Content-Type Overflow
   osx/samba/lsa_transnames_heap                                  2007-05-14       average    Samba lsa_io_trans_names Heap Overflow
   osx/samba/trans2open                                           2003-04-07       great      Samba trans2open Overflow (Mac OS X PPC)
   solaris/dtspcd/heap_noir                                       2002-07-10       great      Solaris dtspcd Heap Overflow
   solaris/lpd/sendmail_exec                                      2001-08-31       excellent  Solaris LPD Command Execution
   solaris/samba/lsa_transnames_heap                              2007-05-14       average    Samba lsa_io_trans_names Heap Overflow
   solaris/samba/trans2open                                       2003-04-07       great      Samba trans2open Overflow (Solaris SPARC)
   solaris/sunrpc/sadmind_adm_build_path                          2008-10-14       great      Sun Solaris sadmind adm_build_path() Buffer Overflow
   solaris/sunrpc/sadmind_exec                                    2003-09-13       excellent  Solaris sadmind Command Execution
   solaris/sunrpc/ypupdated_exec                                  1994-12-12       excellent  Solaris ypupdated Command Execution
   solaris/telnet/fuser                                           2007-02-12       excellent  Sun Solaris Telnet Remote Authentication Bypass Vulnerability
   solaris/telnet/ttyprompt                                       2002-01-18       excellent  Solaris in.telnetd TTYPROMPT Buffer Overflow
   unix/ftp/proftpd_133c_backdoor                                 2010-12-02       excellent  ProFTPD-1.3.3c Backdoor Command Execution
   unix/ftp/vsftpd_234_backdoor                                   2011-07-03       excellent  VSFTPD v2.3.4 Backdoor Command Execution
   unix/http/contentkeeperweb_mimencode                           2009-02-25       excellent  ContentKeeper Web Remote Command Execution
   unix/http/ctek_skyrouter                                       2011-09-08       average    CTEK SkyRouter 4200 and 4300 Command Execution
   unix/http/freepbx_callmenum                                    2012-03-20       manual     FreePBX 2.10.0 / 2.9.0 callmenum Remote Code Execution
   unix/http/lifesize_room                                        2011-07-13       excellent  LifeSize Room Command Injection
   unix/irc/unreal_ircd_3281_backdoor                             2010-06-12       excellent  UnrealIRCD 3.2.8.1 Backdoor Command Execution
   unix/local/setuid_nmap                                         2012-07-19       excellent  Setuid Nmap Exploit
   unix/misc/distcc_exec                                          2002-02-01       excellent  DistCC Daemon Command Execution
   unix/misc/qnx_qconn_exec                                       2012-09-04       excellent  QNX QCONN Remote Command Execution Vulnerability
   unix/misc/spamassassin_exec                                    2006-06-06       excellent  SpamAssassin spamd Remote Command Execution
   unix/misc/zabbix_agent_exec                                    2009-09-10       excellent  Zabbix Agent net.tcp.listen Command Injection
   unix/smtp/clamav_milter_blackhole                              2007-08-24       excellent  ClamAV Milter Blackhole-Mode Remote Code Execution
   unix/smtp/exim4_string_format                                  2010-12-07       excellent  Exim4 <= 4.69 string_format Function Heap Buffer Overflow
   unix/ssh/tectia_passwd_changereq                               2012-12-01       excellent  Tectia SSH USERAUTH Change Request Password Reset Vulnerability
   unix/webapp/awstats_configdir_exec                             2005-01-15       excellent  AWStats configdir Remote Command Execution
   unix/webapp/awstats_migrate_exec                               2006-05-04       excellent  AWStats migrate Remote Command Execution
   unix/webapp/awstatstotals_multisort                            2008-08-26       excellent  AWStats Totals =< v1.14 multisort Remote Command Execution
   unix/webapp/barracuda_img_exec                                 2005-09-01       excellent  Barracuda IMG.PL Remote Command Execution
   unix/webapp/base_qry_common                                    2008-06-14       excellent  BASE base_qry_common Remote File Include
   unix/webapp/basilic_diff_exec                                  2012-06-28       excellent  Basilic 1.5.14 diff.php Arbitrary Command Execution
   unix/webapp/cacti_graphimage_exec                              2005-01-15       excellent  Cacti graph_view.php Remote Command Execution
   unix/webapp/cakephp_cache_corruption                           2010-11-15       excellent  CakePHP <= 1.3.5 / 1.2.8 Cache Corruption Code Execution
   unix/webapp/carberp_backdoor_exec                              2013-06-28       great      Carberp Web Panel C2 Backdoor Remote PHP Code Execution
   unix/webapp/citrix_access_gateway_exec                         2010-12-21       excellent  Citrix Access Gateway Command Execution
   unix/webapp/coppermine_piceditor                               2008-01-30       excellent  Coppermine Photo Gallery <= 1.4.14 picEditor.php Command Execution
   unix/webapp/datalife_preview_exec                              2013-01-28       excellent  DataLife Engine preview.php PHP Code Injection
   unix/webapp/dogfood_spell_exec                                 2009-03-03       excellent  Dogfood CRM spell.php Remote Command Execution
   unix/webapp/egallery_upload_exec                               2012-07-08       excellent  EGallery PHP File Upload Vulnerability
   unix/webapp/foswiki_maketext                                   2012-12-03       excellent  Foswiki MAKETEXT Remote Command Execution
   unix/webapp/generic_exec                                       1993-11-14       excellent  Generic Web Application Unix Command Execution
   unix/webapp/google_proxystylesheet_exec                        2005-08-16       excellent  Google Appliance ProxyStyleSheet Command Execution
   unix/webapp/guestbook_ssi_exec                                 1999-11-05       excellent  Matt Wright guestbook.pl Arbitrary Command Execution
   unix/webapp/hastymail_exec                                     2011-11-22       excellent  Hastymail 2.1.1 RC1 Command Injection
   unix/webapp/havalite_upload_exec                               2013-06-17       excellent  Havalite CMS Arbitary File Upload Vulnerability
   unix/webapp/instantcms_exec                                    2013-06-26       excellent  InstantCMS 1.6 Remote PHP Code Execution
   unix/webapp/invision_pboard_unserialize_exec                   2012-10-25       excellent  Invision IP.Board unserialize() PHP Code Execution
   unix/webapp/joomla_comjce_imgmanager                           2012-08-02       excellent  Joomla Component JCE File Upload Remote Code Execution
   unix/webapp/joomla_tinybrowser                                 2009-07-22       excellent  Joomla 1.5.12 TinyBrowser File Upload Code Execution
   unix/webapp/libretto_upload_exec                               2013-06-14       excellent  LibrettoCMS File Manager Arbitary File Upload Vulnerability
   unix/webapp/mambo_cache_lite                                   2008-06-14       excellent  Mambo Cache_Lite Class mosConfig_absolute_path Remote File Include
   unix/webapp/mitel_awc_exec                                     2010-12-12       excellent  Mitel Audio and Web Conferencing Command Injection
   unix/webapp/moinmoin_twikidraw                                 2012-12-30       manual     MoinMoin twikidraw Action Traversal File Upload
   unix/webapp/mybb_backdoor                                      2011-10-06       excellent  myBB 1.6.4 Backdoor Arbitrary Command Execution
   unix/webapp/nagios3_history_cgi                                2012-12-09       great      Nagios3 history.cgi Host Command Execution
   unix/webapp/nagios3_statuswml_ping                             2009-06-22       excellent  Nagios3 statuswml.cgi Ping Command Execution
   unix/webapp/nagios_graph_explorer                              2012-11-30       excellent  Nagios XI Network Monitor Graph Explorer Component Command Injection
   unix/webapp/narcissus_backend_exec                             2012-11-14       excellent  Narcissus Image Configuration Passthru Vulnerability
   unix/webapp/openemr_upload_exec                                2013-02-13       excellent  OpenEMR PHP File Upload Vulnerability
   unix/webapp/openview_connectednodes_exec                       2005-08-25       excellent  HP Openview connectedNodes.ovpl Remote Command Execution
   unix/webapp/openx_banner_edit                                  2009-11-24       excellent  OpenX banner-edit.php File Upload PHP Code Execution
   unix/webapp/oracle_vm_agent_utl                                2010-10-12       excellent  Oracle VM Server Virtual Server Agent Command Injection
   unix/webapp/oscommerce_filemanager                             2009-08-31       excellent  osCommerce 2.2 Arbitrary PHP Code Execution
   unix/webapp/pajax_remote_exec                                  2006-03-30       excellent  PAJAX Remote Command Execution
   unix/webapp/php_charts_exec                                    2013-01-16       excellent  PHP-Charts v1.0 PHP Code Execution Vulnerability
   unix/webapp/php_eval                                           2008-10-13       manual     Generic PHP Code Evaluation
   unix/webapp/php_include                                        2006-12-17       normal     PHP Remote File Include Generic Code Execution
   unix/webapp/php_vbulletin_template                             2005-02-25       excellent  vBulletin misc.php Template Name Arbitrary Code Execution
   unix/webapp/php_wordpress_foxypress                            2012-06-05       excellent  WordPress plugin Foxypress uploadify.php Arbitrary Code Execution
   unix/webapp/php_wordpress_lastpost                             2005-08-09       excellent  WordPress cache_lastpostdate Arbitrary Code Execution
   unix/webapp/php_wordpress_total_cache                          2013-04-17       excellent  Wordpress W3 Total Cache PHP Code Execution
   unix/webapp/php_xmlrpc_eval                                    2005-06-29       excellent  PHP XML-RPC Arbitrary Code Execution
   unix/webapp/phpbb_highlight                                    2004-11-12       excellent  phpBB viewtopic.php Arbitrary Code Execution
   unix/webapp/phpmyadmin_config                                  2009-03-24       excellent  PhpMyAdmin Config File Code Injection
   unix/webapp/projectpier_upload_exec                            2012-10-08       excellent  Project Pier Arbitrary File Upload Vulnerability
   unix/webapp/qtss_parse_xml_exec                                2003-02-24       excellent  QuickTime Streaming Server parse_xml.cgi Remote Execution
   unix/webapp/redmine_scm_exec                                   2010-12-19       excellent  Redmine SCM Repository Arbitrary Command Execution
   unix/webapp/sphpblog_file_upload                               2005-08-25       excellent  Simple PHP Blog <= 0.4.0 Remote Command Execution
   unix/webapp/squirrelmail_pgp_plugin                            2007-07-09       manual     SquirrelMail PGP Plugin command execution (SMTP)
   unix/webapp/sugarcrm_unserialize_exec                          2012-06-23       excellent  SugarCRM <= 6.3.1 unserialize() PHP Code Execution
   unix/webapp/tikiwiki_graph_formula_exec                        2007-10-10       excellent  TikiWiki tiki-graph_formula Remote PHP Code Execution
   unix/webapp/tikiwiki_jhot_exec                                 2006-09-02       excellent  TikiWiki jhot Remote Command Execution
   unix/webapp/tikiwiki_unserialize_exec                          2012-07-04       excellent  Tiki Wiki <= 8.3 unserialize() PHP Code Execution
   unix/webapp/trixbox_langchoice                                 2008-07-09       manual     Trixbox langChoice PHP Local File Inclusion
   unix/webapp/twiki_history                                      2005-09-14       excellent  TWiki History TWikiUsers rev Parameter Command Execution
   unix/webapp/twiki_maketext                                     2012-12-15       excellent  TWiki MAKETEXT Remote Command Execution
   unix/webapp/twiki_search                                       2004-10-01       excellent  TWiki Search Function Arbitrary Command Execution
   unix/webapp/webmin_show_cgi_exec                               2012-09-06       excellent  Webmin /file/show.cgi Remote Command Execution
   unix/webapp/wp_advanced_custom_fields_exec                     2012-11-14       excellent  WordPress Plugin Advanced Custom Fields Remote File Inclusion
   unix/webapp/wp_asset_manager_upload_exec                       2012-05-26       excellent  WordPress Asset-Manager PHP File Upload Vulnerability
   unix/webapp/wp_google_document_embedder_exec                   2013-01-03       normal     WordPress Plugin Google Document Embedder Arbitrary File Disclosure
   unix/webapp/wp_property_upload_exec                            2012-03-26       excellent  WordPress WP-Property PHP File Upload Vulnerability
   unix/webapp/xoda_file_upload                                   2012-08-21       excellent  XODA 0.4.5 Arbitrary PHP File Upload Vulnerability
   unix/webapp/zoneminder_packagecontrol_exec                     2013-01-22       excellent  ZoneMinder Video Server packageControl Command Execution
   unix/webapp/zpanel_username_exec                               2013-06-07       excellent  ZPanel 10.0.0.2 htpasswd Module Username Command Execution
   windows/antivirus/ams_hndlrsvc                                 2010-07-26       excellent  Symantec System Center Alert Management System (hndlrsvc.exe) Arbitrary Command Execution
   windows/antivirus/ams_xfr                                      2009-04-28       excellent  Symantec System Center Alert Management System (xfr.exe) Arbitrary Command Execution
   windows/antivirus/symantec_iao                                 2009-04-28       good       Symantec Alert Management System Intel Alert Originator Service Buffer Overflow
   windows/antivirus/symantec_rtvscan                             2006-05-24       good       Symantec Remote Management Buffer Overflow
   windows/antivirus/trendmicro_serverprotect                     2007-02-20       good       Trend Micro ServerProtect 5.58 Buffer Overflow
   windows/antivirus/trendmicro_serverprotect_createbinding       2007-05-07       good       Trend Micro ServerProtect 5.58 CreateBinding() Buffer Overflow
   windows/antivirus/trendmicro_serverprotect_earthagent          2007-05-07       good       Trend Micro ServerProtect 5.58 EarthAgent.EXE Buffer Overflow
   windows/arkeia/type77                                          2005-02-18       good       Arkeia Backup Client Type 77 Overflow (Win32)
   windows/backdoor/energizer_duo_payload                         2010-03-05       excellent  Energizer DUO Trojan Code Execution
   windows/backupexec/name_service                                2004-12-16       average    Veritas Backup Exec Name Service Overflow
   windows/backupexec/remote_agent                                2005-06-22       great      Veritas Backup Exec Windows Remote Agent Overflow
   windows/brightstor/ca_arcserve_342                             2008-10-09       average    Computer Associates ARCserve REPORTREMOTEEXECUTECML Buffer Overflow
   windows/brightstor/discovery_tcp                               2005-02-14       average    CA BrightStor Discovery Service TCP Overflow
   windows/brightstor/discovery_udp                               2004-12-20       average    CA BrightStor Discovery Service Stack Buffer Overflow
   windows/brightstor/etrust_itm_alert                            2008-04-04       average    Computer Associates Alert Notification Buffer Overflow
   windows/brightstor/hsmserver                                   2007-09-27       great      CA BrightStor HSM Buffer Overflow
   windows/brightstor/lgserver                                    2007-01-31       average    CA BrightStor ARCserve for Laptops & Desktops LGServer Buffer Overflow
   windows/brightstor/lgserver_multi                              2007-06-06       average    CA BrightStor ARCserve for Laptops & Desktops LGServer Multiple Commands Buffer Overflow
   windows/brightstor/lgserver_rxrlogin                           2007-06-06       average    CA BrightStor ARCserve for Laptops & Desktops LGServer Buffer Overflow
   windows/brightstor/lgserver_rxssetdatagrowthscheduleandfilter  2007-06-06       average    CA BrightStor ARCserve for Laptops & Desktops LGServer (rxsSetDataGrowthScheduleAndFilter) Buffer Overflow
   windows/brightstor/lgserver_rxsuselicenseini                   2007-06-06       average    CA BrightStor ARCserve for Laptops & Desktops LGServer Buffer Overflow
   windows/brightstor/license_gcr                                 2005-03-02       average    CA BrightStor ARCserve License Service GCR NETWORK Buffer Overflow
   windows/brightstor/mediasrv_sunrpc                             2007-04-25       average    CA BrightStor ArcServe Media Service Stack Buffer Overflow
   windows/brightstor/message_engine                              2007-01-11       average    CA BrightStor ARCserve Message Engine Buffer Overflow
   windows/brightstor/message_engine_72                           2010-10-04       average    CA BrightStor ARCserve Message Engine 0x72 Buffer Overflow
   windows/brightstor/message_engine_heap                         2006-10-05       average    CA BrightStor ARCserve Message Engine Heap Overflow
   windows/brightstor/sql_agent                                   2005-08-02       average    CA BrightStor Agent for Microsoft SQL Overflow
   windows/brightstor/tape_engine                                 2006-11-21       average    CA BrightStor ARCserve Tape Engine Buffer Overflow
   windows/brightstor/tape_engine_8A                              2010-10-04       average    CA BrightStor ARCserve Tape Engine 0x8A Buffer Overflow
   windows/brightstor/universal_agent                             2005-04-11       average    CA BrightStor Universal Agent Overflow
   windows/browser/adobe_cooltype_sing                            2010-09-07       great      Adobe CoolType SING Table "uniqueName" Stack Buffer Overflow
   windows/browser/adobe_flash_mp4_cprt                           2012-02-15       normal     Adobe Flash Player MP4 'cprt' Overflow
   windows/browser/adobe_flash_otf_font                           2012-08-09       normal     Adobe Flash Player 11.3 Kern Table Parsing Integer Overflow
   windows/browser/adobe_flash_rtmp                               2012-05-04       normal     Adobe Flash Player Object Type Confusion
   windows/browser/adobe_flash_sps                                2011-08-09       normal     Adobe Flash Player MP4 SequenceParameterSetNALUnit Buffer Overflow
   windows/browser/adobe_flashplayer_arrayindexing                2012-06-21       great      Adobe Flash Player AVM Verification Logic Array Indexing Code Execution
   windows/browser/adobe_flashplayer_avm                          2011-03-15       good       Adobe Flash Player AVM Bytecode Verification Vulnerability
   windows/browser/adobe_flashplayer_flash10o                     2011-04-11       normal     Adobe Flash Player 10.2.153.1 SWF Memory Corruption Vulnerability
   windows/browser/adobe_flashplayer_newfunction                  2010-06-04       normal     Adobe Flash Player "newfunction" Invalid Pointer Use
   windows/browser/adobe_flatedecode_predictor02                  2009-10-08       good       Adobe FlateDecode Stream Predictor 02 Integer Overflow
   windows/browser/adobe_geticon                                  2009-03-24       good       Adobe Collab.getIcon() Buffer Overflow
   windows/browser/adobe_jbig2decode                              2009-02-19       good       Adobe JBIG2Decode Heap Corruption
   windows/browser/adobe_media_newplayer                          2009-12-14       good       Adobe Doc.media.newPlayer Use After Free Vulnerability
   windows/browser/adobe_shockwave_rcsl_corruption                2010-10-21       normal     Adobe Shockwave rcsL Memory Corruption
   windows/browser/adobe_utilprintf                               2008-02-08       good       Adobe util.printf() Buffer Overflow
   windows/browser/aim_goaway                                     2004-08-09       great      AOL Instant Messenger goaway Overflow
   windows/browser/aladdin_choosefilepath_bof                     2012-04-01       normal     Aladdin Knowledge System Ltd ChooseFilePath Buffer Overflow
   windows/browser/amaya_bdo                                      2009-01-28       normal     Amaya Browser v11.0 'bdo' Tag Overflow
   windows/browser/aol_ampx_convertfile                           2009-05-19       normal     AOL Radio AmpX ActiveX Control ConvertFile() Buffer Overflow
   windows/browser/aol_icq_downloadagent                          2006-11-06       excellent  America Online ICQ ActiveX Control Arbitrary File Download and Execute
   windows/browser/apple_itunes_playlist                          2005-01-11       normal     Apple ITunes 4.7 Playlist Buffer Overflow
   windows/browser/apple_quicktime_marshaled_punk                 2010-08-30       great      Apple QuickTime 7.6.7 _Marshaled_pUnk Code Execution
   windows/browser/apple_quicktime_mime_type                      2012-11-07       normal     Apple QuickTime 7.7.2 MIME Type Buffer Overflow
   windows/browser/apple_quicktime_rtsp                           2007-01-01       normal     Apple QuickTime 7.1.3 RTSP URI Buffer Overflow
   windows/browser/apple_quicktime_smil_debug                     2010-08-12       good       Apple QuickTime 7.6.6 Invalid SMIL URI Buffer Overflow
   windows/browser/apple_quicktime_texml_font_table               2012-11-07       normal     Apple QuickTime 7.7.2 TeXML Style Element font-table Field Stack Buffer Overflow
   windows/browser/ask_shortformat                                2007-09-24       normal     Ask.com Toolbar askBar.dll ActiveX Control Buffer Overflow
   windows/browser/asus_net4switch_ipswcom                        2012-02-17       normal     ASUS Net4Switch ipswcom.dll ActiveX Stack Buffer Overflow
   windows/browser/athocgov_completeinstallation                  2008-02-15       normal     AtHocGov IWSAlerts ActiveX Control Buffer Overflow
   windows/browser/autodesk_idrop                                 2009-04-02       normal     Autodesk IDrop ActiveX Control Heap Memory Corruption
   windows/browser/aventail_epi_activex                           2010-08-19       normal     SonicWALL Aventail epi.dll AuthCredential Format String
   windows/browser/awingsoft_web3d_bof                            2009-07-10       average    AwingSoft Winds3D Player SceneURL Buffer Overflow
   windows/browser/awingsoft_winds3d_sceneurl                     2009-11-14       excellent  AwingSoft Winds3D Player 3.5 SceneURL Download and Execute
   windows/browser/baofeng_storm_onbeforevideodownload            2009-04-30       normal     BaoFeng Storm mps.dll ActiveX OnBeforeVideoDownload Buffer Overflow
   windows/browser/barcode_ax49                                   2007-06-22       normal     RKD Software BarCodeAx.dll v4.9 ActiveX Remote Stack Buffer Overflow
   windows/browser/blackice_downloadimagefileurl                  2008-06-05       excellent  Black Ice Cover Page ActiveX Control Arbitrary File Download
   windows/browser/c6_messenger_downloaderactivex                 2008-06-03       excellent  Icona SpA C6 Messenger DownloaderActiveX Control Arbitrary File Download and Execute
   windows/browser/ca_brightstor_addcolumn                        2008-03-16       normal     CA BrightStor ARCserve Backup AddColumn() ActiveX Buffer Overflow
   windows/browser/chilkat_crypt_writefile                        2008-11-03       excellent  Chilkat Crypt ActiveX WriteFile Unsafe Method
   windows/browser/cisco_anyconnect_exec                          2011-06-01       excellent  Cisco AnyConnect VPN Client ActiveX URL Property Download and Execute
   windows/browser/cisco_playerpt_setsource                       2012-03-22       normal     Cisco Linksys PlayerPT ActiveX Control Buffer Overflow
   windows/browser/cisco_playerpt_setsource_surl                  2012-07-17       normal     Cisco Linksys PlayerPT ActiveX Control SetSource sURL argument Buffer Overflow
   windows/browser/citrix_gateway_actx                            2011-07-14       normal     Citrix Gateway ActiveX Control Stack Based Buffer Overflow Vulnerability
   windows/browser/clear_quest_cqole                              2012-05-19       normal     IBM Rational ClearQuest CQOle Remote Code Execution
   windows/browser/communicrypt_mail_activex                      2010-05-19       great      CommuniCrypt Mail 1.16 SMTP ActiveX Stack Buffer Overflow
   windows/browser/creative_software_cachefolder                  2008-05-28       normal     Creative Software AutoUpdate Engine ActiveX Control Buffer Overflow
   windows/browser/crystal_reports_printcontrol                   2010-12-14       normal     Crystal Reports CrystalPrintControl ActiveX ServerResourceVersion Property Overflow
   windows/browser/dell_webcam_crazytalk                          2012-03-19       normal     Dell Webcam CrazyTalk ActiveX BackImage Vulnerability
   windows/browser/dxstudio_player_exec                           2009-06-09       excellent  Worldweaver DX Studio Player <= 3.0.29 shell.execute() Command Execution
   windows/browser/ea_checkrequirements                           2007-10-08       normal     Electronic Arts SnoopyCtrl ActiveX Control Buffer Overflow
   windows/browser/ebook_flipviewer_fviewerloading                2007-06-06       normal     FlipViewer FViewerLoading ActiveX Control Buffer Overflow
   windows/browser/enjoysapgui_comp_download                      2009-04-15       excellent  EnjoySAP SAP GUI ActiveX Control Arbitrary File Download
   windows/browser/enjoysapgui_preparetoposthtml                  2007-07-05       normal     EnjoySAP SAP GUI ActiveX Control Buffer Overflow
   windows/browser/facebook_extractiptc                           2008-01-31       normal     Facebook Photo Uploader 4 ActiveX Control Buffer Overflow
   windows/browser/foxit_reader_plugin_url_bof                    2013-01-07       normal     Foxit Reader Plugin URL Processing Buffer Overflow
   windows/browser/gom_openurl                                    2007-10-27       normal     GOM Player ActiveX Control Buffer Overflow
   windows/browser/greendam_url                                   2009-06-11       normal     Green Dam URL Processing Buffer Overflow
   windows/browser/honeywell_hscremotedeploy_exec                 2013-02-22       excellent  Honeywell HSC Remote Deployer ActiveX Remote Code Execution
   windows/browser/honeywell_tema_exec                            2011-10-20       excellent  Honeywell Tema Remote Installer ActiveX Remote Code Execution
   windows/browser/hp_alm_xgo_setshapenodetype_exec               2012-08-29       normal     HP Application Lifecycle Management XGO.ocx ActiveX SetShapeNodeType() Remote Code Execution
   windows/browser/hp_easy_printer_care_xmlcachemgr               2012-01-11       great      HP Easy Printer Care XMLCacheMgr Class ActiveX Control Remote Code Execution
   windows/browser/hp_easy_printer_care_xmlsimpleaccessor         2011-08-16       great      HP Easy Printer Care XMLSimpleAccessor Class ActiveX Control Remote Code Execution
   windows/browser/hp_loadrunner_addfile                          2008-01-25       normal     Persits XUpload ActiveX AddFile Buffer Overflow
   windows/browser/hp_loadrunner_addfolder                        2007-12-25       good       HP LoadRunner 9.0 ActiveX AddFolder Buffer Overflow
   windows/browser/hpmqc_progcolor                                2007-04-04       normal     HP Mercury Quality Center ActiveX Control ProgColor Buffer Overflow
   windows/browser/hyleos_chemviewx_activex                       2010-02-10       good       Hyleos ChemView ActiveX Control Stack Buffer Overflow
   windows/browser/ibm_spss_c1sizer                               2013-04-26       normal     IBM SPSS SamplePower C1Tab ActiveX Heap Overflow
   windows/browser/ibm_tivoli_pme_activex_bof                     2012-03-01       normal     IBM Tivoli Provisioning Manager Express for Software Distribution Isig.isigCtl.1 ActiveX RunAndUploadFile() Method Overflow
   windows/browser/ibmegath_getxmlvalue                           2009-03-24       normal     IBM Access Support ActiveX Control Buffer Overflow
   windows/browser/ibmlotusdomino_dwa_uploadmodule                2007-12-20       normal     IBM Lotus Domino Web Access Upload Module Buffer Overflow
   windows/browser/ie_cbutton_uaf                                 2012-12-27       normal     Microsoft Internet Explorer CButton Object Use-After-Free Vulnerability
   windows/browser/ie_cgenericelement_uaf                         2013-05-03       good       MS13-038 Microsoft Internet Explorer CGenericElement Object Use-After-Free Vulnerability
   windows/browser/ie_createobject                                2006-04-11       excellent  Internet Explorer COM CreateObject Code Execution
   windows/browser/ie_execcommand_uaf                             2012-09-14       good       MS12-063 Microsoft Internet Explorer execCommand Use-After-Free Vulnerability 
   windows/browser/ie_iscomponentinstalled                        2006-02-24       normal     Internet Explorer isComponentInstalled Overflow
   windows/browser/ie_unsafe_scripting                            2010-09-20       excellent  Internet Explorer Unsafe Scripting Misconfiguration
   windows/browser/imgeviewer_tifmergemultifiles                  2010-03-03       normal     Viscom Image Viewer CP Pro 8.0/Gold 6.0 ActiveX Control
   windows/browser/indusoft_issymbol_internationalseparator       2012-04-28       normal     InduSoft Web Studio ISSymbol.ocx InternationalSeparator() Heap Overflow
   windows/browser/inotes_dwa85w_bof                              2012-06-01       normal     IBM Lotus iNotes dwa85W ActiveX Buffer Overflow
   windows/browser/intrust_annotatex_add                          2012-03-28       average    Quest InTrust Annotation Objects Uninitialized Pointer
   windows/browser/java_basicservice_impl                         2010-10-12       excellent  Sun Java Web Start BasicServiceImpl Code Execution
   windows/browser/java_cmm                                       2013-03-01       normal     Java CMM Remote Code Execution
   windows/browser/java_codebase_trust                            2011-02-15       excellent  Sun Java Applet2ClassLoader Remote Code Execution
   windows/browser/java_docbase_bof                               2010-10-12       great      Sun Java Runtime New Plugin docbase Buffer Overflow
   windows/browser/java_mixer_sequencer                           2010-03-30       great      Java MixerSequencer Object GM_Song Structure Handling Vulnerability
   windows/browser/java_ws_arginject_altjvm                       2010-04-09       excellent  Sun Java Web Start Plugin Command Line Argument Injection
   windows/browser/java_ws_double_quote                           2012-10-16       excellent  Sun Java Web Start Double Quote Injection
   windows/browser/java_ws_vmargs                                 2012-02-14       excellent  Sun Java Web Start Plugin Command Line Argument Injection
   windows/browser/juniper_sslvpn_ive_setupdll                    2006-04-26       normal     Juniper SSL-VPN IVE JuniperSetupDLL.dll ActiveX Control Buffer Overflow
   windows/browser/kazaa_altnet_heap                              2007-10-03       normal     Kazaa Altnet Download Manager ActiveX Control Buffer Overflow
   windows/browser/keyhelp_launchtripane_exec                     2012-06-26       excellent  KeyHelp ActiveX LaunchTriPane Remote Code Execution Vulnerability
   windows/browser/logitechvideocall_start                        2007-05-31       normal     Logitech VideoCall ActiveX Control Buffer Overflow
   windows/browser/lpviewer_url                                   2008-10-06       normal     iseemedia / Roxio / MGI Software LPViewer ActiveX Control Buffer Overflow
   windows/browser/macrovision_downloadandexecute                 2007-10-31       normal     Macrovision InstallShield Update Service Buffer Overflow
   windows/browser/macrovision_unsafe                             2007-10-20       excellent  Macrovision InstallShield Update Service ActiveX Unsafe Method
   windows/browser/maxthon_history_xcs                            2012-11-26       excellent  Maxthon3 about:history XCS Trusted Zone Code Execution
   windows/browser/mcafee_mcsubmgr_vsprintf                       2006-08-01       normal     McAfee Subscription Manager Stack Buffer Overflow
   windows/browser/mcafee_mvt_exec                                2012-04-30       excellent  McAfee Virtual Technician MVTControl 6.3.0.1911 GetObject Vulnerability
   windows/browser/mcafeevisualtrace_tracetarget                  2007-07-07       normal     McAfee Visual Trace ActiveX Control Buffer Overflow
   windows/browser/mirc_irc_url                                   2003-10-13       normal     mIRC IRC URL Buffer Overflow
   windows/browser/mozilla_attribchildremoved                     2011-12-06       average    Firefox 8/9 AttributeChildRemoved() Use-After-Free
   windows/browser/mozilla_interleaved_write                      2010-10-25       normal     Mozilla Firefox Interleaved document.write/appendChild Memory Corruption
   windows/browser/mozilla_mchannel                               2011-05-10       normal     Mozilla Firefox 3.6.16 mChannel Use-After-Free Vulnerability
   windows/browser/mozilla_nssvgvalue                             2011-12-06       average    Firefox 7/8 (<= 8.0.1) nsSVGValue Out-of-Bounds Access Vulnerability
   windows/browser/mozilla_nstreerange                            2011-02-02       normal     Mozilla Firefox "nsTreeRange" Dangling Pointer Vulnerability
   windows/browser/mozilla_reduceright                            2011-06-21       normal     Mozilla Firefox Array.reduceRight() Integer Overflow
   windows/browser/ms03_020_ie_objecttype                         2003-06-04       normal     MS03-020 Internet Explorer Object Type
   windows/browser/ms05_054_onload                                2005-11-21       normal     MS05-054 Microsoft Internet Explorer JavaScript OnLoad Handler Remote Code Execution
   windows/browser/ms06_001_wmf_setabortproc                      2005-12-27       great      Windows XP/2003/Vista Metafile Escape() SetAbortProc Code Execution
   windows/browser/ms06_013_createtextrange                       2006-03-19       normal     Internet Explorer createTextRange() Code Execution
   windows/browser/ms06_055_vml_method                            2006-09-19       normal     Internet Explorer VML Fill Method Code Execution
   windows/browser/ms06_057_webview_setslice                      2006-07-17       normal     Internet Explorer WebViewFolderIcon setSlice() Overflow
   windows/browser/ms06_067_keyframe                              2006-11-14       normal     Internet Explorer Daxctle.OCX KeyFrame Method Heap Buffer Overflow Vulnerability
   windows/browser/ms06_071_xml_core                              2006-10-10       normal     Internet Explorer XML Core Services HTTP Request Handling
   windows/browser/ms07_017_ani_loadimage_chunksize               2007-03-28       great      Windows ANI LoadAniIcon() Chunk Size Stack Buffer Overflow (HTTP)
   windows/browser/ms08_041_snapshotviewer                        2008-07-07       excellent  Snapshot Viewer for Microsoft Access ActiveX Control Arbitrary File Download
   windows/browser/ms08_053_mediaencoder                          2008-09-09       normal     Windows Media Encoder 9 wmex.dll ActiveX Buffer Overflow
   windows/browser/ms08_070_visual_studio_msmask                  2008-08-13       normal     Microsoft Visual Studio Mdmask32.ocx ActiveX Buffer Overflow
   windows/browser/ms08_078_xml_corruption                        2008-12-07       normal     Internet Explorer Data Binding Memory Corruption
   windows/browser/ms09_002_memory_corruption                     2009-02-10       normal     Internet Explorer 7 CFunctionPointer Uninitialized Memory Corruption
   windows/browser/ms09_043_owc_htmlurl                           2009-08-11       normal     Microsoft OWC Spreadsheet HTMLURL Buffer Overflow
   windows/browser/ms09_043_owc_msdso                             2009-07-13       normal     Microsoft OWC Spreadsheet msDataSourceObject Memory Corruption
   windows/browser/ms09_072_style_object                          2009-11-20       normal     Internet Explorer Style getElementsByTagName Memory Corruption
   windows/browser/ms10_002_aurora                                2010-01-14       normal     Internet Explorer "Aurora" Memory Corruption
   windows/browser/ms10_002_ie_object                             2010-01-21       normal     MS10-002 Internet Explorer Object Memory Use-After-Free
   windows/browser/ms10_018_ie_behaviors                          2010-03-09       good       Internet Explorer DHTML Behaviors Use After Free
   windows/browser/ms10_018_ie_tabular_activex                    2010-03-09       good       Internet Explorer Tabular Data Control ActiveX Memory Corruption
   windows/browser/ms10_022_ie_vbscript_winhlp32                  2010-02-26       great      Internet Explorer Winhlp32.exe MsgBox Code Execution
   windows/browser/ms10_026_avi_nsamplespersec                    2010-04-13       normal     MS10-026 Microsoft MPEG Layer-3 Audio Stack Based Overflow
   windows/browser/ms10_042_helpctr_xss_cmd_exec                  2010-06-09       excellent  Microsoft Help Center XSS and Command Execution
   windows/browser/ms10_046_shortcut_icon_dllloader               2010-07-16       excellent  Microsoft Windows Shell LNK Code Execution
   windows/browser/ms10_090_ie_css_clip                           2010-11-03       good       Internet Explorer CSS SetUserClip Memory Corruption
   windows/browser/ms11_003_ie_css_import                         2010-11-29       good       Internet Explorer CSS Recursive Import Use After Free
   windows/browser/ms11_050_mshtml_cobjectelement                 2011-06-16       normal     MS11-050 IE mshtml!CObjectElement Use After Free
   windows/browser/ms11_081_option                                2012-10-11       normal     Microsoft Internet Explorer Option Element Use-After-Free
   windows/browser/ms11_093_ole32                                 2011-12-13       normal     MS11-093 Microsoft Windows OLE Object File Handling Remote Code Execution
   windows/browser/ms12_004_midi                                  2012-01-10       normal     MS12-004 midiOutPlayNextPolyEvent Heap Overflow
   windows/browser/ms12_037_ie_colspan                            2012-06-12       normal     Microsoft Internet Explorer Fixed Table Col Span Heap Overflow
   windows/browser/ms12_037_same_id                               2012-06-12       normal     MS12-037 Internet Explorer Same ID Property Deleted Object Handling Memory Corruption
   windows/browser/ms13_009_ie_slayoutrun_uaf                     2013-02-13       average    MS13-009 Microsoft Internet Explorer SLayoutRun Use-After-Free
   windows/browser/ms13_037_svg_dashstyle                         2013-03-06       normal     MS13-037 Microsoft Internet Explorer COALineDashStyleArray Integer Overflow
   windows/browser/msvidctl_mpeg2                                 2009-07-05       normal     Microsoft DirectShow (msvidctl.dll) MPEG-2 Memory Corruption
   windows/browser/mswhale_checkforupdates                        2009-04-15       normal     Microsoft Whale Intelligent Application Gateway ActiveX Control Buffer Overflow
   windows/browser/msxml_get_definition_code_exec                 2012-06-12       good       MS12-043 Microsoft XML Core Services MSXML Uninitialized Memory Corruption
   windows/browser/nctaudiofile2_setformatlikesample              2007-01-24       normal     NCTAudioFile2 v2.x ActiveX Control SetFormatLikeSample() Buffer Overflow
   windows/browser/nis2004_antispam                               2004-03-19       normal     Norton AntiSpam 2004 SymSpamHelper ActiveX Control Buffer Overflow
   windows/browser/nis2004_get                                    2007-05-16       normal     Symantec Norton Internet Security 2004 ActiveX Control Buffer Overflow
   windows/browser/notes_handler_cmdinject                        2012-06-18       excellent  IBM Lotus Notes Client URL Handler Command Injection
   windows/browser/novell_groupwise_gwcls1_actvx                  2013-01-30       normal     Novell GroupWise Client gwcls1.dll ActiveX Remote Code Execution
   windows/browser/novelliprint_callbackurl                       2010-08-20       normal     Novell iPrint Client ActiveX Control call-back-url Buffer Overflow
   windows/browser/novelliprint_datetime                          2009-12-08       great      Novell iPrint Client ActiveX Control Date/Time Buffer Overflow
   windows/browser/novelliprint_executerequest                    2008-02-22       normal     Novell iPrint Client ActiveX Control ExecuteRequest Buffer Overflow
   windows/browser/novelliprint_executerequest_dbg                2010-08-04       normal     Novell iPrint Client ActiveX Control ExecuteRequest debug Buffer Overflow
   windows/browser/novelliprint_getdriversettings                 2008-06-16       normal     Novell iPrint Client ActiveX Control Buffer Overflow
   windows/browser/novelliprint_getdriversettings_2               2010-11-15       normal     Novell iPrint Client ActiveX Control <= 5.52 Buffer Overflow
   windows/browser/novelliprint_target_frame                      2009-12-08       great      Novell iPrint Client ActiveX Control target-frame Buffer Overflow
   windows/browser/ntr_activex_check_bof                          2012-01-11       normal     NTR ActiveX Control Check() Method Buffer Overflow
   windows/browser/ntr_activex_stopmodule                         2012-01-11       normal     NTR ActiveX Control StopModule() Remote Code Execution
   windows/browser/oracle_autovue_setmarkupmode                   2012-04-18       normal     Oracle AutoVue ActiveX Control SetMarkupMode Buffer Overflow
   windows/browser/oracle_dc_submittoexpress                      2009-08-28       normal     Oracle Document Capture 10g ActiveX Control Buffer Overflow
   windows/browser/oracle_webcenter_checkoutandopen               2013-04-16       excellent  Oracle WebCenter Content CheckOutAndOpen.dll ActiveX Remote Code Execution
   windows/browser/orbit_connecting                               2009-02-03       normal     Orbit Downloader Connecting Log Creation Buffer Overflow
   windows/browser/ovftool_format_string                          2012-11-08       normal     VMWare OVF Tools Format String Vulnerability
   windows/browser/pcvue_func                                     2011-10-05       average    PcVue 10.0 SV.UIGrdCtrl.1 'LoadObject()/SaveObject()' Trusted DWORD Vulnerability
   windows/browser/persits_xupload_traversal                      2009-09-29       excellent  Persits XUpload ActiveX MakeHttpRequest Directory Traversal
   windows/browser/quickr_qp2_bof                                 2012-05-23       normal     IBM Lotus QuickR qp2 ActiveX Buffer Overflow
   windows/browser/real_arcade_installerdlg                       2011-04-03       normal     Real Networks Arcade Games StubbyUtil.ProcessMgr ActiveX Arbitrary Code Execution
   windows/browser/realplayer_cdda_uri                            2010-11-15       normal     RealNetworks RealPlayer CDDA URI Initialization Vulnerability
   windows/browser/realplayer_console                             2008-03-08       normal     RealPlayer rmoc3260.dll ActiveX Control Heap Corruption
   windows/browser/realplayer_import                              2007-10-18       normal     RealPlayer ierpplug.dll ActiveX Control Playlist Name Buffer Overflow
   windows/browser/realplayer_qcp                                 2011-08-16       average    RealNetworks Realplayer QCP Parsing Heap Overflow
   windows/browser/realplayer_smil                                2005-03-01       normal     RealNetworks RealPlayer SMIL Buffer Overflow
   windows/browser/roxio_cineplayer                               2007-04-11       normal     Roxio CinePlayer ActiveX Control Buffer Overflow
   windows/browser/safari_xslt_output                             2011-07-20       excellent  Apple Safari Webkit libxslt Arbitrary File Creation
   windows/browser/samsung_neti_wiewer_backuptoavi_bof            2012-04-21       normal     Samsung NET-i Viewer Multiple ActiveX BackupToAvi() Remote Overflow
   windows/browser/sapgui_saveviewtosessionfile                   2009-03-31       normal     SAP AG SAPgui EAI WebViewer3D Buffer Overflow
   windows/browser/softartisans_getdrivename                      2008-08-25       normal     SoftArtisans XFile FileManager ActiveX Control Buffer Overflow
   windows/browser/sonicwall_addrouteentry                        2007-11-01       normal     SonicWall SSL-VPN NetExtender ActiveX Control Buffer Overflow
   windows/browser/symantec_altirisdeployment_downloadandinstall  2009-09-09       excellent  Symantec Altiris Deployment Solution ActiveX Control Arbitrary File Download and Execute
   windows/browser/symantec_altirisdeployment_runcmd              2009-11-04       normal     Symantec Altiris Deployment Solution ActiveX Control Buffer Overflow
   windows/browser/symantec_appstream_unsafe                      2009-01-15       excellent  Symantec AppStream LaunchObj ActiveX Control Arbitrary File Download and Execute
   windows/browser/symantec_backupexec_pvcalendar                 2008-02-28       normal     Symantec BackupExec Calendar Control Buffer Overflow
   windows/browser/symantec_consoleutilities_browseandsavefile    2009-11-02       normal     Symantec ConsoleUtilities ActiveX Control Buffer Overflow
   windows/browser/synactis_connecttosynactis_bof                 2013-05-30       normal     Synactis PDF In-The-Box ConnectToSynactic Stack Buffer Overflow
   windows/browser/systemrequirementslab_unsafe                   2008-10-16       excellent  Husdawg, LLC. System Requirements Lab ActiveX Unsafe Method
   windows/browser/teechart_pro                                   2011-08-11       normal     TeeChart Professional ActiveX Control <= 2010.0.0.3 Trusted Integer Dereference
   windows/browser/tom_sawyer_tsgetx71ex552                       2011-05-03       normal     Tom Sawyer Software GET Extension Factory Remote Code Execution
   windows/browser/trendmicro_extsetowner                         2010-08-25       normal     Trend Micro Internet Security Pro 2010 ActiveX extSetOwner() Remote Code Execution
   windows/browser/trendmicro_officescan                          2007-02-12       normal     Trend Micro OfficeScan Client ActiveX Control Buffer Overflow
   windows/browser/tumbleweed_filetransfer                        2008-04-07       great      Tumbleweed FileTransfer vcst_eu.dll ActiveX Control Buffer Overflow
   windows/browser/ubisoft_uplay_cmd_exec                         2012-07-29       normal     Ubisoft uplay 2.0.3 Active X Control Arbitrary Code Execution
   windows/browser/ultramjcam_openfiledig_bof                     2012-03-28       normal     TRENDnet SecurView Internet Camera UltraMJCam OpenFileDlg Buffer Overflow
   windows/browser/ultraoffice_httpupload                         2008-08-27       good       Ultra Shareware Office Control ActiveX HttpUpload Buffer Overflow
   windows/browser/verypdf_pdfview                                2008-06-16       normal     VeryPDF PDFView OCX ActiveX OpenPDF Heap Overflow
   windows/browser/viscom_movieplayer_drawtext                    2010-01-12       normal     Viscom Software Movie Player Pro SDK ActiveX 6.8
   windows/browser/vlc_amv                                        2011-03-23       good       VLC AMV Dangling Pointer Vulnerability
   windows/browser/vlc_mms_bof                                    2012-03-15       normal     VLC MMS Stream Handling Buffer Overflow
   windows/browser/webdav_dll_hijacker                            2010-08-18       manual     WebDAV Application DLL Hijacker
   windows/browser/webex_ucf_newobject                            2008-08-06       good       WebEx UCF atucfobj.dll ActiveX NewObject Method Buffer Overflow
   windows/browser/winamp_playlist_unc                            2006-01-29       great      Winamp Playlist UNC Path Computer Name Overflow
   windows/browser/winamp_ultravox                                2008-01-18       normal     Winamp Ultravox Streaming Metadata (in_mp3.dll) Buffer Overflow
   windows/browser/windvd7_applicationtype                        2007-03-20       normal     WinDVD7 IASystemInfo.DLL ActiveX Control Buffer Overflow
   windows/browser/winzip_fileview                                2007-11-02       normal     WinZip FileView (WZFILEVIEW.FileViewCtrl.61) ActiveX Buffer Overflow
   windows/browser/wmi_admintools                                 2010-12-21       great      Microsoft WMI Administration Tools ActiveX Buffer Overflow
   windows/browser/xmplay_asx                                     2006-11-21       good       XMPlay 3.3.0.4 (ASX Filename) Buffer Overflow
   windows/browser/yahoomessenger_fvcom                           2007-08-30       normal     Yahoo! Messenger YVerInfo.dll ActiveX Control Buffer Overflow
   windows/browser/yahoomessenger_server                          2007-06-05       good       Yahoo! Messenger 8.1.0.249 ActiveX Control Buffer Overflow
   windows/browser/zenturiprogramchecker_unsafe                   2007-05-29       excellent  Zenturi ProgramChecker ActiveX Control Arbitrary File Download
   windows/browser/zenworks_helplauncher_exec                     2011-10-19       normal     AdminStudio LaunchHelp.dll ActiveX Arbitrary Code Execution
   windows/dcerpc/ms03_026_dcom                                   2003-07-16       great      Microsoft RPC DCOM Interface Overflow
   windows/dcerpc/ms05_017_msmq                                   2005-04-12       good       Microsoft Message Queueing Service Path Overflow
   windows/dcerpc/ms07_029_msdns_zonename                         2007-04-12       great      Microsoft DNS RPC Service extractQuotedChar() Overflow (TCP)
   windows/dcerpc/ms07_065_msmq                                   2007-12-11       good       Microsoft Message Queueing Service DNS Name Path Overflow
   windows/driver/broadcom_wifi_ssid                              2006-11-11       low        Broadcom Wireless Driver Probe Response SSID Overflow
   windows/driver/dlink_wifi_rates                                2006-11-13       low        D-Link DWL-G132 Wireless Driver Beacon Rates Overflow
   windows/driver/netgear_wg111_beacon                            2006-11-16       low        NetGear WG111v2 Wireless Driver Long Beacon Overflow
   windows/email/ms07_017_ani_loadimage_chunksize                 2007-03-28       great      Windows ANI LoadAniIcon() Chunk Size Stack Buffer Overflow (SMTP)
   windows/email/ms10_045_outlook_ref_only                        2010-06-01       excellent  Outlook ATTACH_BY_REF_ONLY File Execution
   windows/email/ms10_045_outlook_ref_resolve                     2010-06-01       excellent  Outlook ATTACH_BY_REF_RESOLVE File Execution
   windows/emc/alphastor_agent                                    2008-05-27       great      EMC AlphaStor Agent Buffer Overflow
   windows/emc/networker_format_string                            2012-08-29       normal     EMC Networker Format String
   windows/fileformat/a-pdf_wav_to_mp3                            2010-08-17       normal     A-PDF WAV to MP3 v1.0.0 Buffer Overflow
   windows/fileformat/abbs_amp_lst                                2013-06-30       normal     ABBS Audio Media Player .LST Buffer Overflow
   windows/fileformat/acdsee_fotoslate_string                     2011-09-12       good       ACDSee FotoSlate PLP File id Parameter Overflow
   windows/fileformat/acdsee_xpm                                  2007-11-23       good       ACDSee XPM File Section Buffer Overflow
   windows/fileformat/actfax_import_users_bof                     2012-08-28       normal     ActiveFax (ActFax) 4.3 Client Importer Buffer Overflow
   windows/fileformat/activepdf_webgrabber                        2008-08-26       low        activePDF WebGrabber ActiveX Control Buffer Overflow
   windows/fileformat/adobe_collectemailinfo                      2008-02-08       good       Adobe Collab.collectEmailInfo() Buffer Overflow
   windows/fileformat/adobe_cooltype_sing                         2010-09-07       great      Adobe CoolType SING Table "uniqueName" Stack Buffer Overflow
   windows/fileformat/adobe_flashplayer_button                    2010-10-28       normal     Adobe Flash Player "Button" Remote Code Execution
   windows/fileformat/adobe_flashplayer_newfunction               2010-06-04       normal     Adobe Flash Player "newfunction" Invalid Pointer Use
   windows/fileformat/adobe_flatedecode_predictor02               2009-10-08       good       Adobe FlateDecode Stream Predictor 02 Integer Overflow
   windows/fileformat/adobe_geticon                               2009-03-24       good       Adobe Collab.getIcon() Buffer Overflow
   windows/fileformat/adobe_illustrator_v14_eps                   2009-12-03       great      Adobe Illustrator CS4 v14.0.0
   windows/fileformat/adobe_jbig2decode                           2009-02-19       good       Adobe JBIG2Decode Memory Corruption
   windows/fileformat/adobe_libtiff                               2010-02-16       good       Adobe Acrobat Bundled LibTIFF Integer Overflow
   windows/fileformat/adobe_media_newplayer                       2009-12-14       good       Adobe Doc.media.newPlayer Use After Free Vulnerability
   windows/fileformat/adobe_pdf_embedded_exe                      2010-03-29       excellent  Adobe PDF Embedded EXE Social Engineering
   windows/fileformat/adobe_pdf_embedded_exe_nojs                 2010-03-29       excellent  Adobe PDF Escape EXE Social Engineering (No JavaScript)
   windows/fileformat/adobe_reader_u3d                            2011-12-06       average    Adobe Reader U3D Memory Corruption Vulnerability
   windows/fileformat/adobe_u3d_meshdecl                          2009-10-13       good       Adobe U3D CLODProgressiveMeshDeclaration Array Overrun
   windows/fileformat/adobe_utilprintf                            2008-02-08       good       Adobe util.printf() Buffer Overflow
   windows/fileformat/altap_salamander_pdb                        2007-06-19       good       Altap Salamander 2.5 PE Viewer Buffer Overflow
   windows/fileformat/aol_desktop_linktag                         2011-01-31       normal     AOL Desktop 9.6 RTX Buffer Overflow
   windows/fileformat/aol_phobos_bof                              2010-01-20       average    AOL 9.5 Phobos.Playlist Import() Stack-based Buffer Overflow
   windows/fileformat/apple_quicktime_pnsize                      2011-08-08       good       Apple QuickTime PICT PnSize Buffer Overflow
   windows/fileformat/apple_quicktime_texml                       2012-05-15       normal     Apple QuickTime TeXML Style Element Stack Buffer Overflow
   windows/fileformat/audio_coder_m3u                             2013-05-01       normal     AudioCoder .M3U Buffer Overflow
   windows/fileformat/audio_wkstn_pls                             2009-12-08       good       Audio Workstation 6.4.2.4.3 pls Buffer Overflow
   windows/fileformat/audiotran_pls                               2010-01-09       good       Audiotran 1.4.1 (PLS File) Stack Buffer Overflow
   windows/fileformat/aviosoft_plf_buf                            2011-11-09       good       Aviosoft Digital TV Player Professional 1.0 Stack Buffer Overflow
   windows/fileformat/bacnet_csv                                  2010-09-16       good       BACnet OPC Client Buffer Overflow
   windows/fileformat/blazedvd_hdtv_bof                           2012-04-03       normal     BlazeVideo HDTV Player Pro v6.6 Filename Handling Vulnerability
   windows/fileformat/blazedvd_plf                                2009-08-03       good       BlazeDVD 5.1 PLF Buffer Overflow
   windows/fileformat/bsplayer_m3u                                2010-01-07       normal     BS.Player 2.57 Buffer Overflow (Unicode SEH)
   windows/fileformat/ca_cab                                      2007-06-05       good       CA Antivirus Engine CAB Buffer Overflow
   windows/fileformat/cain_abel_4918_rdp                          2008-11-30       good       Cain & Abel <= v4.9.24 RDP Buffer Overflow
   windows/fileformat/ccmplayer_m3u_bof                           2011-11-30       good       CCMPlayer 1.5 m3u Playlist Stack Based Buffer Overflow
   windows/fileformat/coolpdf_image_stream_bof                    2013-01-18       normal     Cool PDF Image Stream Buffer Overflow
   windows/fileformat/corelpdf_fusion_bof                         2013-07-08       normal     Corel PDF Fusion Stack Buffer Overflow
   windows/fileformat/csound_getnum_bof                           2012-02-23       normal     Csound hetro File Handling Stack Buffer Overflow
   windows/fileformat/cutezip_bof                                 2011-02-12       normal     GlobalSCAPE CuteZIP Stack Buffer Overflow
   windows/fileformat/cyberlink_p2g_bof                           2011-09-12       great      CyberLink Power2Go name attribute (p2g) Stack Buffer Overflow Exploit
   windows/fileformat/cytel_studio_cy3                            2011-10-02       good       Cytel Studio 9.0 (CY3 File) Stack Buffer Overflow
   windows/fileformat/deepburner_path                             2006-12-19       great      AstonSoft DeepBurner (DBR File) Path Buffer Overflow
   windows/fileformat/destinymediaplayer16                        2009-01-03       good       Destiny Media Player 1.61 PLS M3U Buffer Overflow
   windows/fileformat/digital_music_pad_pls                       2010-09-17       normal     Digital Music Pad Version 8.2.3.3.4 Stack Buffer Overflow
   windows/fileformat/djstudio_pls_bof                            2009-12-30       normal     DJ Studio Pro 5.1 .pls Stack Buffer Overflow
   windows/fileformat/djvu_imageurl                               2008-10-30       low        DjVu DjVu_ActiveX_MSOffice.dll ActiveX ComponentBuffer Overflow
   windows/fileformat/dvdx_plf_bof                                2007-06-02       normal     DVD X Player 5.5 .plf PlayList Buffer Overflow
   windows/fileformat/emc_appextender_keyworks                    2009-09-29       average    EMC ApplicationXtender (KeyWorks) ActiveX Control Buffer Overflow
   windows/fileformat/erdas_er_viewer_bof                         2013-04-23       normal     ERS Viewer 2011 ERS File Handling Buffer Overflow
   windows/fileformat/erdas_er_viewer_rf_report_error             2013-05-23       normal     ERS Viewer 2013 ERS File Handling Buffer Overflow
   windows/fileformat/esignal_styletemplate_bof                   2011-09-06       normal     eSignal and eSignal Pro <= 10.6.2425.1208 file parsing buffer overflow in QUO
   windows/fileformat/etrust_pestscan                             2009-11-02       average    CA eTrust PestPatrol ActiveX Control Buffer Overflow
   windows/fileformat/ezip_wizard_bof                             2009-03-09       good       eZip Wizard 3.0 Stack Buffer Overflow
   windows/fileformat/fatplayer_wav                               2010-10-18       normal     Fat Player Media Player 0.6b0 Buffer Overflow
   windows/fileformat/fdm_torrent                                 2009-02-02       good       Free Download Manager Torrent Parsing Buffer Overflow
   windows/fileformat/feeddemon_opml                              2009-02-09       great      FeedDemon <= 3.1.0.12 Stack Buffer Overflow
   windows/fileformat/foxit_reader_filewrite                      2011-03-05       normal     Foxit PDF Reader 4.2 Javascript File Write
   windows/fileformat/foxit_reader_launch                         2009-03-09       good       Foxit Reader 3.0 Open Execute Action Stack Based Buffer Overflow
   windows/fileformat/foxit_title_bof                             2010-11-13       great      Foxit PDF Reader v4.1.1 Title Stack Buffer Overflow
   windows/fileformat/free_mp3_ripper_wav                         2011-08-27       great      Free MP3 CD Ripper 1.1 WAV File Stack Buffer Overflow
   windows/fileformat/galan_fileformat_bof                        2009-12-07       normal     gAlan 0.2.1 Buffer Overflow
   windows/fileformat/gsm_sim                                     2010-07-07       normal     GSM SIM Editor 5.15 Buffer Overflow
   windows/fileformat/gta_samp                                    2011-09-18       normal     GTA SA-MP server.cfg Buffer Overflow
   windows/fileformat/hhw_hhp_compiledfile_bof                    2006-02-06       good       HTML Help Workshop 4.74 (hhp Project File) Buffer Overflow
   windows/fileformat/hhw_hhp_contentfile_bof                     2006-02-06       good       HTML Help Workshop 4.74 (hhp Project File) Buffer Overflow
   windows/fileformat/hhw_hhp_indexfile_bof                       2009-01-17       good       HTML Help Workshop 4.74 (hhp Project File) Buffer Overflow
   windows/fileformat/ht_mp3player_ht3_bof                        2009-06-29       good       HT-MP3Player 1.0 HT3 File Parsing Buffer Overflow
   windows/fileformat/ibm_pcm_ws                                  2012-02-28       great      IBM Personal Communications iSeries Access WorkStation 5.9 Profile
   windows/fileformat/ideal_migration_ipj                         2009-12-05       great      PointDev IDEAL Migration Buffer Overflow
   windows/fileformat/irfanview_jpeg2000_bof                      2012-01-16       normal     Irfanview JPEG2000 <= v4.3.2.0 jp2 Stack Buffer Overflow
   windows/fileformat/ispvm_xcf_ispxcf                            2012-05-16       normal     Lattice Semiconductor ispVM System XCF File Handling Overflow
   windows/fileformat/kingview_kingmess_kvl                       2012-11-20       normal     KingView Log File Parsing Buffer Overflow
   windows/fileformat/lattice_pac_bof                             2012-05-16       normal     Lattice Semiconductor PAC-Designer 6.21 Symbol Value Buffer Overflow
   windows/fileformat/lotusnotes_lzh                              2011-05-24       good       Lotus Notes 8.0.x - 8.5.2 FP2 - Autonomy Keyview (.lzh Attachment)
   windows/fileformat/magix_musikmaker_16_mmm                     2011-04-26       good       Magix Musik Maker 16 .mmm Stack Buffer Overflow
   windows/fileformat/mcafee_hercules_deletesnapshot              2008-08-04       low        McAfee Remediation Client ActiveX Control Buffer Overflow
   windows/fileformat/mcafee_showreport_exec                      2012-01-12       normal     McAfee SaaS MyCioScan ShowReport Remote Command Execution
   windows/fileformat/mediacoder_m3u                              2013-06-24       normal     MediaCoder .M3U Buffer Overflow
   windows/fileformat/mediajukebox                                2009-07-01       normal     Media Jukebox 8.0.400 Buffer Overflow (SEH)
   windows/fileformat/microp_mppl                                 2010-08-23       great      MicroP 0.1.1.1600 (MPPL File) Stack Buffer Overflow
   windows/fileformat/millenium_mp3_pls                           2009-07-30       great      Millenium MP3 Studio 2.0 (PLS File) Stack Buffer Overflow
   windows/fileformat/mini_stream_pls_bof                         2010-07-16       great      Mini-Stream RM-MP3 Converter v3.1.2.1 PLS File Stack Buffer Overflow
   windows/fileformat/mjm_coreplayer2011_s3m                      2011-04-30       good       MJM Core Player 2011 .s3m Stack Buffer Overflow
   windows/fileformat/mjm_quickplayer_s3m                         2011-04-30       good       MJM QuickPlayer 1.00 beta 60a / QuickPlayer 2010 .s3m Stack Buffer Overflow
   windows/fileformat/moxa_mediadbplayback                        2010-10-19       average    MOXA MediaDBPlayback ActiveX Control Buffer Overflow
   windows/fileformat/mplayer_sami_bof                            2011-05-19       normal     MPlayer SAMI Subtitle File Buffer Overflow
   windows/fileformat/ms09_067_excel_featheader                   2009-11-10       good       Microsoft Excel Malformed FEATHEADER Record Vulnerability
   windows/fileformat/ms10_004_textbytesatom                      2010-02-09       good       Microsoft PowerPoint Viewer TextBytesAtom Stack Buffer Overflow
   windows/fileformat/ms10_038_excel_obj_bof                      2010-06-08       normal     MS11-038 Microsoft Office Excel Malformed OBJ Record Handling Overflow
   windows/fileformat/ms10_087_rtf_pfragments_bof                 2010-11-09       great      Microsoft Word RTF pFragments Stack Buffer Overflow (File Format)
   windows/fileformat/ms11_006_createsizeddibsection              2010-12-15       great      Microsoft Windows CreateSizedDIBSECTION Stack Buffer Overflow
   windows/fileformat/ms11_021_xlb_bof                            2011-08-09       normal     MS11-021 Microsoft Office 2007 Excel .xlb Buffer Overflow
   windows/fileformat/ms12_005                                    2012-01-10       excellent  MS12-005 Microsoft Office ClickOnce Unsafe Object Package Handling Vulnerability
   windows/fileformat/ms12_027_mscomctl_bof                       2012-04-10       average    MS12-027 MSCOMCTL ActiveX Buffer Overflow
   windows/fileformat/ms_visual_basic_vbp                         2007-09-04       good       Microsoft Visual Basic VBP Buffer Overflow
   windows/fileformat/msworks_wkspictureinterface                 2008-11-28       low        Microsoft Works 7 WkImgSrv.dll WKsPictureInterface() ActiveX Code Execution
   windows/fileformat/mymp3player_m3u                             2010-03-18       good       Steinberg MyMP3Player 3.0 Buffer Overflow
   windows/fileformat/netop                                       2011-04-28       normal     NetOp Remote Control Client 9.5 Buffer Overflow
   windows/fileformat/nuance_pdf_launch_overflow                  2010-10-08       great      Nuance PDF Reader v6.0 Launch Stack Buffer Overflow
   windows/fileformat/openoffice_ole                              2008-04-17       normal     OpenOffice OLE Importer DocumentSummaryInformation Stream Handling Overflow
   windows/fileformat/orbit_download_failed_bof                   2008-04-03       normal     Orbit Downloader URL Unicode Conversion Overflow
   windows/fileformat/orbital_viewer_orb                          2010-02-27       great      Orbital Viewer ORB File Parsing Buffer Overflow
   windows/fileformat/ovf_format_string                           2012-11-08       normal     VMWare OVF Tools Format String Vulnerability
   windows/fileformat/proshow_cellimage_bof                       2009-08-20       great      ProShow Gold v4.0.2549 (PSH File) Stack Buffer Overflow
   windows/fileformat/proshow_load_bof                            2012-06-06       normal     Photodex ProShow Producer 5.0.3256 load File Handling Buffer Overflow
   windows/fileformat/real_networks_netzip_bof                    2011-01-30       good       Real Networks Netzip Classic 7.5.1 86 File Parsing Buffer Overflow Vulnerability
   windows/fileformat/real_player_url_property_bof                2012-12-14       normal     RealPlayer RealMedia File Handling Buffer Overflow
   windows/fileformat/safenet_softremote_groupname                2009-10-30       good       SafeNet SoftRemote GROUPNAME Buffer Overflow
   windows/fileformat/sascam_get                                  2008-12-29       low        SasCam Webcam Server v.2.6.5 Get() method Buffer Overflow
   windows/fileformat/scadaphone_zip                              2011-09-12       good       ScadaTEC ScadaPhone <= v5.3.11.1230 Stack Buffer Overflow
   windows/fileformat/shadow_stream_recorder_bof                  2010-03-29       normal     Shadow Stream Recorder 3.0.1.7 Buffer Overflow
   windows/fileformat/somplplayer_m3u                             2010-01-22       great      S.O.M.P.L 1.0 Player Buffer Overflow
   windows/fileformat/subtitle_processor_m3u_bof                  2011-04-26       normal     Subtitle Processor 7.7.1 .M3U SEH Unicode Buffer Overflow
   windows/fileformat/tfm_mmplayer_m3u_ppl_bof                    2012-03-23       good       TFM MMPlayer (m3u/ppl File) Buffer Overflow
   windows/fileformat/tugzip                                      2008-10-28       good       TugZip 3.5 Zip File Parsing Buffer Overflow Vulnerability
   windows/fileformat/ultraiso_ccd                                2009-04-03       great      UltraISO CCD File Parsing Buffer Overflow
   windows/fileformat/ultraiso_cue                                2007-05-24       great      UltraISO CUE File Parsing Buffer Overflow
   windows/fileformat/ursoft_w32dasm                              2005-01-24       good       URSoft W32Dasm Disassembler Function Buffer Overflow
   windows/fileformat/varicad_dwb                                 2010-03-17       great      VariCAD 2010-2.05 EN (DWB File) Stack Buffer Overflow
   windows/fileformat/videolan_tivo                               2008-10-22       good       VideoLAN VLC TiVo Buffer Overflow
   windows/fileformat/videospirit_visprj                          2011-04-11       good       VeryTools Video Spirit Pro <= 1.70
   windows/fileformat/visio_dxf_bof                               2010-05-04       good       Microsoft Office Visio VISIODWG.DLL DXF File Handling Vulnerability
   windows/fileformat/visiwave_vwr_type                           2011-05-20       great      VisiWave VWR File Parsing Vulnerability
   windows/fileformat/vlc_modplug_s3m                             2011-04-07       average    VideoLAN VLC ModPlug ReadS3M Stack Buffer Overflow
   windows/fileformat/vlc_realtext                                2008-11-05       good       VLC Media Player RealText Subtitle Overflow
   windows/fileformat/vlc_smb_uri                                 2009-06-24       great      VideoLAN Client (VLC) Win32 smb:// URI Buffer Overflow
   windows/fileformat/vlc_webm                                    2011-01-31       good       VideoLAN VLC MKV Memory Corruption
   windows/fileformat/vuplayer_cue                                2009-08-18       good       VUPlayer CUE Buffer Overflow
   windows/fileformat/vuplayer_m3u                                2009-08-18       good       VUPlayer M3U Buffer Overflow
   windows/fileformat/winamp_maki_bof                             2009-05-20       normal     Winamp MAKI Buffer Overflow
   windows/fileformat/wireshark_packet_dect                       2011-04-18       good       Wireshark <= 1.4.4 packet-dect.c Stack Buffer Overflow (local)
   windows/fileformat/wm_downloader_m3u                           2010-07-28       normal     WM Downloader 3.1.2.2 Buffer Overflow
   windows/fileformat/xenorate_xpl_bof                            2009-08-19       great      Xenorate 2.50 (.xpl) universal Local Buffer Overflow (SEH)
   windows/fileformat/xion_m3u_sehbof                             2010-11-23       great      Xion Audio Player 1.0.126 Unicode Stack Buffer Overflow
   windows/fileformat/xradio_xrl_sehbof                           2011-02-08       normal     xRadio 0.95b Buffer Overflow
   windows/fileformat/zinfaudioplayer221_pls                      2004-09-24       good       Zinf Audio Player 2.2.1 (PLS File) Stack Buffer Overflow
   windows/firewall/blackice_pam_icq                              2004-03-18       great      ISS PAM.dll ICQ Parser Buffer Overflow
   windows/firewall/kerio_auth                                    2003-04-28       average    Kerio Firewall 2.1.4 Authentication Packet Overflow
   windows/ftp/32bitftp_list_reply                                2010-10-12       good       32bit FTP Client Stack Buffer Overflow 
   windows/ftp/3cdaemon_ftp_user                                  2005-01-04       average    3Com 3CDaemon 2.0 FTP Username Overflow
   windows/ftp/aasync_list_reply                                  2010-10-12       good       AASync v2.2.1.0 (Win32) Stack Buffer Overflow (LIST)
   windows/ftp/ability_server_stor                                2004-10-22       normal     Ability Server 2.34 STOR Command Stack Buffer Overflow
   windows/ftp/absolute_ftp_list_bof                              2011-11-09       normal     AbsoluteFTP 1.9.6 - 2.2.10 LIST Command Remote Buffer Overflow
   windows/ftp/cesarftp_mkd                                       2006-06-12       average    Cesar FTP 0.99g MKD Command Buffer Overflow
   windows/ftp/comsnd_ftpd_fmtstr                                 2012-06-08       good       ComSndFTP v1.3.7 Beta USER Format String (Write4) Vulnerability
   windows/ftp/dreamftp_format                                    2004-03-03       good       BolinTech Dream FTP Server 1.02 Format String
   windows/ftp/easyfilesharing_pass                               2006-07-31       average    Easy File Sharing FTP Server 2.0 PASS Overflow
   windows/ftp/easyftp_cwd_fixret                                 2010-02-16       great      EasyFTP Server <= 1.7.0.11 CWD Command Stack Buffer Overflow
   windows/ftp/easyftp_list_fixret                                2010-07-05       great      EasyFTP Server <= 1.7.0.11 LIST Command Stack Buffer Overflow
   windows/ftp/easyftp_mkd_fixret                                 2010-04-04       great      EasyFTP Server <= 1.7.0.11 MKD Command Stack Buffer Overflow
   windows/ftp/filecopa_list_overflow                             2006-07-19       average    FileCopa FTP Server pre 18 Jul Version
   windows/ftp/filewrangler_list_reply                            2010-10-12       good       FileWrangler 5.30 Stack Buffer Overflow
   windows/ftp/freefloatftp_user                                  2012-06-12       normal     Free Float FTP Server USER Command Buffer Overflow
   windows/ftp/freefloatftp_wbem                                  2012-12-07       excellent  FreeFloat FTP Server Arbitrary File Upload
   windows/ftp/freeftpd_user                                      2005-11-16       average    freeFTPd 1.0 Username Overflow
   windows/ftp/ftpgetter_pwd_reply                                2010-10-12       good       FTPGetter Standard v3.55.0.05 Stack Buffer Overflow (PWD)
   windows/ftp/ftppad_list_reply                                  2010-10-12       good       FTPPad 1.2.0 Stack Buffer Overflow
   windows/ftp/ftpshell51_pwd_reply                               2010-10-12       good       FTPShell 5.1 Stack Buffer Overflow
   windows/ftp/ftpsynch_list_reply                                2010-10-12       good       FTP Synchronizer Professional 4.0.73.274 Stack Buffer Overflow
   windows/ftp/gekkomgr_list_reply                                2010-10-12       good       Gekko Manager FTP Client Stack Buffer Overflow
   windows/ftp/globalscapeftp_input                               2005-05-01       great      GlobalSCAPE Secure FTP Server Input Overflow
   windows/ftp/goldenftp_pass_bof                                 2011-01-23       average    GoldenFTP PASS Stack Buffer Overflow
   windows/ftp/httpdx_tolog_format                                2009-11-17       great      HTTPDX tolog() Function Format String Vulnerability
   windows/ftp/leapftp_list_reply                                 2010-10-12       good       LeapFTP 3.0.1 Stack Buffer Overflow
   windows/ftp/leapftp_pasv_reply                                 2003-06-09       normal     LeapWare LeapFTP v2.7.3.600 PASV Reply Client Overflow
   windows/ftp/ms09_053_ftpd_nlst                                 2009-08-31       great      Microsoft IIS FTP Server NLST Response Overflow
   windows/ftp/netterm_netftpd_user                               2005-04-26       great      NetTerm NetFTPD USER Buffer Overflow
   windows/ftp/odin_list_reply                                    2010-10-12       good       Odin Secure FTP 4.1 Stack Buffer Overflow (LIST)
   windows/ftp/oracle9i_xdb_ftp_pass                              2003-08-18       great      Oracle 9i XDB FTP PASS Overflow (win32)
   windows/ftp/oracle9i_xdb_ftp_unlock                            2003-08-18       great      Oracle 9i XDB FTP UNLOCK Overflow (win32)
   windows/ftp/proftp_banner                                      2009-08-25       normal     ProFTP 2.9 Banner Remote Buffer Overflow
   windows/ftp/quickshare_traversal_write                         2011-02-03       excellent  QuickShare File Server 1.2.1 Directory Traversal Vulnerability
   windows/ftp/ricoh_dl_bof                                       2012-03-01       normal     Ricoh DC DL-10 SR10 FTP USER Command Buffer Overflow
   windows/ftp/sami_ftpd_list                                     2013-02-27       low        Sami FTP Server LIST Command Buffer Overflow
   windows/ftp/sami_ftpd_user                                     2006-01-24       normal     KarjaSoft Sami FTP Server v2.02 USER Overflow
   windows/ftp/sasser_ftpd_port                                   2004-05-10       average    Sasser Worm avserve FTP PORT Buffer Overflow
   windows/ftp/scriptftp_list                                     2011-10-12       good       ScriptFTP <= 3.3 Remote Buffer Overflow (LIST)
   windows/ftp/seagull_list_reply                                 2010-10-12       good       Seagull FTP v3.3 build 409 Stack Buffer Overflow
   windows/ftp/servu_chmod                                        2004-12-31       normal     Serv-U FTP Server < 4.2 Buffer Overflow
   windows/ftp/servu_mdtm                                         2004-02-26       good       Serv-U FTPD MDTM Overflow
   windows/ftp/slimftpd_list_concat                               2005-07-21       great      SlimFTPd LIST Concatenation Overflow
   windows/ftp/trellian_client_pasv                               2010-04-11       normal     Trellian FTP Client 3.01 PASV Remote Buffer Overflow
   windows/ftp/turboftp_port                                      2012-10-03       great      Turbo FTP Server 1.30.823 PORT Overflow
   windows/ftp/vermillion_ftpd_port                               2009-09-23       great      Vermillion FTP Daemon PORT Command Memory Corruption
   windows/ftp/warftpd_165_pass                                   1998-03-19       average    War-FTPD 1.65 Password Overflow
   windows/ftp/warftpd_165_user                                   1998-03-19       average    War-FTPD 1.65 Username Overflow
   windows/ftp/wftpd_size                                         2006-08-23       average    Texas Imperial Software WFTPD 3.23 SIZE Overflow
   windows/ftp/wsftp_server_503_mkd                               2004-11-29       great      WS-FTP Server 5.03 MKD Overflow
   windows/ftp/wsftp_server_505_xmd5                              2006-09-14       average    Ipswitch WS_FTP Server 5.05 XMD5 Overflow
   windows/ftp/xftp_client_pwd                                    2010-04-22       normal     Xftp FTP Client 3.0 PWD Remote Buffer Overflow
   windows/ftp/xlink_client                                       2009-10-03       normal     Xlink FTP Client Buffer Overflow
   windows/ftp/xlink_server                                       2009-10-03       good       Xlink FTP Server Buffer Overflow
   windows/games/mohaa_getinfo                                    2004-07-17       great      Medal Of Honor Allied Assault getinfo Stack Buffer Overflow
   windows/games/racer_503beta5                                   2008-08-10       great      Racer v0.5.3 beta 5 Buffer Overflow
   windows/games/ut2004_secure                                    2004-06-18       good       Unreal Tournament 2004 "secure" Overflow (Win32)
   windows/http/adobe_robohelper_authbypass                       2009-09-23       excellent  Adobe RoboHelp Server 8 Arbitrary File Upload and Execute
   windows/http/altn_securitygateway                              2008-06-02       average    Alt-N SecurityGateway username Buffer Overflow
   windows/http/altn_webadmin                                     2003-06-24       average    Alt-N WebAdmin USER Buffer Overflow
   windows/http/amlibweb_webquerydll_app                          2010-08-03       normal     Amlibweb NetOpacs webquery.dll Stack Buffer Overflow
   windows/http/apache_chunked                                    2002-06-19       good       Apache Win32 Chunked Encoding
   windows/http/apache_mod_rewrite_ldap                           2006-07-28       great      Apache module mod_rewrite LDAP protocol Buffer Overflow
   windows/http/apache_modjk_overflow                             2007-03-02       great      Apache mod_jk 1.2.20 Buffer Overflow
   windows/http/avaya_ccr_imageupload_exec                        2012-06-28       excellent  Avaya IP Office Customer Call Reporter ImageUpload.ashx Remote Command Execution
   windows/http/badblue_ext_overflow                              2003-04-20       great      BadBlue 2.5 EXT.dll Buffer Overflow
   windows/http/badblue_passthru                                  2007-12-10       great      BadBlue 2.72b PassThru Buffer Overflow
   windows/http/bea_weblogic_jsessionid                           2009-01-13       good       BEA WebLogic JSESSIONID Cookie Value Overflow
   windows/http/bea_weblogic_post_bof                             2008-07-17       great      Oracle Weblogic Apache Connector POST Request Buffer Overflow
   windows/http/bea_weblogic_transfer_encoding                    2008-09-09       great      BEA Weblogic Transfer-Encoding Buffer Overflow
   windows/http/belkin_bulldog                                    2009-03-08       average    Belkin Bulldog Plus Web Service Buffer Overflow
   windows/http/ca_arcserve_rpc_authbypass                        2011-07-25       excellent  CA Arcserve D2D GWT RPC Credential Information Disclosure
   windows/http/ca_igateway_debug                                 2005-10-06       average    CA iTechnology iGateway Debug Mode Buffer Overflow
   windows/http/ca_totaldefense_regeneratereports                 2011-04-13       excellent  CA Total Defense Suite reGenerateReports Stored Procedure SQL Injection
   windows/http/coldfusion_fckeditor                              2009-07-03       excellent  ColdFusion 8.0.1 Arbitrary File Upload and Execute
   windows/http/cyclope_ess_sqli                                  2012-08-08       excellent  Cyclope Employee Surveillance Solution v6 SQL Injection
   windows/http/easyftp_list                                      2010-02-18       great      EasyFTP Server <= 1.7.0.11 list.html path Stack Buffer Overflow
   windows/http/edirectory_host                                   2006-10-21       great      Novell eDirectory NDS Server Host Header Overflow
   windows/http/edirectory_imonitor                               2005-08-11       great      eDirectory 8.7.3 iMonitor Remote Stack Buffer Overflow
   windows/http/efs_easychatserver_username                       2007-08-14       great      EFS Easy Chat Server Authentication Request Handling Buffer Overflow
   windows/http/ektron_xslt_exec                                  2012-10-16       excellent  Ektron 8.02 XSLT Transform Remote Code Execution
   windows/http/ezserver_http                                     2012-06-18       excellent  EZHomeTech EzServer <= 6.4.017 Stack Buffer Overflow Vulnerability
   windows/http/fdm_auth_header                                   2009-02-02       great      Free Download Manager Remote Control Server Buffer Overflow
   windows/http/hp_imc_mibfileupload                              2013-03-07       great      HP Intelligent Management Center Arbitrary File Upload
   windows/http/hp_nnm_getnnmdata_hostname                        2010-05-11       great      HP OpenView Network Node Manager getnnmdata.exe (Hostname) CGI Buffer Overflow
   windows/http/hp_nnm_getnnmdata_icount                          2010-05-11       great      HP OpenView Network Node Manager getnnmdata.exe (ICount) CGI Buffer Overflow
   windows/http/hp_nnm_getnnmdata_maxage                          2010-05-11       great      HP OpenView Network Node Manager getnnmdata.exe (MaxAge) CGI Buffer Overflow
   windows/http/hp_nnm_nnmrptconfig_nameparams                    2011-01-10       normal     HP OpenView NNM nnmRptConfig nameParams Buffer Overflow
   windows/http/hp_nnm_nnmrptconfig_schdparams                    2011-01-10       normal     HP OpenView NNM nnmRptConfig.exe schdParams Buffer Overflow
   windows/http/hp_nnm_openview5                                  2007-12-06       great      HP OpenView Network Node Manager OpenView5.exe CGI Buffer Overflow
   windows/http/hp_nnm_ovalarm_lang                               2009-12-09       great      HP OpenView Network Node Manager ovalarm.exe CGI Buffer Overflow
   windows/http/hp_nnm_ovas                                       2008-04-02       good       HP OpenView NNM 7.53, 7.51 OVAS.EXE Pre-Authentication Stack Buffer Overflow
   windows/http/hp_nnm_ovbuildpath_textfile                       2011-11-01       normal     HP OpenView Network Node Manager ov.dll _OVBuildPath Buffer Overflow
   windows/http/hp_nnm_ovwebhelp                                  2009-12-09       great      HP OpenView Network Node Manager OvWebHelp.exe CGI Buffer Overflow
   windows/http/hp_nnm_ovwebsnmpsrv_main                          2010-06-16       great      HP OpenView Network Node Manager ovwebsnmpsrv.exe main Buffer Overflow
   windows/http/hp_nnm_ovwebsnmpsrv_ovutil                        2010-06-16       great      HP OpenView Network Node Manager ovwebsnmpsrv.exe ovutil Buffer Overflow
   windows/http/hp_nnm_ovwebsnmpsrv_uro                           2010-06-08       great      HP OpenView Network Node Manager ovwebsnmpsrv.exe Unrecognized Option Buffer Overflow
   windows/http/hp_nnm_snmp                                       2009-12-09       great      HP OpenView Network Node Manager Snmp.exe CGI Buffer Overflow
   windows/http/hp_nnm_snmpviewer_actapp                          2010-05-11       great      HP OpenView Network Node Manager snmpviewer.exe Buffer Overflow
   windows/http/hp_nnm_toolbar_01                                 2009-01-07       great      HP OpenView Network Node Manager Toolbar.exe CGI Buffer Overflow
   windows/http/hp_nnm_toolbar_02                                 2009-01-21       normal     HP OpenView Network Node Manager Toolbar.exe CGI Cookie Handling Buffer Overflow
   windows/http/hp_nnm_webappmon_execvp                           2010-07-20       great      HP OpenView Network Node Manager execvp_nc Buffer Overflow
   windows/http/hp_nnm_webappmon_ovjavalocale                     2010-08-03       great      HP NNM CGI webappmon.exe OvJavaLocale Buffer Overflow
   windows/http/hp_openview_insight_backdoor                      2011-01-31       excellent  HP OpenView Performance Insight Server Backdoor Account Code Execution
   windows/http/hp_power_manager_filename                         2011-10-19       normal     HP Power Manager 'formExportDataLogs' Buffer Overflow
   windows/http/hp_power_manager_login                            2009-11-04       average    Hewlett-Packard Power Manager Administration Buffer Overflow
   windows/http/hp_sys_mgmt_exec                                  2013-06-11       excellent  HP System Management Homepage JustGetSNMPQueue Command Injection
   windows/http/httpdx_handlepeer                                 2009-10-08       great      HTTPDX h_handlepeer() Function Buffer Overflow
   windows/http/httpdx_tolog_format                               2009-11-17       great      HTTPDX tolog() Function Format String Vulnerability
   windows/http/ia_webmail                                        2003-11-03       average    IA WebMail 3.x Buffer Overflow
   windows/http/ibm_tivoli_endpoint_bof                           2011-05-31       good       IBM Tivoli Endpoint Manager POST Query Buffer Overflow
   windows/http/ibm_tpmfosd_overflow                              2007-05-02       good       IBM TPM for OS Deployment 5.1.0.x rembo.exe Buffer Overflow
   windows/http/ibm_tsm_cad_header                                2007-09-24       good       IBM Tivoli Storage Manager Express CAD Service Buffer Overflow
   windows/http/icecast_header                                    2004-09-28       great      Icecast (<= 2.0.1) Header Overwrite (win32)
   windows/http/integard_password_bof                             2010-09-07       great      Race River Integard Home/Pro LoginAdmin Password Stack Buffer Overflow
   windows/http/intersystems_cache                                2009-09-29       great      InterSystems Cache UtilConfigHome.csp Argument Buffer Overflow
   windows/http/ipswitch_wug_maincfgret                           2004-08-25       great      Ipswitch WhatsUp Gold 8.03 Buffer Overflow
   windows/http/kolibri_http                                      2010-12-26       good       Kolibri <= v2.0 HTTP Server HEAD Buffer Overflow
   windows/http/landesk_thinkmanagement_upload_asp                2012-02-15       excellent  LANDesk Lenovo ThinkManagement Console Remote Command Execution
   windows/http/mailenable_auth_header                            2005-04-24       great      MailEnable Authorization Header Buffer Overflow
   windows/http/manageengine_apps_mngr                            2011-04-08       average    ManageEngine Applications Manager Authenticated Code Execution
   windows/http/maxdb_webdbm_database                             2006-08-29       good       MaxDB WebDBM Database Parameter Overflow
   windows/http/maxdb_webdbm_get_overflow                         2005-04-26       good       MaxDB WebDBM GET Buffer Overflow
   windows/http/mcafee_epolicy_source                             2006-07-17       average    McAfee ePolicy Orchestrator / ProtectionPilot Overflow
   windows/http/mdaemon_worldclient_form2raw                      2003-12-29       great      MDaemon <= 6.8.5 WorldClient form2raw.cgi Stack Buffer Overflow
   windows/http/minishare_get_overflow                            2004-11-07       average    Minishare 1.4.1 Buffer Overflow
   windows/http/navicopa_get_overflow                             2006-09-28       great      NaviCOPA 2.0.1 URL Handling Buffer Overflow
   windows/http/netdecision_http_bof                              2012-02-24       normal     NetDecision 4.5.1 HTTP Server Buffer Overflow
   windows/http/novell_imanager_upload                            2010-10-01       excellent  Novell iManager getMultiPartParameters Arbitrary File Upload
   windows/http/novell_mdm_lfi                                    2013-03-13       normal     Novell Zenworks Mobile Managment MDM.php Local File Inclusion Vulnerability
   windows/http/novell_messenger_acceptlang                       2006-04-13       average    Novell Messenger Server 2.0 Accept-Language Overflow
   windows/http/nowsms                                            2008-02-19       good       Now SMS/MMS Gateway Buffer Overflow
   windows/http/oracle9i_xdb_pass                                 2003-08-18       great      Oracle 9i XDB HTTP PASS Overflow (win32)
   windows/http/oracle_btm_writetofile                            2012-08-07       excellent  Oracle Business Transaction Management FlashTunnelService Remote Code Execution
   windows/http/osb_uname_jlist                                   2010-07-13       excellent  Oracle Secure Backup Authentication Bypass/Command Injection Vulnerability
   windows/http/peercast_url                                      2006-03-08       average    PeerCast <= 0.1216 URL Handling Buffer Overflow (win32)
   windows/http/php_apache_request_headers_bof                    2012-05-08       normal     PHP apache_request_headers Function Buffer Overflow
   windows/http/privatewire_gateway                               2006-06-26       average    Private Wire Gateway Buffer Overflow
   windows/http/psoproxy91_overflow                               2004-02-20       average    PSO Proxy v0.91 Stack Buffer Overflow
   windows/http/rabidhamster_r4_log                               2012-02-09       normal     RabidHamster R4 Log Entry sprintf() Buffer Overflow
   windows/http/sambar6_search_results                            2003-06-21       normal     Sambar 6 Search Results Buffer Overflow
   windows/http/sap_configservlet_exec_noauth                     2012-11-01       great      SAP ConfigServlet Remote Code Execution
   windows/http/sap_host_control_cmd_exec                         2012-08-14       average    SAP NetWeaver HostControl Command Injection
   windows/http/sap_mgmt_con_osexec_payload                       2011-03-08       excellent  SAP Management Console OSExecute Payload Execution
   windows/http/sapdb_webtools                                    2007-07-05       great      SAP DB 7.4 WebTools Buffer Overflow
   windows/http/savant_31_overflow                                2002-09-10       great      Savant 3.1 Web Server Overflow
   windows/http/servu_session_cookie                              2009-11-01       good       Rhinosoft Serv-U Session Cookie Buffer Overflow
   windows/http/shoutcast_format                                  2004-12-23       average    SHOUTcast DNAS/win32 1.9.4 File Request Format String Overflow
   windows/http/shttpd_post                                       2006-10-06       average    SHTTPD <= 1.34 URI-Encoded POST Request Overflow (win32)
   windows/http/solarwinds_storage_manager_sql                    2011-12-07       excellent  Solarwinds Storage Manager 5.1.0 SQL Injection
   windows/http/sonicwall_scrutinizer_sqli                        2012-07-22       excellent  Dell SonicWALL (Plixer) Scrutinizer 9 SQL Injection
   windows/http/steamcast_useragent                               2008-01-24       average    Streamcast <= 0.9.75 HTTP User-Agent Buffer Overflow
   windows/http/sws_connection_bof                                2012-07-20       normal     Simple Web Server Connection Header Buffer Overflow
   windows/http/sybase_easerver                                   2005-07-25       average    Sybase EAServer 5.2 Remote Stack Buffer Overflow
   windows/http/sysax_create_folder                               2012-07-29       normal     Sysax Multi Server 5.64 Create Folder Buffer Overflow
   windows/http/trackercam_phparg_overflow                        2005-02-18       average    TrackerCam PHP Argument Buffer Overflow
   windows/http/trendmicro_officescan                             2007-06-28       good       Trend Micro OfficeScan Remote Stack Buffer Overflow
   windows/http/umbraco_upload_aspx                               2012-06-28       excellent  Umbraco CMS Remote Command Execution
   windows/http/webster_http                                      2002-12-02       average    Webster HTTP Server GET Buffer Overflow
   windows/http/xampp_webdav_upload_php                           2012-01-14       excellent  XAMPP WebDAV PHP Upload
   windows/http/xitami_if_mod_since                               2007-09-24       average    Xitami 2.5c2 Web Server If-Modified-Since Overflow
   windows/http/zenworks_assetmgmt_uploadservlet                  2011-11-02       excellent  Novell ZENworks Asset Management Remote Execution
   windows/http/zenworks_uploadservlet                            2010-03-30       excellent  Novell ZENworks Configuration Management Remote Execution
   windows/iis/iis_webdav_upload_asp                              1994-01-01       excellent  Microsoft IIS WebDAV Write Access Code Execution
   windows/iis/ms01_023_printer                                   2001-05-01       good       Microsoft IIS 5.0 Printer Host Header Overflow
   windows/iis/ms01_026_dbldecode                                 2001-05-15       excellent  Microsoft IIS/PWS CGI Filename Double Decode Command Execution
   windows/iis/ms01_033_idq                                       2001-06-18       good       Microsoft IIS 5.0 IDQ Path Overflow
   windows/iis/ms02_018_htr                                       2002-04-10       good       Microsoft IIS 4.0 .HTR Path Overflow
   windows/iis/ms02_065_msadc                                     2002-11-20       normal     Microsoft IIS MDAC msadcs.dll RDS DataStub Content-Type Overflow
   windows/iis/ms03_007_ntdll_webdav                              2003-05-30       great      Microsoft IIS 5.0 WebDAV ntdll.dll Path Overflow
   windows/iis/msadc                                              1998-07-17       excellent  Microsoft IIS MDAC msadcs.dll RDS Arbitrary Remote Command Execution
   windows/imap/eudora_list                                       2005-12-20       great      Qualcomm WorldMail 3.0 IMAPD LIST Buffer Overflow
   windows/imap/imail_delete                                      2004-11-12       average    IMail IMAP4D Delete Overflow
   windows/imap/ipswitch_search                                   2007-07-18       average    Ipswitch IMail IMAP SEARCH Buffer Overflow
   windows/imap/mailenable_login                                  2006-12-11       great      MailEnable IMAPD (2.34/2.35) Login Request Buffer Overflow
   windows/imap/mailenable_status                                 2005-07-13       great      MailEnable IMAPD (1.54) STATUS Request Buffer Overflow
   windows/imap/mailenable_w3c_select                             2005-10-03       great      MailEnable IMAPD W3C Logging Buffer Overflow
   windows/imap/mdaemon_cram_md5                                  2004-11-12       great      Mdaemon 8.0.3 IMAPD CRAM-MD5 Authentication Overflow
   windows/imap/mdaemon_fetch                                     2008-03-13       great      MDaemon 9.6.4 IMAPD FETCH Buffer Overflow
   windows/imap/mercur_imap_select_overflow                       2006-03-17       average    Mercur v5.0 IMAP SP3 SELECT Buffer Overflow
   windows/imap/mercur_login                                      2006-03-17       average    Mercur Messaging 2005 IMAP Login Buffer Overflow
   windows/imap/mercury_login                                     2007-03-06       average    Mercury/32 <= 4.01b LOGIN Buffer Overflow
   windows/imap/mercury_rename                                    2004-11-29       average    Mercury/32 v4.01a IMAP RENAME Buffer Overflow
   windows/imap/novell_netmail_append                             2006-12-23       average    Novell NetMail <= 3.52d IMAP APPEND Buffer Overflow
   windows/imap/novell_netmail_auth                               2007-01-07       average    Novell NetMail <=3.52d IMAP AUTHENTICATE Buffer Overflow
   windows/imap/novell_netmail_status                             2005-11-18       average    Novell NetMail <= 3.52d IMAP STATUS Buffer Overflow
   windows/imap/novell_netmail_subscribe                          2006-12-23       average    Novell NetMail <= 3.52d IMAP SUBSCRIBE Buffer Overflow
   windows/isapi/ms00_094_pbserver                                2000-12-04       good       Microsoft IIS Phone Book Service Overflow
   windows/isapi/ms03_022_nsiislog_post                           2003-06-25       good       Microsoft IIS ISAPI nsiislog.dll ISAPI POST Overflow
   windows/isapi/ms03_051_fp30reg_chunked                         2003-11-11       good       Microsoft IIS ISAPI FrontPage fp30reg.dll Chunked Overflow
   windows/isapi/rsa_webagent_redirect                            2005-10-21       good       Microsoft IIS ISAPI RSA WebAgent Redirect Overflow
   windows/isapi/w3who_query                                      2004-12-06       good       Microsoft IIS ISAPI w3who.dll Query String Overflow
   windows/ldap/imail_thc                                         2004-02-17       average    IMail LDAP Service Buffer Overflow
   windows/ldap/pgp_keyserver7                                    2001-07-16       good       Network Associates PGP KeyServer 7 LDAP Buffer Overflow
   windows/license/calicclnt_getconfig                            2005-03-02       average    Computer Associates License Client GETCONFIG Overflow
   windows/license/calicserv_getconfig                            2005-03-02       normal     Computer Associates License Server GETCONFIG Overflow
   windows/license/flexnet_lmgrd_bof                              2012-03-23       normal     FlexNet License Server Manager lmgrd Buffer Overflow
   windows/license/sentinel_lm7_udp                               2005-03-07       average    SentinelLM UDP Buffer Overflow
   windows/local/adobe_sandbox_adobecollabsync                    2013-05-14       great      AdobeCollabSync Buffer Overflow Adobe Reader X Sandbox Bypass
   windows/local/always_install_elevated                          2010-03-18       average    Windows AlwaysInstallElevated MSI
   windows/local/ask                                              2012-01-03       excellent  Windows Escalate UAC Execute RunAs
   windows/local/bypassuac                                        2010-12-31       excellent  Windows Escalate UAC Protection Bypass
   windows/local/current_user_psexec                              1999-01-01       excellent  PsExec via Current User Token
   windows/local/ms10_092_schelevator                             2010-09-13       excellent  Windows Escalate Task Scheduler XML Privilege Escalation
   windows/local/ms11_080_afdjoinleaf                             2011-11-30       average    MS11-080 AfdJoinLeaf Privilege Escalation
   windows/local/novell_client_nicm                               2013-05-22       average    Novell Client 2 SP3 nicm.sys Local Privilege Escalation
   windows/local/novell_client_nwfs                               2008-06-26       average    Novell Client 4.91 SP4 nwfs.sys Local Privilege Escalation
   windows/local/payload_inject                                   2011-10-12       excellent  Windows Manage Memory Payload Injection
   windows/local/persistence                                      2011-10-19       excellent  Windows Manage Persistent Payload Installer
   windows/local/ppr_flatten_rec                                  2013-05-15       average    Windows EPATHOBJ::pprFlattenRec Local Privilege Escalation
   windows/local/s4u_persistence                                  2013-01-02       excellent  Windows Manage User Level Persistent Payload Installer
   windows/local/service_permissions                              2012-10-15       great      Windows Escalate Service Permissions Local Privilege Escalation
   windows/local/trusted_service_path                             2001-10-25       excellent  Windows Service Trusted Path Privilege Escalation
   windows/lotus/domino_http_accept_language                      2008-05-20       average    IBM Lotus Domino Web Server Accept-Language Stack Buffer Overflow
   windows/lotus/domino_icalendar_organizer                       2010-09-14       normal     IBM Lotus Domino iCalendar MAILTO Buffer Overflow
   windows/lotus/domino_sametime_stmux                            2008-05-21       average    IBM Lotus Domino Sametime STMux.exe Stack Buffer Overflow
   windows/lotus/lotusnotes_lzh                                   2011-05-24       normal     Lotus Notes 8.0.x - 8.5.2 FP2 - Autonomy Keyview (.lzh Attachment)
   windows/lpd/hummingbird_exceed                                 2005-05-27       average    Hummingbird Connectivity 10 SP5 LPD Buffer Overflow
   windows/lpd/niprint                                            2003-11-05       good       NIPrint LPD Request Overflow
   windows/lpd/saplpd                                             2008-02-04       good       SAP SAPLPD 6.28 Buffer Overflow
   windows/lpd/wincomlpd_admin                                    2008-02-04       good       WinComLPD <= 3.0.2 Buffer Overflow
   windows/misc/actfax_raw_server_bof                             2013-02-05       normal     ActFax 5.01 RAW Server Buffer Overflow
   windows/misc/agentxpp_receive_agentx                           2010-04-16       good       AgentX++ Master AgentX::receive_agentx Stack Buffer Overflow
   windows/misc/allmediaserver_bof                                2012-07-04       normal     ALLMediaServer 0.8 Buffer Overflow
   windows/misc/apple_quicktime_rtsp_response                     2007-11-23       normal     Apple QuickTime 7.3 RTSP Response Header Buffer Overflow
   windows/misc/asus_dpcproxy_overflow                            2008-03-21       average    Asus Dpcproxy Buffer Overflow
   windows/misc/avaya_winpmd_unihostrouter                        2011-05-23       normal     Avaya WinPMD UniteHostRouter Buffer Overflow
   windows/misc/avidphoneticindexer                               2011-11-29       normal     Avid Media Composer 5.5 - Avid Phonetic Indexer Buffer Overflow
   windows/misc/bakbone_netvault_heap                             2005-04-01       average    BakBone NetVault Remote Heap Overflow
   windows/misc/bcaaa_bof                                         2011-04-04       good       Blue Coat Authentication and Authorization Agent (BCAAA) 5 Buffer Overflow
   windows/misc/bigant_server                                     2008-04-15       average    BigAnt Server 2.2 Buffer Overflow
   windows/misc/bigant_server_250                                 2008-04-15       great      BigAnt Server 2.50 SP1 Buffer Overflow
   windows/misc/bigant_server_dupf_upload                         2013-01-09       excellent  BigAnt Server DUPF Command Arbitrary File Upload
   windows/misc/bigant_server_sch_dupf_bof                        2013-01-09       normal     BigAnt Server 2 SCH And DUPF Buffer Overflow
   windows/misc/bigant_server_usv                                 2009-12-29       great      BigAnt Server 2.52 USV Buffer Overflow
   windows/misc/bomberclone_overflow                              2006-02-16       average    Bomberclone 0.11.6 Buffer Overflow
   windows/misc/bopup_comm                                        2009-06-18       good       Bopup Communications Server Buffer Overflow
   windows/misc/borland_interbase                                 2007-07-24       average    Borland Interbase Create-Request Buffer Overflow
   windows/misc/borland_starteam                                  2008-04-02       average    Borland CaliberRM StarTeam Multicast Service Buffer Overflow
   windows/misc/citrix_streamprocess                              2011-01-20       good       Citrix Provisioning Services 5.6 streamprocess.exe Buffer Overflow
   windows/misc/citrix_streamprocess_data_msg                     2011-11-04       normal     Citrix Provisioning Services 5.6 SP1 Streamprocess Opcode 0x40020000 Buffer Overflow
   windows/misc/citrix_streamprocess_get_boot_record_request      2011-11-04       normal     Citrix Provisioning Services 5.6 SP1 Streamprocess Opcode 0x40020004 Buffer Overflow
   windows/misc/citrix_streamprocess_get_footer                   2011-11-04       normal     Citrix Provisioning Services 5.6 SP1 Streamprocess Opcode 0x40020002 Buffer Overflow
   windows/misc/citrix_streamprocess_get_objects                  2011-11-04       normal     Citrix Provisioning Services 5.6 SP1 Streamprocess Opcode 0x40020006 Buffer Overflow
   windows/misc/doubletake                                        2008-06-04       average    DoubleTake/HP StorageWorks Storage Mirroring Service Authentication Overflow
   windows/misc/eiqnetworks_esa                                   2006-07-24       average    eIQNetworks ESA License Manager LICMGR_ADDLICENSE Overflow
   windows/misc/eiqnetworks_esa_topology                          2006-07-25       average    eIQNetworks ESA Topology DELETEDEVICE Overflow
   windows/misc/enterasys_netsight_syslog_bof                     2011-12-19       normal     Enterasys NetSight nssyslogd.exe Buffer Overflow
   windows/misc/eureka_mail_err                                   2009-10-22       normal     Eureka Email 2.2q ERR Remote Buffer Overflow
   windows/misc/fb_cnct_group                                     2013-01-31       normal     Firebird Relational Database CNCT Group Number Buffer Overflow
   windows/misc/fb_isc_attach_database                            2007-10-03       average    Firebird Relational Database isc_attach_database() Buffer Overflow
   windows/misc/fb_isc_create_database                            2007-10-03       average    Firebird Relational Database isc_create_database() Buffer Overflow
   windows/misc/fb_svc_attach                                     2007-10-03       average    Firebird Relational Database SVC_attach() Buffer Overflow
   windows/misc/gimp_script_fu                                    2012-05-18       normal     GIMP script-fu Server Buffer Overflow
   windows/misc/hp_dataprotector_dtbclslogin                      2010-09-09       normal     HP Data Protector DtbClsLogin Buffer Overflow
   windows/misc/hp_dataprotector_new_folder                       2012-03-12       normal     HP Data Protector Create New Folder Buffer Overflow
   windows/misc/hp_imc_uam                                        2012-08-29       normal     HP Intelligent Management Center UAM Buffer Overflow
   windows/misc/hp_magentservice                                  2012-01-12       average    HP Diagnostics Server magentservice.exe Overflow
   windows/misc/hp_omniinet_1                                     2009-12-17       great      HP OmniInet.exe MSG_PROTOCOL Buffer Overflow
   windows/misc/hp_omniinet_2                                     2009-12-17       great      HP OmniInet.exe MSG_PROTOCOL Buffer Overflow
   windows/misc/hp_omniinet_3                                     2011-06-29       great      HP OmniInet.exe Opcode 27 Buffer Overflow
   windows/misc/hp_omniinet_4                                     2011-06-29       good       HP OmniInet.exe Opcode 20 Buffer Overflow
   windows/misc/hp_operations_agent_coda_34                       2012-07-09       normal     HP Operations Agent Opcode coda.exe 0x34 Buffer Overflow
   windows/misc/hp_operations_agent_coda_8c                       2012-07-09       normal     HP Operations Agent Opcode coda.exe 0x8c Buffer Overflow
   windows/misc/hp_ovtrace                                        2007-08-09       average    HP OpenView Operations OVTrace Buffer Overflow
   windows/misc/ib_isc_attach_database                            2007-10-03       good       Borland InterBase isc_attach_database() Buffer Overflow
   windows/misc/ib_isc_create_database                            2007-10-03       good       Borland InterBase isc_create_database() Buffer Overflow
   windows/misc/ib_svc_attach                                     2007-10-03       good       Borland InterBase SVC_attach() Buffer Overflow
   windows/misc/ibm_cognos_tm1admsd_bof                           2012-04-02       normal     IBM Cognos tm1admsd.exe Overflow
   windows/misc/ibm_director_cim_dllinject                        2009-03-10       excellent  IBM System Director Agent DLL Injection
   windows/misc/ibm_tsm_cad_ping                                  2009-11-04       good       IBM Tivoli Storage Manager Express CAD Service Buffer Overflow
   windows/misc/ibm_tsm_rca_dicugetidentify                       2009-11-04       great      IBM Tivoli Storage Manager Express RCA Service Buffer Overflow
   windows/misc/itunes_extm3u_bof                                 2012-06-21       normal     Apple iTunes 10 Extended M3U Stack Buffer Overflow
   windows/misc/landesk_aolnsrvr                                  2007-04-13       average    LANDesk Management Suite 8.7 Alert Service Buffer Overflow
   windows/misc/lianja_db_net                                     2013-05-22       normal     Lianja SQL 1.0.0RC5.1 db_netserver Stack Buffer Overflow
   windows/misc/mercury_phonebook                                 2005-12-19       average    Mercury/32 <= v4.01b PH Server Module Buffer Overflow
   windows/misc/mini_stream                                       2009-12-25       normal     Mini-Stream 3.0.1.1 Buffer Overflow
   windows/misc/mirc_privmsg_server                               2008-10-02       normal     mIRC <= 6.34 PRIVMSG Handling Stack Buffer Overflow
   windows/misc/ms07_064_sami                                     2007-12-11       normal     Microsoft DirectX DirectShow SAMI Buffer Overflow
   windows/misc/ms10_104_sharepoint                               2010-12-14       excellent  Microsoft Office SharePoint Server 2007 Remote Code Execution
   windows/misc/netcat110_nt                                      2004-12-27       great      Netcat v1.10 NT Stack Buffer Overflow
   windows/misc/nettransport                                      2010-01-02       normal     NetTransport Download Manager 2.90.510 Buffer Overflow
   windows/misc/poisonivy_bof                                     2012-06-24       normal     Poison Ivy 2.3.2 C&C Server Buffer Overflow
   windows/misc/poppeeper_date                                    2009-02-27       normal     POP Peeper v3.4 DATE Buffer Overflow
   windows/misc/poppeeper_uidl                                    2009-02-27       normal     POP Peeper v3.4 UIDL Buffer Overflow
   windows/misc/pxexploit                                         2011-08-05       excellent  PXE Exploit Server
   windows/misc/realtek_playlist                                  2008-12-16       great      Realtek Media Player Playlist Buffer Overflow
   windows/misc/sap_2005_license                                  2009-08-01       great      SAP Business One License Manager 2005 Buffer Overflow
   windows/misc/sap_netweaver_dispatcher                          2012-05-08       normal     SAP NetWeaver Dispatcher DiagTraceR3Info Buffer Overflow
   windows/misc/shixxnote_font                                    2004-10-04       great      ShixxNOTE 6.net Font Field Overflow
   windows/misc/splayer_content_type                              2011-05-04       normal     SPlayer 3.7 Content-Type Buffer Overflow
   windows/misc/stream_down_bof                                   2011-12-27       good       CoCSoft StreamDown 6.8.0 Buffer Overflow
   windows/misc/talkative_response                                2009-03-17       normal     Talkative IRC v0.4.4.16 Response Buffer Overflow
   windows/misc/tiny_identd_overflow                              2007-05-14       average    TinyIdentD 2.2 Stack Buffer Overflow
   windows/misc/trendmicro_cmdprocessor_addtask                   2011-12-07       good       TrendMicro Control Manger <= v5.5 CmdProcessor.exe Stack Buffer Overflow
   windows/misc/ufo_ai                                            2009-10-28       average    UFO: Alien Invasion IRC Client Buffer Overflow
   windows/misc/windows_rsh                                       2007-07-24       average    Windows RSH daemon Buffer Overflow
   windows/misc/wireshark_lua                                     2011-07-18       excellent  Wireshark console.lua Pre-Loading Script Execution
   windows/misc/wireshark_packet_dect                             2011-04-18       good       Wireshark <= 1.4.4 packet-dect.c Stack Buffer Overflow (remote)
   windows/mmsp/ms10_025_wmss_connect_funnel                      2010-04-13       great      Windows Media Services ConnectFunnel Stack Buffer Overflow
   windows/motorola/timbuktu_fileupload                           2008-05-10       excellent  Timbuktu Pro Directory Traversal/File Upload
   windows/mssql/lyris_listmanager_weak_pass                      2005-12-08       excellent  Lyris ListManager MSDE Weak sa Password
   windows/mssql/ms02_039_slammer                                 2002-07-24       good       Microsoft SQL Server Resolution Overflow
   windows/mssql/ms02_056_hello                                   2002-08-05       good       Microsoft SQL Server Hello Overflow
   windows/mssql/ms09_004_sp_replwritetovarbin                    2008-12-09       good       Microsoft SQL Server sp_replwritetovarbin Memory Corruption
   windows/mssql/ms09_004_sp_replwritetovarbin_sqli               2008-12-09       excellent  Microsoft SQL Server sp_replwritetovarbin Memory Corruption via SQL Injection
   windows/mssql/mssql_linkcrawler                                2000-01-01       great      Microsoft SQL Server Database Link Crawling Command Execution
   windows/mssql/mssql_payload                                    2000-05-30       excellent  Microsoft SQL Server Payload Execution
   windows/mssql/mssql_payload_sqli                               2000-05-30       excellent  Microsoft SQL Server Payload Execution via SQL Injection
   windows/mysql/mysql_mof                                        2012-12-01       excellent  Oracle MySQL for Microsoft Windows MOF Execution
   windows/mysql/mysql_payload                                    2009-01-16       excellent  Oracle MySQL for Microsoft Windows Payload Execution
   windows/mysql/mysql_yassl_hello                                2008-01-04       average    MySQL yaSSL SSL Hello Message Buffer Overflow
   windows/mysql/scrutinizer_upload_exec                          2012-07-27       excellent  Plixer Scrutinizer NetFlow and sFlow Analyzer 9 Default MySQL Credential
   windows/nfs/xlink_nfsd                                         2006-11-06       average    Omni-NFS Server Buffer Overflow
   windows/nntp/ms05_030_nntp                                     2005-06-14       normal     Microsoft Outlook Express NNTP Response Parsing Buffer Overflow
   windows/novell/file_reporter_fsfui_upload                      2012-11-16       great      NFR Agent FSFUI Record File Upload RCE
   windows/novell/groupwisemessenger_client                       2008-07-02       normal     Novell GroupWise Messenger Client Buffer Overflow
   windows/novell/netiq_pum_eval                                  2012-11-15       excellent  NetIQ Privileged User Manager 2.3.1 ldapagnt_eval() Remote Perl Code Execution
   windows/novell/nmap_stor                                       2006-12-23       average    Novell NetMail <= 3.52d NMAP STOR Buffer Overflow
   windows/novell/zenworks_desktop_agent                          2005-05-19       good       Novell ZENworks 6.5 Desktop/Server Management Overflow
   windows/novell/zenworks_preboot_op21_bof                       2010-03-30       normal     Novell ZENworks Configuration Management Preboot Service 0x21 Buffer Overflow
   windows/novell/zenworks_preboot_op4c_bof                       2012-02-22       normal     Novell ZENworks Configuration Management Preboot Service 0x4c Buffer Overflow
   windows/novell/zenworks_preboot_op6_bof                        2010-03-30       normal     Novell ZENworks Configuration Management Preboot Service 0x06 Buffer Overflow
   windows/novell/zenworks_preboot_op6c_bof                       2012-02-22       normal     Novell ZENworks Configuration Management Preboot Service 0x6c Buffer Overflow
   windows/oracle/client_system_analyzer_upload                   2011-01-18       excellent  Oracle Database Client System Analyzer Arbitrary File Upload
   windows/oracle/extjob                                          2007-01-01       excellent  Oracle Job Scheduler Named Pipe Command Execution
   windows/oracle/osb_ndmp_auth                                   2009-01-14       good       Oracle Secure Backup NDMP_CONNECT_CLIENT_AUTH Buffer Overflow
   windows/oracle/tns_arguments                                   2001-06-28       good       Oracle 8i TNS Listener (ARGUMENTS) Buffer Overflow
   windows/oracle/tns_auth_sesskey                                2009-10-20       great      Oracle 10gR2 TNS Listener AUTH_SESSKEY Buffer Overflow
   windows/oracle/tns_service_name                                2002-05-27       good       Oracle 8i TNS Listener SERVICE_NAME Buffer Overflow
   windows/pop3/seattlelab_pass                                   2003-05-07       great      Seattle Lab Mail 5.5 POP3 Buffer Overflow
   windows/postgres/postgres_payload                              2009-04-10       excellent  PostgreSQL for Microsoft Windows Payload Execution
   windows/proxy/bluecoat_winproxy_host                           2005-01-05       great      Blue Coat WinProxy Host Header Overflow
   windows/proxy/ccproxy_telnet_ping                              2004-11-11       average    CCProxy <= v6.2 Telnet Proxy Ping Overflow
   windows/proxy/proxypro_http_get                                2004-02-23       great      Proxy-Pro Professional GateKeeper 4.7 GET Request Overflow
   windows/proxy/qbik_wingate_wwwproxy                            2006-06-07       good       Qbik WinGate WWW Proxy Server URL Processing Overflow
   windows/scada/citect_scada_odbc                                2008-06-11       normal     CitectSCADA/CitectFacilities ODBC Buffer Overflow
   windows/scada/codesys_gateway_server_traversal                 2013-02-02       excellent  SCADA 3S CoDeSys Gateway Server Directory Traversal
   windows/scada/codesys_web_server                               2011-12-02       normal     SCADA 3S CoDeSys CmpWebServer <= v3.4 SP4 Patch 2 Stack Buffer Overflow
   windows/scada/daq_factory_bof                                  2011-09-13       good       DaqFactory HMI NETB Request Overflow
   windows/scada/factorylink_csservice                            2011-03-25       normal     Siemens FactoryLink 8 CSService Logging Path Param Buffer Overflow
   windows/scada/factorylink_vrn_09                               2011-03-21       average    Siemens FactoryLink vrn.exe Opcode 9 Buffer Overflow
   windows/scada/iconics_genbroker                                2011-03-21       good       Iconics GENESIS32 Integer overflow version 9.21.201.01
   windows/scada/iconics_webhmi_setactivexguid                    2011-05-05       good       ICONICS WebHMI ActiveX Buffer Overflow
   windows/scada/igss9_igssdataserver_listall                     2011-03-24       good       7-Technologies IGSS <= v9.00.00 b11063 IGSSdataServer.exe Stack Buffer Overflow
   windows/scada/igss9_igssdataserver_rename                      2011-03-24       normal     7-Technologies IGSS 9 IGSSdataServer .RMS Rename Buffer Overflow
   windows/scada/igss9_misc                                       2011-03-24       excellent  7-Technologies IGSS 9 Data Server/Collector Packet Handling Vulnerabilities
   windows/scada/indusoft_webstudio_exec                          2011-11-04       excellent  InduSoft Web Studio Arbitrary Upload Remote Code Execution
   windows/scada/moxa_mdmtool                                     2010-10-20       great      MOXA Device Manager Tool 2.1 Buffer Overflow
   windows/scada/procyon_core_server                              2011-09-08       normal     Procyon Core Server HMI <= v1.13 Coreservice.exe Stack Buffer Overflow
   windows/scada/realwin                                          2008-09-26       great      DATAC RealWin SCADA Server Buffer Overflow
   windows/scada/realwin_on_fc_binfile_a                          2011-03-21       great      DATAC RealWin SCADA Server 2 On_FC_CONNECT_FCS_a_FILE Buffer Overflow
   windows/scada/realwin_on_fcs_login                             2011-03-21       great      RealWin SCADA Server DATAC Login Buffer Overflow
   windows/scada/realwin_scpc_initialize                          2010-10-15       great      DATAC RealWin SCADA Server SCPC_INITIALIZE Buffer Overflow
   windows/scada/realwin_scpc_initialize_rf                       2010-10-15       great      DATAC RealWin SCADA Server SCPC_INITIALIZE_RF Buffer Overflow
   windows/scada/realwin_scpc_txtevent                            2010-11-18       great      DATAC RealWin SCADA Server SCPC_TXTEVENT Buffer Overflow
   windows/scada/scadapro_cmdexe                                  2011-09-16       excellent  Measuresoft ScadaPro <= 4.0.0 Remote Command Execution
   windows/scada/sunway_force_control_netdbsrv                    2011-09-22       great      Sunway Forcecontrol SNMP NetDBServer.exe Opcode 0x57
   windows/scada/winlog_runtime                                   2011-01-13       great      Sielco Sistemi Winlog Buffer Overflow
   windows/scada/winlog_runtime_2                                 2012-06-04       normal     Sielco Sistemi Winlog Buffer Overflow 2.07.14 - 2.07.16
   windows/sip/aim_triton_cseq                                    2006-07-10       great      AIM Triton 1.0.4 CSeq Buffer Overflow
   windows/sip/sipxezphone_cseq                                   2006-07-10       great      SIPfoundry sipXezPhone 0.35a CSeq Field Overflow
   windows/sip/sipxphone_cseq                                     2006-07-10       great      SIPfoundry sipXphone 2.6.0.27 CSeq Buffer Overflow
   windows/smb/ms03_049_netapi                                    2003-11-11       good       Microsoft Workstation Service NetAddAlternateComputerName Overflow
   windows/smb/ms04_007_killbill                                  2004-02-10       low        Microsoft ASN.1 Library Bitstring Heap Overflow
   windows/smb/ms04_011_lsass                                     2004-04-13       good       Microsoft LSASS Service DsRolerUpgradeDownlevelServer Overflow
   windows/smb/ms04_031_netdde                                    2004-10-12       good       Microsoft NetDDE Service Overflow
   windows/smb/ms05_039_pnp                                       2005-08-09       good       Microsoft Plug and Play Service Overflow
   windows/smb/ms06_025_rasmans_reg                               2006-06-13       good       Microsoft RRAS Service RASMAN Registry Overflow
   windows/smb/ms06_025_rras                                      2006-06-13       average    Microsoft RRAS Service Overflow
   windows/smb/ms06_040_netapi                                    2006-08-08       good       Microsoft Server Service NetpwPathCanonicalize Overflow
   windows/smb/ms06_066_nwapi                                     2006-11-14       good       Microsoft Services MS06-066 nwapi32.dll Module Exploit
   windows/smb/ms06_066_nwwks                                     2006-11-14       good       Microsoft Services MS06-066 nwwks.dll Module Exploit
   windows/smb/ms06_070_wkssvc                                    2006-11-14       manual     Microsoft Workstation Service NetpManageIPCConnect Overflow
   windows/smb/ms07_029_msdns_zonename                            2007-04-12       manual     Microsoft DNS RPC Service extractQuotedChar() Overflow (SMB)
   windows/smb/ms08_067_netapi                                    2008-10-28       great      Microsoft Server Service Relative Path Stack Corruption
   windows/smb/ms09_050_smb2_negotiate_func_index                 2009-09-07       good       Microsoft SRV2.SYS SMB Negotiate ProcessID Function Table Dereference
   windows/smb/ms10_061_spoolss                                   2010-09-14       excellent  Microsoft Print Spooler Service Impersonation Vulnerability
   windows/smb/netidentity_xtierrpcpipe                           2009-04-06       great      Novell NetIdentity Agent XTIERRPCPIPE Named Pipe Buffer Overflow
   windows/smb/psexec                                             1999-01-01       manual     Microsoft Windows Authenticated User Code Execution
   windows/smb/psexec_psh                                         1999-01-01       manual     Microsoft Windows Authenticated Powershell Command Execution
   windows/smb/smb_relay                                          2001-03-31       excellent  Microsoft Windows SMB Relay Code Execution
   windows/smb/timbuktu_plughntcommand_bof                        2009-06-25       great      Timbuktu <= 8.6.6 PlughNTCommand Named Pipe Buffer Overflow
   windows/smtp/mailcarrier_smtp_ehlo                             2004-10-26       good       TABS MailCarrier v2.51 SMTP EHLO Overflow
   windows/smtp/mercury_cram_md5                                  2007-08-18       great      Mercury Mail SMTP AUTH CRAM-MD5 Buffer Overflow
   windows/smtp/ms03_046_exchange2000_xexch50                     2003-10-15       good       MS03-046 Exchange 2000 XEXCH50 Heap Overflow
   windows/smtp/njstar_smtp_bof                                   2011-10-31       normal     NJStar Communicator 3.00 MiniSMTP Buffer Overflow
   windows/smtp/wmailserver                                       2005-07-11       average    SoftiaCom WMailserver 1.0 Buffer Overflow
   windows/smtp/ypops_overflow1                                   2004-09-27       average    YPOPS 0.6 Buffer Overflow
   windows/ssh/freeftpd_key_exchange                              2006-05-12       average    FreeFTPd 1.0.10 Key Exchange Algorithm String Buffer Overflow
   windows/ssh/freesshd_authbypass                                2010-08-11       excellent  Freesshd Authentication Bypass
   windows/ssh/freesshd_key_exchange                              2006-05-12       average    FreeSSHd 1.0.9 Key Exchange Algorithm String Buffer Overflow
   windows/ssh/putty_msg_debug                                    2002-12-16       normal     PuTTy.exe <= v0.53 Buffer Overflow
   windows/ssh/securecrt_ssh1                                     2002-07-23       average    SecureCRT <= 4.0 Beta 2 SSH1 Buffer Overflow
   windows/ssh/sysax_ssh_username                                 2012-02-27       normal     Sysax 5.53 SSH Username Buffer Overflow
   windows/ssl/ms04_011_pct                                       2004-04-13       average    Microsoft Private Communications Transport Overflow
   windows/telnet/gamsoft_telsrv_username                         2000-07-17       average    GAMSoft TelSrv 1.5 Username Buffer Overflow
   windows/telnet/goodtech_telnet                                 2005-03-15       average    GoodTech Telnet Server <= 5.0.6 Buffer Overflow
   windows/tftp/attftp_long_filename                              2006-11-27       average    Allied Telesyn TFTP Server 1.9 Long Filename Overflow
   windows/tftp/distinct_tftp_traversal                           2012-04-08       excellent  Distinct TFTP 3.10 Writable Directory Traversal Execution
   windows/tftp/dlink_long_filename                               2007-03-12       good       D-Link TFTP 1.0 Long Filename Buffer Overflow
   windows/tftp/futuresoft_transfermode                           2005-05-31       average    FutureSoft TFTP Server 2000 Transfer-Mode Overflow
   windows/tftp/netdecision_tftp_traversal                        2009-05-16       excellent  NetDecision 4.2 TFTP Writable Directory Traversal Execution
   windows/tftp/opentftp_error_code                               2008-07-05       average    OpenTFTP SP 1.4 Error Packet Overflow
   windows/tftp/quick_tftp_pro_mode                               2008-03-27       good       Quick FTP Pro 2.1 Transfer-Mode Overflow
   windows/tftp/tftpd32_long_filename                             2002-11-19       average    TFTPD32 <= 2.21 Long Filename Buffer Overflow
   windows/tftp/tftpdwin_long_filename                            2006-09-21       great      TFTPDWIN v0.4.2 Long Filename Buffer Overflow
   windows/tftp/tftpserver_wrq_bof                                2008-03-26       normal     TFTP Server for Windows 1.4 ST WRQ Buffer Overflow
   windows/tftp/threectftpsvc_long_mode                           2006-11-27       great      3CTftpSvc TFTP Long Mode Buffer Overflow
   windows/unicenter/cam_log_security                             2005-08-22       great      CA CAM log_security() Stack Buffer Overflow (Win32)
   windows/vnc/realvnc_client                                     2001-01-29       normal     RealVNC 3.3.7 Client Buffer Overflow
   windows/vnc/ultravnc_client                                    2006-04-04       normal     UltraVNC 1.0.1 Client Buffer Overflow
   windows/vnc/ultravnc_viewer_bof                                2008-02-06       normal     UltraVNC 1.0.2 Client (vncviewer.exe) Buffer Overflow
   windows/vnc/winvnc_http_get                                    2001-01-29       average    WinVNC Web Server <= v3.3.3r7 GET Overflow
   windows/vpn/safenet_ike_11                                     2009-06-01       average    SafeNet SoftRemote IKE Service Buffer Overflow
   windows/winrm/winrm_script_exec                                2012-11-01       manual     WinRM Script Exec Remote Code Execution
   windows/wins/ms04_045_wins                                     2004-12-14       great      Microsoft WINS Service Memory Overwrite
'''

ms_spreadsheet_xslt_str = '''
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="text" encoding="utf-8" />

  <xsl:param name="delim" select="'|'" />
  <xsl:param name="quote" select="''" />
  <xsl:param name="break" select="'&#xA;'" />

<xsl:template match="/">
    <xsl:apply-templates select="xworksheet" />
</xsl:template>

<xsl:template match="xworksheet">
    <xsl:apply-templates select="xsheetData"/>
</xsl:template>

<xsl:template match="xsheetData">
    <xsl:apply-templates select="xrow"/>
</xsl:template>

<xsl:template match="xrow">
    <xsl:apply-templates select="xc"/>
    <xsl:if test="following-sibling::*">
        <xsl:value-of select="$break" />
    </xsl:if>
</xsl:template>

<xsl:template match="xc">
    <xsl:value-of select="concat($quote, normalize-space(.), $quote)" />
    <xsl:if test="following-sibling::*">
        <xsl:value-of select="$delim" />
    </xsl:if>
</xsl:template>
</xsl:stylesheet>
'''

kb_nos = {
        '977165': 'MS10_015 Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (kitrap0d - meterpreter "getsystem")',
        '828749': 'MS03_049 Microsoft Workstation Service NetAddAlternateComputerName Overflow (netapi)     ',
        '828028': 'MS04_007 Microsoft ASN.1 Library Bitstring Heap Overflow (killbill)      ',
        '835732': 'MS04_011 Microsoft LSASS Service DsRolerUpgradeDownlevelServer Overflow (lsass)    ',
        '841533': 'MS04_031 Microsoft NetDDE Service Overflow (netdde)',
        '899588': 'MS05_039 Microsoft Plug and Play Service Overflow (pnp)',
        '911280': 'MS06_025 Microsoft RRAS Service RASMAN Registry Overflow (rasmans_reg)',
        '911280': 'MS06_025 Microsoft RRAS Service Overflow (rras)',
        '921883': 'MS06_040 Microsoft Server Service NetpwPathCanonicalize Overflow (netapi)',
        '923980': 'MS06_066 Microsoft Services MS06-066 nwapi32.dll (nwapi)',
        '923980': 'MS06_066 Microsoft Services MS06-066 nwwks.dll (nwwks)',
        '924270': 'MS06_070 Microsoft Workstation Service NetpManageIPCConnect Overflow (wkssvc)',
        '935966': 'MS07_029 Microsoft DNS RPC Service extractQuotedChar() Overflow (SMB) (msdns_zonename)',
        '958644': 'MS08_067 Microsoft Server Service Relative Path Stack Corruption (netapi)',
        '975517': 'MS09_050 Microsoft SRV2.SYS SMB Negotiate ProcessID Function Table Dereference (smb2_negotiate_func_index)',
        '823980': 'MS03_026 Microsoft RPC DCOM Interface Overflow',
        '892944': 'MS05_017 Microsoft Message Queueing Service Path Overflow',
        '937894': 'MS07_065 Microsoft Message Queueing Service DNS Name Path Overflow'
}

reg_paths = (
    'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services',
#    'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell',
    'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit',
    'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce',
#    'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices',
    'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce',
#    'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices',
#    'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce',
#    'HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows',
)

# We don't care if some users / groups hold dangerous permission because they're trusted
# These have fully qualified names:
trusted_principals_fq = [
    "BUILTIN\\Administrators",
    "NT SERVICE\\TrustedInstaller",
    "NT AUTHORITY\\SYSTEM"
]

# We don't care if members of these groups hold dangerous permission because they're trusted
# These have names without a domain:
#trusted_principals = (
    #"Administrators",
    #"Domain Admins",
    #"Enterprise Admins",
#)
trusted_principals = []

eventlog_key_hklm = 'SYSTEM\CurrentControlSet\Services\Eventlog'

# Windows privileges from 
windows_privileges = (
        "SeAssignPrimaryTokenPrivilege",
        "SeBackupPrivilege",
        "SeCreatePagefilePrivilege",
        "SeCreateTokenPrivilege",
        "SeDebugPrivilege",
        "SeEnableDelegationPrivilege",
        "SeLoadDriverPrivilege",
        "SeMachineAccountPrivilege",
        "SeManageVolumePrivilege",
        "SeRelabelPrivilege",
        "SeRestorePrivilege",
        "SeShutdownPrivilege",
        "SeSyncAgentPrivilege",
        "SeTakeOwnershipPrivilege",
        "SeTcbPrivilege",
        "SeTrustedCredManAccessPrivilege",
        "SeSecurityPrivilege",
        "SeRemoteShutdownPrivilege",
        "SeProfileSingleProcessPrivilege",
        "SeAuditPrivilege",
        "SeIncreaseBasePriorityPrivilege",
        "SeIncreaseWorkingSetPrivilege",
        "SeIncreaseQuotaPrivilege",
        "SeLockMemoryPrivilege",
        "SeSystemEnvironmentPrivilege",
        "SeChangeNotifyPrivilege",
        "SeCreateGlobalPrivilege",
        "SeCreatePermanentPrivilege",
        "SeCreateSymbolicLinkPrivilege",
        "SeImpersonatePrivilege",
        "SeSystemProfilePrivilege",
        "SeSystemtimePrivilege",
        "SeTimeZonePrivilege",
        "SeUndockPrivilege",
        "SeUnsolicitedInputPrivilege",
        "SeBatchLogonRight",
        "SeDenyBatchLogonRight",
        "SeDenyInteractiveLogonRight",
        "SeDenyNetworkLogonRight",
        "SeDenyRemoteInteractiveLogonRight",
        "SeDenyServiceLogonRight",
        "SeInteractiveLogonRight",
        "SeNetworkLogonRight",
        "SeRemoteInteractiveLogonRight",
        "SeServiceLogonRight"
)

share_types = (
    "STYPE_IPC",
    "STYPE_DISKTREE",
    "STYPE_PRINTQ",
    "STYPE_DEVICE",
)

sv_types = (
        "SV_TYPE_WORKSTATION",
        "SV_TYPE_SERVER",
        "SV_TYPE_SQLSERVER",
        "SV_TYPE_DOMAIN_CTRL",
        "SV_TYPE_DOMAIN_BAKCTRL",
        "SV_TYPE_TIME_SOURCE",
        "SV_TYPE_AFP",
        "SV_TYPE_NOVELL",
        "SV_TYPE_DOMAIN_MEMBER",
        "SV_TYPE_PRINTQ_SERVER",
        "SV_TYPE_DIALIN_SERVER",
        "SV_TYPE_XENIX_SERVER",
        "SV_TYPE_NT",
        "SV_TYPE_WFW",
        "SV_TYPE_SERVER_MFPN",
        "SV_TYPE_SERVER_NT",
        "SV_TYPE_POTENTIAL_BROWSER",
        "SV_TYPE_BACKUP_BROWSER",
        "SV_TYPE_MASTER_BROWSER",
        "SV_TYPE_DOMAIN_MASTER",
        "SV_TYPE_SERVER_OSF",
        "SV_TYPE_SERVER_VMS",
        "SV_TYPE_WINDOWS",
        "SV_TYPE_DFS",
        "SV_TYPE_CLUSTER_NT",
        "SV_TYPE_TERMINALSERVER",  # missing from win32netcon.py
        #"SV_TYPE_CLUSTER_VS_NT",  # missing from win32netcon.py
        "SV_TYPE_DCE",
        "SV_TYPE_ALTERNATE_XPORT",
        "SV_TYPE_LOCAL_LIST_ONLY",
        "SV_TYPE_DOMAIN_ENUM"
)

win32netcon.SV_TYPE_TERMINALSERVER = 0x2000000 
win32netcon.UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x000080
win32netcon.UF_TRUSTED_FOR_DELEGATION = 0x080000
win32netcon.UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x01000000

sid_is_group_type = {
    ntsecuritycon.SidTypeUser: 0,
    ntsecuritycon.SidTypeGroup: 1,
    ntsecuritycon.SidTypeDomain: 0,
    ntsecuritycon.SidTypeAlias: 1,
    ntsecuritycon.SidTypeWellKnownGroup: 1,
    ntsecuritycon.SidTypeDeletedAccount: 0,
    ntsecuritycon.SidTypeInvalid: 0,
    ntsecuritycon.SidTypeUnknown: 0,
    ntsecuritycon.SidTypeComputer: 0,
    ntsecuritycon.SidTypeLabel: 0
}

sid_type = {
    ntsecuritycon.SidTypeUser: "user",
    ntsecuritycon.SidTypeGroup: "group",
    ntsecuritycon.SidTypeDomain: "domain",
    ntsecuritycon.SidTypeAlias: "alias",
    ntsecuritycon.SidTypeWellKnownGroup: "wellknowngroup",
    ntsecuritycon.SidTypeDeletedAccount: "deletedaccount",
    ntsecuritycon.SidTypeInvalid: "invalid",
    ntsecuritycon.SidTypeUnknown: "unknown",
    ntsecuritycon.SidTypeComputer: "computer",
    ntsecuritycon.SidTypeLabel: "label"
}

dangerous_perms_write = {
    # http://www.tek-tips.com/faqs.cfm?fid
    'share': {
        ntsecuritycon: (
            "FILE_READ_DATA",
            "FILE_WRITE_DATA",
            "FILE_APPEND_DATA",
            "FILE_READ_EA",
            "FILE_WRITE_EA",
            "FILE_EXECUTE",
            "FILE_READ_ATTRIBUTES",
            "FILE_WRITE_ATTRIBUTES",
            "DELETE",
            "READ_CONTROL",
            "WRITE_DAC",
            "WRITE_OWNER",
            "SYNCHRONIZE",
        )
    },
    'file': {
        ntsecuritycon: (
            #"FILE_READ_DATA",
            "FILE_WRITE_DATA",
            "FILE_APPEND_DATA",  # probably not dangerous for .exe files, but could be dangerous for .bat (or other script) files
            #"FILE_READ_EA",
            #"FILE_WRITE_EA",
            #"FILE_EXECUTE",
            #"FILE_READ_ATTRIBUTES",
            #"FILE_WRITE_ATTRIBUTES",
            "DELETE",
            #"READ_CONTROL",
            "WRITE_DAC",
            "WRITE_OWNER",
            #"SYNCHRONIZE",
        )
    },
    # http://msdn.microsoft.com/en-us/library/ms724878(VS.85).aspx
    # KEY_ALL_ACCESS: STANDARD_RIGHTS_REQUIRED KEY_QUERY_VALUE KEY_SET_VALUE KEY_CREATE_SUB_KEY KEY_ENUMERATE_SUB_KEYS KEY_NOTIFY KEY_CREATE_LINK
    # KEY_CREATE_LINK (0x0020) Reserved for system use.
    # KEY_CREATE_SUB_KEY (0x0004)    Required to create a subkey of a registry key.
    # KEY_ENUMERATE_SUB_KEYS (0x0008)    Required to enumerate the subkeys of a registry key.
    # KEY_EXECUTE (0x20019)    Equivalent to KEY_READ.
    # KEY_NOTIFY (0x0010)    Required to request change notifications for a registry key or for subkeys of a registry key.
    # KEY_QUERY_VALUE (0x0001)    Required to query the values of a registry key.
    # KEY_READ (0x20019)    Combines the STANDARD_RIGHTS_READ, KEY_QUERY_VALUE, KEY_ENUMERATE_SUB_KEYS, and KEY_NOTIFY values.
    # KEY_SET_VALUE (0x0002)    Required to create, delete, or set a registry value.
    # KEY_WOW64_32KEY (0x0200)    Indicates that an application on 64-bit Windows should operate on the 32-bit registry view. For more information, see Accessing an Alternate Registry View.    This flag must be combined using the OR operator with the other flags in this table that either query or access registry values.
    # Windows 2000:  This flag is not supported.
    # KEY_WOW64_64KEY (0x0100)    Indicates that an application on 64-bit Windows should operate on the 64-bit registry view. For more information, see Accessing an Alternate Registry View.
    # This flag must be combined using the OR operator with the other flags in this table that either query or access registry values.
    # Windows 2000:  This flag is not supported.
    # KEY_WRITE (0x20006)    Combines the STANDARD_RIGHTS_WRITE, KEY_SET_VALUE, and KEY_CREATE_SUB_KEY access rights.
    # "STANDARD_RIGHTS_REQUIRED",
    # "STANDARD_RIGHTS_WRITE",
    # "STANDARD_RIGHTS_READ",
    # "DELETE",
    # "READ_CONTROL",
    # "WRITE_DAC",
    #"WRITE_OWNER",
    'regkey': {
        _winreg: (
            #"KEY_ALL_ACCESS",  # Combines the STANDARD_RIGHTS_REQUIRED, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_CREATE_SUB_KEY, KEY_ENUMERATE_SUB_KEYS, KEY_NOTIFY, and KEY_CREATE_LINK access rights.
            #"KEY_QUERY_VALUE", # GUI "Query Value"
            "KEY_SET_VALUE",  # GUI "Set Value".  Required to create, delete, or set a registry value.
            "KEY_CREATE_LINK",  # GUI "Create Link".  Reserved for system use.
            "KEY_CREATE_SUB_KEY",  # GUI "Create subkey"
            # "KEY_ENUMERATE_SUB_KEYS",  # GUI "Create subkeys"
            # "KEY_NOTIFY", # GUI "Notify"
            #"KEY_EXECUTE", # same as KEY_READ
            #"KEY_READ",
            #"KEY_WOW64_32KEY",
            #"KEY_WOW64_64KEY",
            # "KEY_WRITE", # Combines the STANDARD_RIGHTS_WRITE, KEY_SET_VALUE, and KEY_CREATE_SUB_KEY access rights.
        ),
        ntsecuritycon: (
            "DELETE",  # GUI "Delete"
            # "READ_CONTROL", # GUI "Read Control" - read security descriptor
            "WRITE_DAC",  # GUI "Write DAC"
            "WRITE_OWNER",  # GUI "Write Owner"
            #"STANDARD_RIGHTS_REQUIRED",
            #"STANDARD_RIGHTS_WRITE",
            #"STANDARD_RIGHTS_READ",
        )
    },
    'directory': {
        ntsecuritycon: (
            #"FILE_LIST_DIRECTORY",
            "FILE_ADD_FILE",
            "FILE_ADD_SUBDIRECTORY",
            #"FILE_READ_EA",
            "FILE_WRITE_EA",
            #"FILE_TRAVERSE",
            "FILE_DELETE_CHILD",
            #"FILE_READ_ATTRIBUTES",
            "FILE_WRITE_ATTRIBUTES",
            "DELETE",
            #"READ_CONTROL",
            "WRITE_DAC",
            "WRITE_OWNER",
            #"SYNCHRONIZE",
        )
    },
    'service_manager': {
        # For service manager
        # http://msdn.microsoft.com/en-us/library/ms685981(VS.85).aspx
        # SC_MANAGER_ALL_ACCESS (0xF003F)    Includes STANDARD_RIGHTS_REQUIRED, in addition to all access rights in this table.
        # SC_MANAGER_CREATE_SERVICE (0x0002)    Required to call the CreateService function to create a service object and add it to the database.
        # SC_MANAGER_CONNECT (0x0001)    Required to connect to the service control manager.
        # SC_MANAGER_ENUMERATE_SERVICE (0x0004)    Required to call the EnumServicesStatusEx function to list the services that are in the database.
        # SC_MANAGER_LOCK (0x0008)    Required to call the LockServiceDatabase function to acquire a lock on the database.
        # SC_MANAGER_MODIFY_BOOT_CONFIG (0x0020)    Required to call the NotifyBootConfigStatus function.
        # SC_MANAGER_QUERY_LOCK_STATUS (0x0010)Required to call the  QueryServiceLockStatus function to retrieve the lock status information for the database.
        win32service: (
            "SC_MANAGER_ALL_ACCESS",
            "SC_MANAGER_CREATE_SERVICE",
            "SC_MANAGER_CONNECT",
            "SC_MANAGER_ENUMERATE_SERVICE",
            "SC_MANAGER_LOCK",
            "SC_MANAGER_MODIFY_BOOT_CONFIG",
            "SC_MANAGER_QUERY_LOCK_STATUS",
        )
    },
    # http://msdn.microsoft.com/en-gb/library/windows/desktop/ms686769(v=vs.85).aspx
    'thread': {
        win32con: (
            "THREAD_TERMINATE",
            #"THREAD_SUSPEND_RESUME",
            #"THREAD_GET_CONTEXT",
            "THREAD_SET_CONTEXT",
            "THREAD_SET_INFORMATION",
            #"THREAD_QUERY_INFORMATION",
            "THREAD_SET_THREAD_TOKEN",
            "THREAD_IMPERSONATE",
            "THREAD_DIRECT_IMPERSONATION",
            #"THREAD_ALL_ACCESS",
            #"THREAD_QUERY_LIMITED_INFORMATION", TODO
            # "THREAD_SET_LIMITED_INFORMATION" TODO
        ),
        ntsecuritycon: (
            "DELETE",
            #"READ_CONTROL",
            "WRITE_DAC",
            "WRITE_OWNER",
            #"SYNCHRONIZE",
        )
    },
    # http://msdn.microsoft.com/en-us/library/ms684880(v=vs.85).aspx
    'process': {
        win32con: (
            "PROCESS_TERMINATE",
            "PROCESS_CREATE_THREAD",
            "PROCESS_VM_OPERATION",
            "PROCESS_VM_READ",
            "PROCESS_VM_WRITE",
            "PROCESS_DUP_HANDLE",
            "PROCESS_CREATE_PROCESS",
            "PROCESS_SET_QUOTA",
            "PROCESS_SET_INFORMATION",
            #"PROCESS_QUERY_INFORMATION",
            #"PROCESS_QUERY_LIMITED_INFORMATION",
            "PROCESS_SUSPEND_RESUME",
            #"PROCESS_ALL_ACCESS"
        ),
        ntsecuritycon: (
            "DELETE",
            #"READ_CONTROL",
            "WRITE_DAC",
            "WRITE_OWNER",
            #"SYNCHRONIZE",
            #"STANDARD_RIGHTS_REQUIRED",
            #"STANDARD_RIGHTS_READ",
            #"STANDARD_RIGHTS_WRITE",
            #"STANDARD_RIGHTS_EXECUTE",
            #"STANDARD_RIGHTS_ALL",
            #"SPECIFIC_RIGHTS_ALL",
            #"ACCESS_SYSTEM_SECURITY",
            #"MAXIMUM_ALLOWED",
            #"GENERIC_READ",
            #"GENERIC_WRITE",
            #"GENERIC_EXECUTE",
            #"GENERIC_ALL"
        )
    },
    'token': {
        win32con: (
            "TOKEN_ADJUST_DEFAULT",
            "TOKEN_ADJUST_GROUPS",
            "TOKEN_ADJUST_PRIVILEGES",
            #"TOKEN_ADJUST_SESSIONID", TODO what's the number for this?
            "TOKEN_ASSIGN_PRIMARY",
            "TOKEN_DUPLICATE",
            "TOKEN_EXECUTE",
            "TOKEN_IMPERSONATE",
#            "TOKEN_QUERY",
 #           "TOKEN_QUERY_SOURCE",
  #          "TOKEN_READ",
            "TOKEN_WRITE",
            "TOKEN_ALL_ACCESS"
        ),
        ntsecuritycon: (
            "DELETE",
   #         "READ_CONTROL",
            "WRITE_DAC",
            "WRITE_OWNER",
            #"SYNCHRONIZE",
        )
    },
    'service': {
        # For services:
        # http://msdn.microsoft.com/en-us/library/ms685981(VS.85).aspx
        # SERVICE_ALL_ACCESS (0xF01FF)    Includes STANDARD_RIGHTS_REQUIRED in addition to all access rights in this table.
        # SERVICE_CHANGE_CONFIG (0x0002)    Required to call the ChangeServiceConfig or ChangeServiceConfig2 function to change the service configuration. Because     this grants the caller the right to change the executable file that the system runs, it should be granted only to administrators.
        # SERVICE_ENUMERATE_DEPENDENTS (0x0008)    Required to call the EnumDependentServices function to enumerate all the services dependent on the service.
        # SERVICE_INTERROGATE (0x0080)    Required to call the ControlService function to ask the service to report its status immediately.
        # SERVICE_PAUSE_CONTINUE (0x0040)    Required to call the ControlService function to pause or continue the service.
        # SERVICE_QUERY_CONFIG (0x0001)    Required to call the QueryServiceConfig and QueryServiceConfig2 functions to query the service configuration.
        # SERVICE_QUERY_STATUS (0x0004)    Required to call the QueryServiceStatusEx function to ask the service control manager about the status of the service.
        # SERVICE_START (0x0010)    Required to call the StartService function to start the service.
        # SERVICE_STOP (0x0020)    Required to call the ControlService function to stop the service.
        # SERVICE_USER_DEFINED_CONTROL(0x0100)    Required to call the ControlService function to specify a user-defined control code.
        win32service: (
            # "SERVICE_INTERROGATE",
            # "SERVICE_QUERY_STATUS",
            # "SERVICE_ENUMERATE_DEPENDENTS",
            "SERVICE_ALL_ACCESS",
            "SERVICE_CHANGE_CONFIG",
            "SERVICE_PAUSE_CONTINUE",
            # "SERVICE_QUERY_CONFIG",
            "SERVICE_START",
            "SERVICE_STOP",
            # "SERVICE_USER_DEFINED_CONTROL", # TODO this is granted most of the time.  Double check that's not a bad thing.
        ),
        ntsecuritycon: (
            "DELETE",
            "WRITE_DAC",
            "WRITE_OWNER"
        )
#        win32con: (
#            "READ_CONTROL"
#        )
    },
}

win32con.PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
win32con.PROCESS_SUSPEND_RESUME = 0x0800

all_perms = {
    'share': {
        ntsecuritycon: (
            "FILE_READ_DATA",
            "FILE_WRITE_DATA",
            "FILE_APPEND_DATA",
            "FILE_READ_EA",
            "FILE_WRITE_EA",
            "FILE_EXECUTE",
            "FILE_READ_ATTRIBUTES",
            "FILE_WRITE_ATTRIBUTES",
            "DELETE",
            "READ_CONTROL",
            "WRITE_DAC",
            "WRITE_OWNER",
            "SYNCHRONIZE",
        )
    },
    'file': {
        ntsecuritycon: (
            "FILE_READ_DATA",
            "FILE_WRITE_DATA",
            "FILE_APPEND_DATA",
            "FILE_READ_EA",
            "FILE_WRITE_EA",
            "FILE_EXECUTE",
            "FILE_READ_ATTRIBUTES",
            "FILE_WRITE_ATTRIBUTES",
            "DELETE",
            "READ_CONTROL",
            "WRITE_DAC",
            "WRITE_OWNER",
            "SYNCHRONIZE",
        )
    },
    'regkey': {
        _winreg: (
            #"KEY_ALL_ACCESS",
            "KEY_CREATE_LINK",
            "KEY_CREATE_SUB_KEY",
            "KEY_ENUMERATE_SUB_KEYS",
            #"KEY_EXECUTE", # same as KEY_READ
            "KEY_NOTIFY",
            "KEY_QUERY_VALUE",
            "KEY_READ",
            "KEY_SET_VALUE",
            "KEY_WOW64_32KEY",
            "KEY_WOW64_64KEY",
            #"KEY_WRITE", #STANDARD_RIGHTS_WRITE, KEY_SET_VALUE, and KEY_CREATE_SUB_KEY access rights.
        ),
        ntsecuritycon: (
            "DELETE",
            "READ_CONTROL",
            "WRITE_DAC",
            "WRITE_OWNER",
            #"STANDARD_RIGHTS_REQUIRED",
            #"STANDARD_RIGHTS_WRITE", # same as STANDARD_RIGHTS_READ http://msdn.microsoft.com/en-us/library/aa379607(v=vs.85).aspx what is it for?
            #"STANDARD_RIGHTS_READ", # same as STANDARD_RIGHTS_WRITE http://msdn.microsoft.com/en-us/library/aa379607(v=vs.85).aspx what is it for?
            #"SYNCHRONIZE",
        )
    },
    'directory': {
        ntsecuritycon: (
            "FILE_LIST_DIRECTORY",
            "FILE_ADD_FILE",
            "FILE_ADD_SUBDIRECTORY",
            "FILE_READ_EA",
            "FILE_WRITE_EA",
            "FILE_TRAVERSE",
            "FILE_DELETE_CHILD",
            "FILE_READ_ATTRIBUTES",
            "FILE_WRITE_ATTRIBUTES",
            "DELETE",
            "READ_CONTROL",
            "WRITE_DAC",
            "WRITE_OWNER",
            "SYNCHRONIZE",
        )
    },
    'service_manager': {
        win32service: (
            "SC_MANAGER_ALL_ACCESS",
            "SC_MANAGER_CREATE_SERVICE",
            "SC_MANAGER_CONNECT",
            "SC_MANAGER_ENUMERATE_SERVICE",
            "SC_MANAGER_LOCK",
            "SC_MANAGER_MODIFY_BOOT_CONFIG",
            "SC_MANAGER_QUERY_LOCK_STATUS",
        )
    },
    'service': {
        win32service: (
            "SERVICE_INTERROGATE",
            "SERVICE_QUERY_STATUS",
            "SERVICE_ENUMERATE_DEPENDENTS",
            # "SERVICE_ALL_ACCESS", # combination of other rights
            "SERVICE_CHANGE_CONFIG",
            "SERVICE_PAUSE_CONTINUE",
            "SERVICE_QUERY_CONFIG",
            "SERVICE_START",
            "SERVICE_STOP",
            "SERVICE_USER_DEFINED_CONTROL",  # TODO this is granted most of the time.  Double check that's not a bad thing.
        ),
        ntsecuritycon: (
            "DELETE",
            "READ_CONTROL",  # needed to read acl of service
            "WRITE_DAC",
            "WRITE_OWNER",
            "SYNCHRONIZE",
            #"STANDARD_RIGHTS_REQUIRED", # combination of other rights
            #"STANDARD_RIGHTS_READ", # combination of other rights
            #"STANDARD_RIGHTS_WRITE", # combination of other rights
            #"STANDARD_RIGHTS_EXECUTE", # combination of other rights
            #"STANDARD_RIGHTS_ALL", # combination of other rights
            #"SPECIFIC_RIGHTS_ALL", # combination of other rights
            "ACCESS_SYSTEM_SECURITY",
            #"MAXIMUM_ALLOWED",
            "GENERIC_READ",
            "GENERIC_WRITE",
            "GENERIC_EXECUTE",
            "GENERIC_ALL"
        )
    },
    # http://msdn.microsoft.com/en-gb/library/windows/desktop/ms686769(v=vs.85).aspx
    'thread': {
        win32con: (
            "THREAD_TERMINATE",
            "THREAD_SUSPEND_RESUME",
            "THREAD_GET_CONTEXT",
            "THREAD_SET_CONTEXT",
            "THREAD_SET_INFORMATION",
            "THREAD_QUERY_INFORMATION",
            "THREAD_SET_THREAD_TOKEN",
            "THREAD_IMPERSONATE",
            "THREAD_DIRECT_IMPERSONATION",
            #"THREAD_ALL_ACCESS",
            #"THREAD_QUERY_LIMITED_INFORMATION", TODO
            # "THREAD_SET_LIMITED_INFORMATION" TODO
        ),
        ntsecuritycon: (
            "DELETE",
            "READ_CONTROL",
            "WRITE_DAC",
            "WRITE_OWNER",
            "SYNCHRONIZE",
        )
    },
    # http://msdn.microsoft.com/en-us/library/ms684880(v=vs.85).aspx
    'process': {
        win32con: (
            "PROCESS_TERMINATE",
            "PROCESS_CREATE_THREAD",
            "PROCESS_VM_OPERATION",
            "PROCESS_VM_READ",
            "PROCESS_VM_WRITE",
            "PROCESS_DUP_HANDLE",
            "PROCESS_CREATE_PROCESS",
            "PROCESS_SET_QUOTA",
            "PROCESS_SET_INFORMATION",
            "PROCESS_QUERY_INFORMATION",
            "PROCESS_QUERY_LIMITED_INFORMATION",
            "PROCESS_SUSPEND_RESUME",
            #"PROCESS_ALL_ACCESS"
        ),
        ntsecuritycon: (
            "DELETE",
            "READ_CONTROL",
            "WRITE_DAC",
            "WRITE_OWNER",
            "SYNCHRONIZE",
            #"STANDARD_RIGHTS_REQUIRED",
            #"STANDARD_RIGHTS_READ",
            #"STANDARD_RIGHTS_WRITE",
            #"STANDARD_RIGHTS_EXECUTE",
            #"STANDARD_RIGHTS_ALL",
            #"SPECIFIC_RIGHTS_ALL",
            #"ACCESS_SYSTEM_SECURITY",
            #"MAXIMUM_ALLOWED",
            #"GENERIC_READ",
            #"GENERIC_WRITE",
            #"GENERIC_EXECUTE",
            #"GENERIC_ALL"
        )
    },
    'thread': {
        win32con: (
            "THREAD_TERMINATE",
            "THREAD_SUSPEND_RESUME",
            "THREAD_GET_CONTEXT",
            "THREAD_SET_CONTEXT",
            "THREAD_SET_INFORMATION",
            "THREAD_QUERY_INFORMATION",
            "THREAD_SET_THREAD_TOKEN",
            "THREAD_IMPERSONATE",
            "THREAD_DIRECT_IMPERSONATION",
            #"THREAD_ALL_ACCESS",
            #"THREAD_QUERY_LIMITED_INFORMATION", TODO
            # "THREAD_SET_LIMITED_INFORMATION" TODO
        ),
        ntsecuritycon: (
            "DELETE",
            "READ_CONTROL",
            "WRITE_DAC",
            "WRITE_OWNER",
            "SYNCHRONIZE",
        )
    },
    'token': {
        win32con: (
            "TOKEN_ADJUST_DEFAULT",
            "TOKEN_ADJUST_GROUPS",
            "TOKEN_ADJUST_PRIVILEGES",
            #"TOKEN_ADJUST_SESSIONID", TODO what's the number for this?
            "TOKEN_ASSIGN_PRIMARY",
            "TOKEN_DUPLICATE",
            "TOKEN_EXECUTE",
            "TOKEN_IMPERSONATE",
            "TOKEN_QUERY",
            "TOKEN_QUERY_SOURCE",
            "TOKEN_READ",
            "TOKEN_WRITE",
            "TOKEN_ALL_ACCESS"
        ),
        ntsecuritycon: (
            "DELETE",
            "READ_CONTROL",
            "WRITE_DAC",
            "WRITE_OWNER",
            #"SYNCHRONIZE",
        )
    },
}

# Used to store a data structure representing the issues we've found
# We use this to generate the report
issues = {}

# TODO: Use a big XML file instead.  Read it in to generate this dictionary.
issue_template = {
    'WPC001': {
       'title': "Insecure Permissions on Program Files",
       'description': '''Some of the programs in %ProgramFiles% and/or %ProgramFiles(x86)% could be changed by non-administrative users.

This could allow certain users on the system to place malicious code into certain key directories, or to replace programs with malicious ones.  A malicious local user could use this technique to hijack the privileges of other local users, running commands with their privileges.
''',
       'recommendation': '''Programs run by multiple users should only be changable only by administrative users.  The directories containing these programs should only be changable only by administrators too.  Revoke write privileges for non-administrative users from the above programs and directories.''',
       'supporting_data': {
          'writable_progs': {
             'section': "description",
             'preamble': "The programs below can be modified by non-administrative users:",
          },
          'writable_dirs': {
             'section': "description",
             'preamble': "The directories below can be changed by non-administrative users:",
          },
       }
    },
    'WPC002': {
       'title': "Insecure Permissions on Files and Directories in Path (OBSELETE ISSUE)",
       'description': '''Some of the programs and directories in the %PATH% variable could be changed by non-administrative users.

This could allow certain users on the system to place malicious code into certain key directories, or to replace programs with malicious ones.  A malicious local user could use this technique to hijack the privileges of other local users, running commands with their privileges.
''',
       'recommendation': '''Programs run by multiple users should only be changable only by administrative users.  The directories containing these programs should only be changable only by administrators too.  Revoke write privileges for non-administrative users from the above programs and directories.''',
       'supporting_data': {
          'writable_progs': {
             'section': "description",
             'preamble': "The programs below are in the path of the user used to carry out this audit.  Each one can be changed by non-administrative users:",
          },
          'writable_dirs': {
             'section': "description",
             'preamble': "The directories below are in the path of the user used to carry out this audit.  Each one can be changed by non-administrative users:",
          }
       }
    },
    # TODO walk the whole registry looking for .exe and .dll in data?
    'WPC003': {
       'title': "Insecure Permissions In Windows Registry (TODO)",
       'description': '''Some registry keys that hold the names of programs run by other users were checked and found to have insecure permissions.  It would be possible for non-administrative users to modify the registry to cause different programs to be run.  This weakness could be abused by low-privileged users to run commands of their choosing with higher privileges.''',
       'recommendation': '''Modify the permissions on the above registry keys to allow only administrators write access.  Revoke write access from low-privileged users.''',
       'supporting_data': {
          'writable_reg_paths': {
             'section': "description",
             'preamble': "The registry keys below could be changed by non-administrative users:",
          },
       }
    },
    'WPC005': {
       'title': "Insecure Permissions On Windows Service Registry Keys (OBSELETED by WPC038 and others)",
       'description': '''Some registry keys that hold the names of programs that are run when Windows Services start were found to have weak file permissions.  They could be changed by non-administrative users to cause malicious programs to be run instead of the intended Windows Service Executable.''',
       'recommendation': '''Modify the permissions on the above programs to allow only administrators write access.  Revoke write access from low-privileged users.''',
       'supporting_data': {
          'writable_reg_paths': {
             'section': "description",
             'preamble': "The registry keys below could be changed by non-administrative users:",
          },
       }
    },
    'WPC007': {
       'title': "Write Permissions Allowed On Event Log File",
       'description': '''Some of the Event Log files could be changed by non-administrative users.  This may allow attackers to cover their tracks.''',
       'recommendation': '''Modify the permissions on the above files to allow only administrators write access.  Revoke write access from low-privileged users.''',
       'supporting_data': {
          'writable_eventlog_file': {
             'section': "description",
             'preamble': "The files below could be changed by non-administrative users:",
          },
       }
    },
    'WPC008': {
       'title': "Insecure Permissions On Event Log DLL",
       'description': '''Some DLL files used by Event Viewer to display logs could be changed by non-administrative users.  It may be possible to replace these with a view to having code run when an administrative user next views log files.''',
       'recommendation': '''Modify the permissions on the above DLLs to allow only administrators write access.  Revoke write access from low-privileged users.''',
       'supporting_data': {
          'writable_eventlog_dll': {
             'section': "description",
             'preamble': "The DLL files below could be changed by non-administrative users:",
          },
       }
    },
    'WPC009': {
       'title': "Insecure Permissions On Event Log Registry Key",
       'description': '''Some registry keys that hold the names of DLLs used by Event Viewer and the location of Log Files are writable by non-administrative users.  It may be possible to maliciouly alter the registry to change the location of log files or run malicious code.''',
       'recommendation': '''Modify the permissions on the above programs to allow only administrators write access.  Revoke write access from low-privileged users.''',
       'supporting_data': {
          'writable_eventlog_key': {
             'section': "description",
             'preamble': "The registry keys below could be changed by non-administrative users:",
          },
       }
    },
    'WPC010': {
       'title': "File Creation Allowed On Drive Root",
       'description': '''Some of the local drive roots allow non-administrative users to create files.  This could allow malicious files to be placed in on the server in the hope that they'll allow a local user to escalate privileges (e.g. create program.exe which might get accidentally launched by another user).''',
       'recommendation': '''Modify the permissions on the drive roots to only allow administrators write access.  Revoke write access from low-privileged users.''',
       'supporting_data': {
          'dir_add_file': {
             'section': "description",
             'preamble': "The following drives allow non-administrative users to write to their root directory:",
          },
       }
    },
    'WPC011': {
       'title': "Insecure (Non-NTFS) File System Used",
       'description': '''Some local drives use Non-NTFS file systems.  These drive therefore don't allow secure file permissions to be used.  Any local user can change any data on these drives.''',
       'recommendation': '''Use NTFS filesystems instead of FAT.  Ensure that strong file permissions are set - NTFS file permissions are insecure by default after FAT file systems are converted.''',
       'supporting_data': {
          'drive_and_fs_list': {
             'section': "description",
             'preamble': "The following drives use Non-NTFS file systems:",
          },
       }
    },
    'WPC012': {
       'title': "Insecure Permissions On Windows Services (OBSELETE)",
       'description': '''Some of the Windows Services installed have weak permissions.  This could allow non-administrators to manipulate services to their own advantage.  The impact depends on the permissions granted, but can include starting services, stopping service or even reconfiguring them to run a different program.  This can lead to denial of service or even privilege escalation if the service is running as a user with more privilege than a malicious local user.''',
       'recommendation': '''Review the permissions that have been granted to non-administrative users and revoke access where possible.''',
       'supporting_data': {
          'weak_service_perms': {
             'section': "description",
             'preamble': "Some Windows Services can be manipulated by non-administrator users:",
          },
       }
    },
    'WPC013': {
       'title': "Insecure Permissions On Files / Directories In System PATH",
       'description': '''Some programs/directories in the system path have weak permissions.  TODO which user are affected by this issue?''',
       'recommendation': '''Review the permissions that have been granted to non-administrative users and revoke access where possible.''',
       'supporting_data': {
          'writable_progs': {
             'section': "description",
             'preamble': "The following programs/DLLs in the system PATH can be manipulated by non-administrator users:",
          },
          'writable_dirs': {
             'section': "description",
             'preamble': "The following directories in the system PATH can be manipulated by non-administrator users:",
          },
       }
    },
    'WPC014': {
       'title': "Insecure Permissions On Files / Directories In Current User's PATH",
       'description': '''Some programs/directories in the path of the user used to perform this audit have weak permissions.''',
       'recommendation': '''Review the permissions that have been granted to non-administrative users and revoke access where possible.''',
       'supporting_data': {
          'writable_progs': {
             'section': "description",
             'preamble': "The following programs/DLLs in current user's PATH can be manipulated by non-administrator users:",
          },
          'writable_dirs': {
             'section': "description",
             'preamble': "The following directories in the current user's PATH can be manipulated by non-administrator users:",
          },
       }
    },
    'WPC015': {
       'title': "Insecure Permissions On Files / Directories In Users' PATHs (TODO)",
       'description': '''Some programs/directories in the paths of users on this system have weak permissions.''',
       'recommendation': '''Review the permissions that have been granted to non-administrative users and revoke access where possible.''',
       'supporting_data': {
          'writable_progs': {
             'section': "description",
             'preamble': "The following programs/DLLs in users' PATHs can be manipulated by non-administrator users:",
          },
          'writable_dirs': {
             'section': "description",
             'preamble': "The following directories in users' PATHs can be manipulated by non-administrator users:",
          },
       }
    },
    'WPC016': {
       'title': "Insecure Permissions On Running Programs (OBSELETED by WPC067)",
       'description': '''Some programs running at the time of the audit have weak file permissions.  The corresponding programs could be altered by non-administrator users.''',
       'recommendation': '''Review the permissions that have been granted to non-administrative users and revoke access where possible.''',
       'supporting_data': {
          'weak_perms_exes': {
             'section': "description",
             'preamble': "The following programs were running at the time of the audit, but could be changed on-disk by non-administrator users:",
          },
          'weak_perms_dlls': {
             'section': "description",
             'preamble': "The following DLLs are used by program which were running at the time of the audit.  These DLLs can be changed on-disk by non-administrator users:",
          },
       }
    },
    'WPC018': {
       'title': "Service Can Be Started By Non-Admin Users",
       'description': '''The service-level permissions on some Windows services allow them to be started by non-administrative users.  This can often be desirable, in which case this issue can be ignored.  However, sometimes it can allow users to expose or exploit a vulnerability connected with the service - e.g. it may listen on the network or it may have been tampered with by an attacker and they now need to start the service.  The permission is not always dangerous on its own, but can sometimes aid a local attacker.''',
       'recommendation': '''Review the service-level permissions that have been granted to non-administrative users and revoke access where possible.''',
       'supporting_data': {
          'principals_with_service_perm': {
             'section': "description",
             'preamble': "The SERVICE_START permission has been granted to the following non-administrative users:",
          },
       }
    },
    'WPC019': {
       'title': "Service Can Be Stopped By Non-Admin Users",
       'description': '''The service-level permissions on some Windows services allow them to be stopped by non-administrative users.  This can often be desirable, in which case this issue can be ignored.  However, sometimes it can allow users to evade monitoring services - e.g. Anti-virus.  This permission can also be required in order to exploit other weaknesses such as weak file permissions on service executables.  The permission is not always dangerous on its own, but can sometimes aid a local attacker.''',
       'recommendation': '''Review the service-level permissions that have been granted to non-administrative users and revoke access where possible.''',
       'supporting_data': {
          'principals_with_service_perm': {
             'section': "description",
             'preamble': "The SERVICE_STOP permission has been granted to the following non-administrative users:",
          },
       }
    },
    'WPC020': {
       'title': "Service Can Be Paused/Resumed By Non-Admin Users",
       'description': '''The service-level permissions on some Windows services allow them to be paused/resumed by non-administrative users.  This can often be desirable, in which case this issue can be ignored.  However, sometimes it can allow users to allow users to evade monitoring - e.g. from Anti-virus services.  The permission is not always dangerous on its own, but can sometimes aid a local attacker.''',
       'recommendation': '''Review the service-level permissions that have been granted to non-administrative users and revoke access where possible.''',
       'supporting_data': {
          'principals_with_service_perm': {
             'section': "description",
             'preamble': "The SERVICE_PAUSE_CONTINUE permission has been granted to the following non-administrative users:",
          },
       }
    },
    'WPC021': {
       'title': "Service Can Be Reconfigured By Non-Admin Users",
       'description': '''The service-level permissions on some Windows services allow them to be reconfigured by non-administrative users.  This should not normally be required and is inherently insecure.  It could certain users alter the program which is run when this service start and to alter which user the service runs as.  The most likely attack would be to reconfigure the service to run as LocalSystem with no password and to select a malicious executable.  This would give the attacker administrator level access to the local system.''',
       'recommendation': '''Review the service-level permissions that have been granted to non-administrative users and revoke access where possible.''',
       'supporting_data': {
          'principals_with_service_perm': {
             'section': "description",
             'preamble': "The SERVICE_CHANGE_CONFIG permission has been granted to the following non-administrative users:",
          },
       }
    },
    'WPC022': {
       'title': "Service Can Be Deleted By Non-Admin Users",
       'description': '''The service-level permissions on some Windows services allow them to be deleted by non-administrative users.  This should not normally be required and is inherently insecure.  It could allow local users to delete the service.  This may allow them to evade monitor - e.g. from Anti-virus - or to disrupt normal business operations.  Note that the user would not be able to replace the service as administrator level rights are required to create new services.''',
       'recommendation': '''Review the service-level permissions that have been granted to non-administrative users and revoke access where possible.''',
       'supporting_data': {
          'principals_with_service_perm': {
             'section': "description",
             'preamble': "The DELETE permission has been granted to the following non-administrative users:",
          },
       }
    },
    'WPC023': {
       'title': "Service Permissions Can Be Altered By Non-Admin Users",
       'description': '''The service-level permissions on some Windows services allow some non-administrative users to set any service-level permissions of their choosing.  This should not normally be required and is inherently insecure.  It has a similar effect to granting the user DELETE and SERVICE_CHANGE_CONFIG.  These powerful rights could allow the user to reconfigure a service to provide them with administrator level access, or simply to delete the service, disrupting normal business operations.''',
       'recommendation': '''Review the service-level permissions that have been granted to non-administrative users and revoke access where possible.''',
       'supporting_data': {
          'principals_with_service_perm': {
             'section': "description",
             'preamble': "The WRITE_DAC permission has been granted to the following non-administrative users:",
          },
       }
    },
    'WPC024': {
       'title': "Non-Admin Users Can Take Ownership of Service",
       'description': '''The service-level permissions on some Windows services allow ownership to be claimed by some non-administrative users.  This should not normally be required and is inherently insecure.  It has a similar effect to granting the user WRITE_DAC (and thus DELETE and SERVICE_CHANGE_CONFIG).  These powerful rights could allow the user to reconfigure a service to provide them with administrator level access, or simply to delete the service, disrupting normal business operations.''',
       'recommendation': '''Review the service-level permissions that have been granted to non-administrative users and revoke access where possible.''',
       'supporting_data': {
          'principals_with_service_perm': {
             'section': "description",
             'preamble': "The WRITE_OWNER permission has been granted to the following non-administrative users:",
          },
       }
    },
    'WPC025': {
       'title': "Services Owned By Non-Admin Users",
       'description': '''The owner in the security descriptor for some services is set to a non-administrative user.  This should not normally be required and is inherently insecure.  It has a similar effect to granting the user WRITE_DAC (and thus DELETE and SERVICE_CHANGE_CONFIG).  These powerful rights could allow the user to reconfigure a service to provide them with administrator level access, or simply to delete the service, disrupting normal business operations.''',
       'recommendation': '''Review the service-level permissions that have been granted to non-administrative users and revoke access where possible.''',
       'supporting_data': {
          'principals_with_service_ownership': {
             'section': "description",
             'preamble': "The following services are owned by non-administrative users:",
          },
       }
    },
    'WPC026': {
       'title': "Delete Permission Granted On Windows Service Executables",
       'description': '''Some of the programs that are run when Windows Services start were found to have weak file permissions.  It is possible for non-administrative local users to delete some of the Windows Service executables with malicious programs.  This could lead to disruption or denial of service.''',
       'recommendation': '''Modify the permissions on the above programs to allow only administrators delete permission.  Revoke delete permission from low-privileged users.''',
       'supporting_data': {
          'service_exe_write_perms': {
             'section': "description",
             'preamble': "The programs below have DELETE permission granted to non-administrative users:",
          },
       }
    },
    'WPC027': {
       'title': "Append Permission Granted Windows Service Executables",
       'description': '''Some of the programs that are run when Windows Services start were found to have weak file permissions.  It is possible for non-administrative local users to append to some of the Windows Service executables with malicious programs.  This is unlikely to be exploitable for .exe files, but is it bad security practise to allow more access than necessary to low-privileged users.''',
       'recommendation': '''Modify the permissions on the above programs to allow only administrators delete permission.  Revoke delete permission from low-privileged users.''',
       'supporting_data': {
          'service_exe_write_perms': {
             'section': "description",
             'preamble': "The programs below have FILE_APPEND permission granted to non-administrative users:",
          },
       }
    },
    'WPC028': {
       'title': "Untrusted Users Can Modify Windows Service Executables",
       'description': '''Some of the programs that are run when Windows Services start were found to have weak file permissions.  It is possible for non-administrative local users to replace some of the Windows Service executables with malicious programs.  This could be abused to execute programs with the privileges of the Windows services concerned.''',
       'recommendation': '''Modify the permissions on the above programs to allow only administrators write access.  Revoke write access from low-privileged users.''',
       'supporting_data': {
          'service_exe_write_perms': {
             'section': "description",
             'preamble': "The programs below have FILE_WRITE, WRITE_DAC or WRITE_OWNER permission granted to non-administrative users:",
          },
       }
    },
    'WPC029': {
       'title': "Windows Service Executables Owned By Untrusted Users",
       'description': '''Some of the programs that are run when Windows Services start were found to be owned by untrusted users.  Consequently, these programs can be replace with malicious programs by low-privileged users.  This could result is users stealing the privileges of the services affected.''',
       'recommendation': '''Change the ownership of the affected programs.  They should be owned by administrators.''',
       'supporting_data': {
          'service_exe_owner': {
             'section': "description",
             'preamble': "The programs below were owned by non-administrative users:",
          },
       }
    },
    'WPC030': {
       'title': "Parent Directories of Windows Service Executables Allow Untrusted Users FILE_DELETE_CHILD and FILE_ADD_SUBDIR Permissions",
       'description': '''Some of the programs that are run when Windows Services start were found to have parent directories that had both FILE_DELETE_CHILD and FILE_ADD_SUBDIR permissions granted to untrusted users.  This combination of directory permissions allows entire portions of the parent directory structure can be deleted and replaced, allowing the service executable to be susbstituted with a malicoius one.  In this way low-privileged users could steal the privileges of the services affected.''',
       'recommendation': '''Change the directory permissions granted to low-privileged users.  They should never be granted FILE_DELETE_CHILD permission to the parent directory of a program.  FILE_ADD_SUBDIR should be used sparingly.''',
       'supporting_data': {
          'service_exe_parent_dir_perms': {
             'section': "description",
             'preamble': "The programs had parent directories which granted non-administrative users FILE_DELETE_CHILD and FILE_ADD_SUBDIR permissions:",
          },
       }
    },
    'WPC031': {
       'title': "Parent Directories of Windows Service Executables Allow Untrusted Users DELETE Permissions And Can Be Replaced Because of FILE_ADD_SUBDIR Permission",
       'description': '''Some of the programs that are run when Windows Services start were found to have parent directories that had DELETE permission granted to untrusted users. Further the parent directories of the directories affected had FILE_ADD_SUBDIR granted for low-privileged users.  This combination of directory permissions allows entire portions of the parent directory structure can be deleted and replaced, allowing the service executable to be susbstituted with a malicoius one.  In this way low-privileged users could steal the privileges of the services affected.''',
       'recommendation': '''Change the directory permissions granted to low-privileged users.  They should never be granted DELETE permission to the parent directory of a program.  FILE_ADD_SUBDIR should be used sparingly.''',
       'supporting_data': {
          'service_exe_parent_grandparent_write_perms': {
             'section': "description",
             'preamble': "The programs below were owned by non-administrative users:",
          },
       }
    },
    'WPC032': {
       'title': "Parent Directories of Windows Service Executables Can Have File Permissions Altered By Untrusted Users",
       'description': '''Some of the programs that are run when Windows Services start were found to have parent directories that had the permissions WRITE_OWNER or WRITE_DAC granted to untrusted users.  Consequently, low-privileged users could grant themselves any privilege they desired on these directories.  This could result in entire portions of the parent directory structure can be deleted and replaced, allowing the service executable to be susbstituted with a malicoius one.  In this way low-privileged users could steal the privileges of the services affected.''',
       'recommendation': '''Change the directory permissions granted to low-privileged users.  Service executables should never have WRITE_OWNER or WRITE_DAC granted to low privileged users.''',
       'supporting_data': {
          'service_exe_parent_dir_perms': {
             'section': "description",
             'preamble': "The directories below had the permissions WRITE_OWNER or WRITE_DAC granted to non-administrative users:",
          },
       }
    },
    'WPC033': {
       'title': "Parent Directories of Windows Service Executables Owned By Untrusted Users",
       'description': '''Some of the programs that are run when Windows Services start were found to have parent directories that were owned by untrusted users.  Consequently, entire portions of the parent directory structure can be deleted and replaced, allowing the service executable to be susbstituted with a malicoius one.  This could result is users stealing the privileges of the services affected.''',
       'recommendation': '''Change the ownership of the affected directories.  They should be owned by administrators.''',
       'supporting_data': {
          'service_exe_parent_dir_untrusted_ownership': {
             'section': "description",
             'preamble': "The directories below were owned by non-administrative users:",
          },
       }
    },
    'WPC034': {
       'title': "Windows Service Executables Allow DELETE Permissions To Untrusted Users And Can Be Replaced Because of FILE_ADD_FILE Permission On Parent Directory",
       'description': '''Some of the programs that are run when Windows Services start were found to have DELETE permission granted to low-privileged users.  Furthermore, the parent directory allowed FILE_ADD_FILE permission to low-privileged users.  This combination of directory permissions allows the service executable to be deleted and replaced malicoius program.  In this way low-privileged users could steal the privileges of the services affected.''',
       'recommendation': '''Change the file and directory permissions granted to low-privileged users.  They should never be granted DELETE permission on a service executable.  The use of FILE_ADD_FILE on parent directories should also be avoided.''',
       'supporting_data': {
          'service_exe_file_parent_write_perms': {
             'section': "description",
             'preamble': "The programs had parent directories which granted non-administrative users FILE_DELETE_CHILD and FILE_ADD_SUBDIR permissions:",
          },
       }
    },
    'WPC035': {
       'title': "Windows Service Registry Keys Are Owned By Untrusted Users",
       'description': '''Configuration information for Windows Service is stored in the registry.  Some of the keys were found to be owned by non-administrative users.  It would be possible for these users to maliciously modify the registry to change the executable run to a malicious one, or to make the service run with higher privileges.  It could lead to a low-privileged user escalating privilges to local administrator.''',
       'recommendation': '''Change the ownership of registry keys pertaining to Windows Servies.  Keys should only be owned by administors only.''',
       'supporting_data': {
          'service_exe_regkey_untrusted_ownership': {
             'section': "description",
             'preamble': "The registry keys below were owned by non-administrative users:",
          },
       }
    },
    'WPC036': {
       'title': "Permissions on Windows Service Registry Keys Can be Changed By Untrusted Users",
       'description': '''Configuration information for Windows Service is stored in the registry.  Some of the keys were found to have WRITE_DAC or WRITE_OWNER permissions granted for non-administrative users.  After modifying the permission as desired, it would be possible for these users to maliciously modify the registry to change the executable run to a malicious one, or to make the service run with higher privileges.  It could lead to a low-privileged user escalating privilges to local administrator.''',
       'recommendation': '''Change the permissions of registry keys pertaining to Windows Servies.  Keys should never allow WRITE_DAC or WRITE_OWNER for low-privileged users.''',
       'supporting_data': {
          'service_reg_perms': {
             'section': "description",
             'preamble': "The registry keys below had WRITE_DAC or WRITE_OWNER granted for non-administrative users:",
          },
       }
    },
    'WPC037': {
       'title': "Windows Service Registry Values Can be Changed By Untrusted Users",
       'description': '''Configuration information for Windows Service is stored in the registry.  Some of the keys were found to have the KEY_SET_VALUE permission granted for non-administrative users.  It would be possible for these users to maliciously modify the registry to change the executable run to a malicious one, or to make the service run with higher privileges.  It could lead to a low-privileged user escalating privilges to local administrator.''',
       'recommendation': '''Change the permissions of registry keys pertaining to Windows Servies.  Service registry keys should never allow KEY_SET_VALUE for low-privileged users.''',
       'supporting_data': {
          'service_reg_perms': {
             'section': "description",
             'preamble': "The registry keys below had KEY_SET_VALUE granted for non-administrative users:",
          },
       }
    },
    'WPC038': {
       'title': "Windows Service Registry Keys Allow KEY_CREATE_LINK",
       'description': '''Configuration information for Windows Service is stored in the registry.  Some of the keys were found to have the KEY_CREATE_LINK permission granted for non-administrative users.  This allows low-privileged users to create Registry Symbolic Links.  While this feature appears to be poorly documented by Microsoft, there is sample code freely available on the Internet.  The impact of this issue is similar to that for the KEY_CREATE_SUB_KEY issue: It may be possible for low privileged users to manipulate services - though this would depend on how the service responded to the addition of new registry keys.''',
       'recommendation': '''Change the permissions of registry keys pertaining to Windows Servies.  Service registry keys should never allow KEY_CREATE_LINK for low-privileged users.''',
       'supporting_data': {
          'service_reg_perms': {
             'section': "description",
             'preamble': "The registry keys below had KEY_CREATE_LINK granted for non-administrative users:",
          },
       }
    },
    'WPC039': {
       'title': "Windows Service Registry Keys Allow Untrusted Users To Create Subkeys",
       'description': '''Configuration information for Windows Service is stored in the registry.  Some of the keys were found to have the KEY_CREATE_SUB_KEY permission granted for non-administrative users.  It may be possible for low privileged users to manipulate service - though this would depend on how the service responded to the addition of new registry keys.''',
       'recommendation': '''Review the permissions of keys with KEY_CREATE_SUB_KEY granged.  Revoke KEY_CREATE_SUB_KEY permissions for non-administrative users where possible.''',
       'supporting_data': {
          'service_reg_perms': {
             'section': "description",
             'preamble': "The registry keys below had KEY_CREATE_SUB_KEY granted for non-administrative users:",
          },
       }
    },
    'WPC040': {
       'title': "Windows Service Registry Keys Allow Untrusted Users To Delete Them",
       'description': '''Configuration information for Windows Service is stored in the registry.  Some of the keys were found to have the DELETE permission granted for non-administrative users.  Low privileged users could delete the service configuration information, disrupting normal business operations.''',
       'recommendation': '''Change the permissions of registry keys pertaining to Windows Servies.  Service registry keys should never allow DELETE for low-privileged users.''',
       'supporting_data': {
          'service_reg_perms': {
             'section': "description",
             'preamble': "The registry keys below had DELETE granted for non-administrative users:",
          },
       }
    },
    'WPC041': {
       'title': "Windows Service Registry Keys Have Parent Keys Owned By Untrusted Users",
       'description': '''Configuration information for Windows Service is stored in the registry.  Some of the parent keys were found to be owned by non-administrative users.  This could allow low-privileged users to alter the permissions on the keys concerned, delete them, add subkeys and add/alter registry values for that key.  This probably constitutes a denial of service risk, but may also allow privilege escalation depending on how the service responds to registry keys being tampered with.''',
       'recommendation': '''Change the ownership of registry keys pertaining to Windows Servies.  Service registry keys should be owned by the administrators group.''',
       'supporting_data': {
          'service_regkey_parent_untrusted_ownership': {
             'section': "description",
             'preamble': "The registry keys below were owned by non-administrative users:",
          },
       }
    },
    'WPC042': {
       'title': "Permissions on Windows Service Registry Keys Can Be Changed By Untrusted Users",
       'description': '''Configuration information for Windows Service is stored in the registry.  TODO.''',
       'recommendation': '''TODO.''',
       'supporting_data': {
          'service_regkey_parent_perms': {
             'section': "description",
             'preamble': "The registry keys below were owned by non-administrative users:",
          },
       }
    },
    'WPC043': {
       'title': "Windows Service Registry Keys Can Be Deleted And Replaced By Untrusted Users",
       'description': '''Configuration information for Windows Service is stored in the registry.  TODO.''',
       'recommendation': '''TODO.''',
       'supporting_data': {
          'service_regkey_parent_grandparent_write_perms': {
             'section': "description",
             'preamble': "The registry keys below were owned by non-administrative users:",
          },
       }
    },
    'WPC046': {
       'title': "Windows Registry Keys Containing Program Owned By Untrusted Users",
       'description': '''Some of the registry keys holding the names of programs run by other users could be changed by non-administrative users.  TODO''',
       'recommendation': '''TODO''',
       'supporting_data': {
          'regkey_untrusted_ownership': {
             'section': "description",
             'preamble': "The registry keys below can be changed by non-administrative users:",
          },
       }
    },
    'WPC047': {
       'title': "Windows Registry Keys Containing Programs Can Have Permissions Changed By Untrusted Users",
       'description': '''Some of the registry keys holding the names of programs run by other users could be changed by non-administrative users.  TODO''',
       'recommendation': '''TODO''',
       'supporting_data': {
          'regkey_perms': {
             'section': "description",
             'preamble': "The registry keys below can be changed by non-administrative users:",
          },
       }
    },
    'WPC048': {
       'title': "Windows Registry Keys Containing Program Names Can Be Changed By Untrusted Users",
       'description': '''Some of the registry keys holding the names of programs run by other users could be changed by non-administrative users.  It would be possible for an attacker to substitute the name of malicious program which then stole the privileges of other accounts.''',
       'recommendation': '''The keys below should only have write access for administrators.''',
       'supporting_data': {
          'regkey_perms': {
             'section': "description",
             'preamble': "The registry keys below can be changed by non-administrative users:",
          },
       }
    },
    'WPC049': {
       'title': "Windows Registry Keys Containing Programs Can Have Subkey Added By Untrusted Users",
       'description': '''Some of the registry keys holding the names of programs run by other users could be changed by non-administrative users.  TODO''',
       'recommendation': '''TODO''',
       'supporting_data': {
          'regkey_perms': {
             'section': "description",
             'preamble': "The registry keys below can be changed by non-administrative users:",
          },
       }
    },
    'WPC050': {
       'title': "Windows Registry Keys Containing Programs Can Be Deleted",
       'description': '''Some of the registry keys holding the names of programs run by other users could be changed by non-administrative users.  TODO''',
       'recommendation': '''TODO''',
       'supporting_data': {
          'regkey_perms': {
             'section': "description",
             'preamble': "The registry keys below can be changed by non-administrative users:",
          },
       }
    },
    'WPC051': {
       'title': "Windows Service Has Insecurely Quoted Path",
       'description': '''The path to the executable for the service contains one or more spaces and quotes have not been correctly used around the path.  The path is therefore ambiguous which could result in the wrong program being executed when the service is started - e.g. "C:\\program.exe" instead of "C:\\program files\\foo\\bar.exe".  The issue is not necessarily exploitable unless a local attacker has permissions to add an alternative executable to the correct location on the filesystem.  The impact of the issue should be considered higher for services that run with high privileges.''',
       'recommendation': '''Use quotes around the path to executables if they contain spaces: C:\\program files\\foo\\bar.exe -> "C:\\program files\\foo\\bar.exe".''',
       'supporting_data': {
          'service_info': {
             'section': "description",
             'preamble': "The following services have insecurely quoted paths:",
          },
       }
    },
    'WPC052': {
       'title': "Windows Service DLL Can Be Replaced",
       'description': '''Each windows service has a corresponding registry key in HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services.  Some services have a "Parameters" subkey and a value called "ServiceDll" (e.g. HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\someservice\\Parameters\\ServiceDll = c:\\dir\\foo.dll").  The DLL for some of the services on the system audited can be replaced by non-administrative users.  TODO how and by whom?  Users able to replace the service DLL could run code of their choosing with the privileges of the service.''',
       'recommendation': '''Set strong file permissions on the service DLLs and their partent directories.''',
       'supporting_data': {
          'service_dll': {
             'section': "description",
             'preamble': "The following services have weak file permissions on the service DLLs:",
          },
       }
    },
    'WPC053': {
       'title': "Context Handler Menus Use Poorly Protected Files",
       'description': '''Context Menus appear in Windows Explorer when files are right-clicked.  Each has a corresponding DLL or .EXE.  Some of the referenced DLLs or .EXE file can be replaced by non-administrative users.  As these context menus are used by all system users, there is a possibility that a user might run malicious code of an attacker's choosing if the DLLs or .EXEs are modified.  TODO how can the files be modified?

Context Menu Handlers are described here: http://msdn.microsoft.com/en-us/library/windows/desktop/cc144171(v=vs.85).aspx

Shell Extenstion Handlers more generally are described here: http://msdn.microsoft.com/en-us/library/windows/desktop/cc144067(v=vs.85).aspx       ''',
       'recommendation': '''Set strong file permissions on the service DLLs and their partent directories.''',
       'supporting_data': {
          'regkey_ref_replacable_file': {
             'section': "description",
             'preamble': "The following shell extension use DLLs or .EXE files with weak file permissions:",
          },
       }
    },
    'WPC054': {
       'title': "Property Sheet Handlers Use Poorly Protected Files",
       'description': '''"Property Sheets" appear in Windows Explorer when files are right-clicked and the "Properties" context menu selected.  The DLLs or .EXEs used to generate these property sheets can be replaced by non-administrative users.  As these property sheets are used by all system users, there is a possibility that a user might run malicious code of an attacker's choosing if the DLLs or .EXEs are modified.  TODO how can the files be modified?  

Property Sheet Handlers are described here: http://msdn.microsoft.com/en-us/library/windows/desktop/cc144106(v=vs.85).aspx

Shell Extenstion Handlers more generally are described here: http://msdn.microsoft.com/en-us/library/windows/desktop/cc144067(v=vs.85).aspx       ''',
       'recommendation': '''Set strong file permissions on the service DLLs and their partent directories.''',
       'supporting_data': {
          'regkey_ref_replacable_file': {
             'section': "description",
             'preamble': "The following shell extension use DLLs or .EXE files with weak file permissions:",
          },
       }
    },
    'WPC055': {
       'title': "Copy Hook Handlers Use Poorly Protected Files",
       'description': '''"Copy Hook Handlers" are a type of Windows Explorer shell extension that can control the copying, moving, deleting and renaming of files and folder.  Each as a corresponding DLL or .EXE.  Some of DLLs or .EXEs used can be replaced by non-administrative users.  As Copy Hooks are used by all system users, there is a possibility that a user might run malicious code of an attacker's choosing if the DLLs or .EXEs are modified.  TODO how can the files be modified?

Copy Hook Handlers are described here: http://msdn.microsoft.com/en-us/library/windows/desktop/cc144063(v=vs.85).aspx

Shell Extenstion Handlers more generally are described here: http://msdn.microsoft.com/en-us/library/windows/desktop/cc144067(v=vs.85).aspx       ''',
       'recommendation': '''Set strong file permissions on the service DLLs and their partent directories.''',
       'supporting_data': {
          'regkey_ref_replacable_file': {
             'section': "description",
             'preamble': "The following shell extension use DLLs or .EXE files with weak file permissions:",
          },
       }
    },
    'WPC056': {
       'title': "DragDrop Handlers Use Poorly Protected Files",
       'description': '''"DragDrop Handlers" are a type of Windows Explorer shell extension that determine behaviour when files or folders are dragged and dropped.  Each as a corresponding DLL or .EXE.  Some of DLLs or .EXEs used can be replaced by non-administrative users.  As DragDrop Handlers are used by all system users, there is a possibility that a user might run malicious code of an attacker's choosing if the DLLs or .EXEs are modified.  TODO how can the files be modified?

DragDrop Handlers are described here: http://msdn.microsoft.com/en-us/library/windows/desktop/cc144171(v=vs.85).aspx

Shell Extenstion Handlers more generally are described here: http://msdn.microsoft.com/en-us/library/windows/desktop/cc144067(v=vs.85).aspx       ''',
       'recommendation': '''Set strong file permissions on the service DLLs and their partent directories.''',
       'supporting_data': {
          'regkey_ref_replacable_file': {
             'section': "description",
             'preamble': "The following shell extension use DLLs or .EXE files with weak file permissions:",
          },
       }
    },
    'WPC057': {
       'title': "Column Handlers Use Poorly Protected Files",
       'description': '''"Column Handlers" are a type of Windows Explorer shell extension that determine behaviour the users tries to add or remove columns from the display.  Each as a corresponding DLL or .EXE.  Some of DLLs or .EXEs used can be replaced by non-administrative users.  As Column Handlers are used by all system users, there is a possibility that a user might run malicious code of an attacker's choosing if the DLLs or .EXEs are modified.  TODO how can the files be modified?

Column Handlers are described here: http://msdn.microsoft.com/en-us/library/windows/desktop/bb776831(v=vs.85).aspx

Shell Extenstion Handlers more generally are described here: http://msdn.microsoft.com/en-us/library/windows/desktop/cc144067(v=vs.85).aspx       ''',
       'recommendation': '''Set strong file permissions on the service DLLs and their partent directories.''',
       'supporting_data': {
          'regkey_ref_replacable_file': {
             'section': "description",
             'preamble': "The following shell extension use DLLs or .EXE files with weak file permissions:",
          },
       }
    },
    # TODO checks for these:
    # Icon Overlay Handlers http://msdn.microsoft.com/en-us/library/windows/desktop/cc144123(v=vs.85).aspx
    # Search Handlers http://msdn.microsoft.com/en-us/library/windows/desktop/bb776834(v=vs.85).aspx

    # TODO add RunOnceEx keys to this issue + HKCU\run, runonce, runonceex
    'WPC058': {
       'title': "Registry \"Run\" Keys Reference Programs With Weak Permissions",
       'description': '''The Run and RunOnce keys under HKLM reference programs that are run when a user logs in with the privielges of that user.  Some of the programs referenced by the registry keys can be modified by non-administrative user.  This could allow a malcious user to run code of their choosing under the context of other user accounts.  Run and RunOnce are described here: http://msdn.microsoft.com/en-us/library/aa376977(v=vs.85).aspx''',
       'recommendation': '''Set strong file permissions on the executables their parent directories.''',
       'supporting_data': {
          'regkey_ref_file': {
             'section': "description",
             'preamble': "The programs referenced from the registry can be modified by non-admin users:",
          },
       }
    },
    'WPC059': {
       'title': "Registry \"RunServices\" Keys Reference Programs With Weak Permissions",
       'description': '''The RunServices and RunServicesOnce keys under HKLM reference programs that are run before the Login Dialog box appears.  Commands are run as SYSTEM.  Some of the programs referenced by the registry keys can be modified by non-administrative user.  This could allow a malcious user to run code of their choosing under the context of the SYSTEM account.  RunServices and RunServicesOnce are described here: http://support.microsoft.com/kb/179365''',
       'recommendation': '''Set strong file permissions on the executables their parent directories.''',
       'supporting_data': {
          'regkey_ref_file': {
             'section': "description",
             'preamble': "The programs referenced from the registry can be modified by non-admin users:",
          },
       }
    },
    'WPC060': {
       'title': "KnownDLLs Have Weak Permissions",
       'description': '''The KnownDLLs registry key holds the name and path of various DLLs.  Programs that rely on these DLLs will load them from the known location instead of searching the rest of the PATH.  More information on KnownDLLs can be found here: http://support.microsoft.com/kb/164501''',
       'recommendation': '''Set strong file permissions on the DLLs their parent directories.''',
       'supporting_data': {
          'regkey_ref_file': {
             'section': "description",
             'preamble': "The programs referenced from the registry can be modified by non-admin users:",
          },
       }
    },
    'WPC061': {
       'title': "CLSID References DLLs/EXEs With Weak File Permissions (experimental)",
       'description': '''Some of the CLSIDs reference files with insecure permissions.  This may indicate the presence of a vulnerability, but it depends what the CLSID is used for.  Try searching the registry for the CLSIDs below to determine how they are used and if this issue might be exploitable.

Further information about CLSIDs is available here: http://msdn.microsoft.com/en-us/library/windows/desktop/ms691424(v=vs.85).aspx''',
       'recommendation': '''Set strong file permissions on files referenced from CLSIDs.''',
       'supporting_data': {
          'regkey_ref_file': {
             'section': "description",
             'preamble': "The programs referenced from the registry can be modified by non-admin users:",
          },
       }
    },
    'WPC062': {
       'title': "Windows Service Executable Is Missing",
       'description': '''Each Windows Service has a corresponding executable.  The executables for some services were missing at the time of the audit.  This can sometimes be caused programs being manually deleted instead of being properly uninstalled.  Although this configuration is unusual and probably undesirable, it is unlikely to be a security issue unless an attacker can recreate the executables in question - an issue that was NOT checked for (please check manually).  It may be an indication that an attacker has previously abused a Windows service and left it in a half-configured state, so investigating the cause of the problem is advised.''',
       'recommendation': '''Investigate why the service is broken and either fix or remove the service as appropriate.''',
       'supporting_data': {
          'service_no_exe': {
             'section': "description",
             'preamble': "The following Windows Services has missing executables:",
          },
       }
    },
    'WPC063': {
       'title': "Windows Service Running Under Domain Account",
       'description': '''The configuration for each Windows Service specifies the user context under which the service runs.  Often services run as Built-in security pricipals such as LocalSystem, Network Service, Local Service, etc. or as a dedicated local user account.  In the case of the system audited, some of the Windows Services were found to run in the context of a Domain account.  It would therefore be possible for any attacker who gained local admin rights on the system to recover the cleartext password for the Domain accounts in question.  Depending on the priviliges of those accounts, it may be possible for an attacker to abuse the accounts to compromise further systems on the network.''',
       'recommendation': '''Ensure that Domain accounts are only used when absolutely necessary.  When they are used, ensure that the group memberships of the account are restricted to only those required - avoiding membership of Domain Admins.  Where possible also ensure that service accounts are only able to logon from a whitelist of named workstations.  These recommendations help to limit the potential abuse of domain accounts.''',
       'supporting_data': {
          'service_domain_user': {
             'section': "description",
             'preamble': "The following windows services run in the context of Domain accounts:",
          },
       }
    },
    'WPC064': {
       'title': "Windows Service Running Under Named Local Account",
       'description': '''The configuration for each Windows Service specifies the user context under which the service runs.  Often services run as Built-in security pricipals such as LocalSystem, Network Service, Local Service, etc.  In the case of the system audited, some of the Windows Services were found to run in the context of a local account that wasn't a Built-in security principal.  This can be a secure configuration and indeed is recommended configuration for some services such as SQL Server.  However, if administrators have similar services running on other systems, they sometimes configure the Windows Service account to have the same password on each.  It would therefore be possible for any attacker who gained local admin rights on the system to recover the cleartext password for the local Windows Service accounts in question.  It passwords are reused, it may be possible for an attacker to abuse the accounts to compromise further systems on the network.''',
       'recommendation': '''Ensure that the group memberships of the account are restricted to only those required - avoiding membership of the Administrators group.  Where possible also ensure that service accounts are not able to log on interactively, as batch jobs or log in over the network.  These recommendations help to limit the potential abuse of windows service accounts.''',
       'supporting_data': {
          'service_domain_user': {
             'section': "description",
             'preamble': "The following windows services run in the context of local accounts:",
          },
       }
    },
    'WPC065': {
       'title': "Windows Services for Pentesting/Auditing Tools Found",
       'description': '''Some of the Windows service running appear to correspond to tools that are commons used for pentesting or auditing.  These may or may not present a security problem.  The main purpose of this issue is to advise the auditor to check if they accidentally added any Windows services.''',
       'recommendation': '''Check each of the Windows services below and remove them if they have been added during the pentest/audit.''',
       'supporting_data': {
          'sectool_services': {
             'section': "description",
             'preamble': "The following windows services appear to be pentesting/auditing tools:",
          },
       }
    },
    'WPC066': {
       'title': "Files for Pentesting/Auditing Tools Found (TODO)",
       'description': '''Some of the files found during the audit have the same name as tools used during pentesting and security auditing.  These may or may not present a security problem.  The main purpose of this issue is to advise the auditor to check if they forgot to remove any tools.''',
       'recommendation': '''Check each of the files below and remove them if they have been added during the pentest/audit.''',
       'supporting_data': {
          'sectool_files': {
             'section': "description",
             'preamble': "The following files appear to be pentesting/auditing tools:",
          },
       }
    },
    'WPC067': {
       'title': "Executables for Running Processes Can Be Modified On Disk",
       'description': '''The file permissions for the processes running at the time of the audit were checked.  The executables for some of the processes could be replaced by non-administrative users.  This could enable an attacker to escalate privilege to the owner of the processes concerned.  An attacker would need to replace the program on disk and wait for the program to be run again as the user concerned.''',
       'recommendation': '''Set strong file permissions on each of the programs below.  Also set strong file permissions on parent directories.  Ideally only administrative users would have the ability to change programs run by multiple users.  Note that this issue can usually be considered a false positive is users are simply running programs from their home directory - provided that no other non-admin users can modify them.''',
       'supporting_data': {
          'process_exe': {
             'section': "description",
             'preamble': "The following files could be replaced by non-administrative users (TODO: how?):",
          },
       }
    },
    'WPC068': {
       'title': "DLLs Used by Running Processes Can Be Modified On Disk",
       'description': '''The file permissions for DLLs used by processes running at the time of the audit were checked.  The DLLs for some of the processes could be replaced by non-administrative users.  This could enable an attacker to escalate privilege to the owner of the processes concerned.  An attacker would need to replace the DLL on disk and wait for the program to be run again as the user concerned.''',
       'recommendation': '''Set strong file permissions on each of the DLLs below.  Also set strong file permissions on parent directories.  Ideally only administrative users would have the ability to change DLLs used by multiple users.    Note that this issue can usually be considered a false positive is users are simply running programs from their home directory - provided that no other non-admin users can modify them.''',
       'supporting_data': {
          'process_dll': {
             'section': "description",
             'preamble': "The following files could be replaced by non-administrative users (TODO: how?):",
          },
       }
    },
    'WPC069': {
       'title': "Processes Security Descriptor Allow Access To Non-Admin Users (TODO)",
       'description': '''TODO.  Writeme+Fixme.  This issue currently get false positives about non-priv users being able to change their own process.  Also needs to take account of RESTRICTED processes http://blogs.msdn.com/b/aaron_margosis/archive/2004/09/10/227727.aspx http://msdn.microsoft.com/en-us/library/ms972827.aspx''',
       'recommendation': '''TODO''',
       'supporting_data': {
          'process_perms': {
             'section': "description",
             'preamble': "TODO",
          },
       }
    },
    'WPC070': {
       'title': "Windows Users/Groups Hold Powerful Privilege: SeAssignPrimaryTokenPrivilege",
       'description': '''TODO SE_ASSIGNPRIMARYTOKEN_NAME TEXT("SeAssignPrimaryTokenPrivilege") Required to assign the primary token of a process.''',
       'recommendation': '''Review the list of users below who hold this privilege.  Revoke it where it is not required - e.g. under 'Replace a process-level token'  in secpol.msc.''',
       'supporting_data': {
          'user_powerful_priv': {
             'section': "description",
             'preamble': "The following users hold the privilege:",
          },
          'group_powerful_priv': {
             'section': "description",
             'preamble': "The following groups hold the privilege:",
          },
       }
    },
    'WPC071': {
       'title': "Windows Users/Groups Hold Powerful Privilege: SeBackupPrivilege",
       'description': '''TODO SE_BACKUP_NAME TEXT("SeBackupPrivilege") Required to perform backup operations. This privilege causes the system to grant all read access control to any file, regardless of the access control list (ACL) specified for the file. Any access request other than read is still evaluated with the ACL. This privilege is required by the RegSaveKey and RegSaveKeyExfunctions. The following access rights are granted if this privilege is held: READ_CONTROL ACCESS_SYSTEM_SECURITY FILE_GENERIC_READ FILE_TRAVERSE''',
       'recommendation': '''Review the list of users below who hold this privilege.  Revoke it where it is not required - e.g. under 'Back up files and directories'  in secpol.msc.''',
       'supporting_data': {
          'user_powerful_priv': {
             'section': "description",
             'preamble': "The following users hold the privilege:",
          },
          'group_powerful_priv': {
             'section': "description",
             'preamble': "The following groups hold the privilege:",
          },
       }
    },
    'WPC072': {
       'title': "Windows Users/Groups Hold Powerful Privilege: SeCreatePagefilePrivilege",
       'description': '''TODO SE_CREATE_PAGEFILE_NAME TEXT("SeCreatePagefilePrivilege") Required to create a paging file. .''',
       'recommendation': '''Review the list of users below who hold this privilege.  Revoke it where it is not required - e.g. under 'Create a pagefile'  in secpol.msc.''',
       'supporting_data': {
          'user_powerful_priv': {
             'section': "description",
             'preamble': "The following users hold the privilege:",
          },
          'group_powerful_priv': {
             'section': "description",
             'preamble': "The following groups hold the privilege:",
          },
       }
    },
    'WPC073': {
       'title': "Windows Users/Groups Hold Powerful Privilege: SeCreateTokenPrivilege",
       'description': '''TODO SE_CREATE_TOKEN_NAME TEXT("SeCreateTokenPrivilege") Required to create a primary token.''',
       'recommendation': '''Review the list of users below who hold this privilege.  Revoke it where it is not required - e.g. under 'Create a token object'  in secpol.msc.''',
       'supporting_data': {
          'user_powerful_priv': {
             'section': "description",
             'preamble': "The following users hold the privilege:",
          },
          'group_powerful_priv': {
             'section': "description",
             'preamble': "The following groups hold the privilege:",
          },
       }
    },
    'WPC074': {
       'title': "Windows Users/Groups Hold Powerful Privilege: SeDebugPrivilege",
       'description': '''TODO SE_DEBUG_NAME TEXT("SeDebugPrivilege") Required to debug and adjust the memory of a process owned by another account.''',
       'recommendation': '''Review the list of users below who hold this privilege.  Revoke it where it is not required - e.g. under 'Debug programs'  in secpol.msc.''',
       'supporting_data': {
          'user_powerful_priv': {
             'section': "description",
             'preamble': "The following users hold the privilege:",
          },
          'group_powerful_priv': {
             'section': "description",
             'preamble': "The following groups hold the privilege:",
          },
       }
    },
    'WPC075': {
       'title': "Windows Users/Groups Hold Powerful Privilege: SeEnableDelegationPrivilege",
       'description': '''TODO SE_ENABLE_DELEGATION_NAME TEXT("SeEnableDelegationPrivilege") Required to mark user and computer accounts as trusted for delegation.''',
       'recommendation': '''Review the list of users below who hold this privilege.  Revoke it where it is not required - e.g. under 'Enable computer and user accounts to be trusted for delegation'  in secpol.msc.''',
       'supporting_data': {
          'user_powerful_priv': {
             'section': "description",
             'preamble': "The following users hold the privilege:",
          },
          'group_powerful_priv': {
             'section': "description",
             'preamble': "The following groups hold the privilege:",
          },
       }
    },
    'WPC076': {
       'title': "Windows Users/Groups Hold Powerful Privilege: SeLoadDriverPrivilege",
       'description': '''TODO SE_LOAD_DRIVER_NAME TEXT("SeLoadDriverPrivilege") Required to load or unload a device driver.''',
       'recommendation': '''Review the list of users below who hold this privilege.  Revoke it where it is not required - e.g. under 'Load and unload device drivers'  in secpol.msc.''',
       'supporting_data': {
          'user_powerful_priv': {
             'section': "description",
             'preamble': "The following users hold the privilege:",
          },
          'group_powerful_priv': {
             'section': "description",
             'preamble': "The following groups hold the privilege:",
          },
       }
    },
    'WPC077': {
       'title': "Windows Users/Groups Hold Powerful Privilege: SeMachineAccountPrivilege",
       'description': '''TODO SE_MACHINE_ACCOUNT_NAME TEXT("SeMachineAccountPrivilege") Required to create a computer account.''',
       'recommendation': '''Review the list of users below who hold this privilege.  Revoke it where it is not required - e.g. under 'Add workstations to domain'  in secpol.msc.''',
       'supporting_data': {
          'user_powerful_priv': {
             'section': "description",
             'preamble': "The following users hold the privilege:",
          },
          'group_powerful_priv': {
             'section': "description",
             'preamble': "The following groups hold the privilege:",
          },
       }
    },
    'WPC078': {
       'title': "Windows Users/Groups Hold Powerful Privilege: SeManageVolumePrivilege",
       'description': '''Microsoft warns that "Use caution when assigning this user right. Users with this user right can explore disks and extend files in to memory that contains other data. When the extended files are opened, the user might be able to read and modify the acquired data."''',
       'recommendation': '''Review the list of users below who hold this privilege.  Revoke it where it is not required - e.g. under 'Manage the files on a volume / Perform volume maintenance tasks'  in secpol.msc.''',
       'supporting_data': {
          'user_powerful_priv': {
             'section': "description",
             'preamble': "The following users hold the privilege:",
          },
          'group_powerful_priv': {
             'section': "description",
             'preamble': "The following groups hold the privilege:",
          },
       }
    },
    'WPC079': {
       'title': "Windows Users/Groups Hold Powerful Privilege: SeRelabelPrivilege",
       'description': '''TODO SE_RELABEL_NAME TEXT("SeRelabelPrivilege") Required to modify the mandatory integrity level of an object.''',
       'recommendation': '''Review the list of users below who hold this privilege.  Revoke it where it is not required - e.g. under 'Modify an object label'  in secpol.msc.''',
       'supporting_data': {
          'user_powerful_priv': {
             'section': "description",
             'preamble': "The following users hold the privilege:",
          },
          'group_powerful_priv': {
             'section': "description",
             'preamble': "The following groups hold the privilege:",
          },
       }
    },
    'WPC080': {
       'title': "Windows Users/Groups Hold Powerful Privilege: SeRestorePrivilege",
       'description': '''Some users have been granted the ability to write to any file or directory, even if object permissions don't allow it.  Specifically, check for the following permissions can be bypassed by the affected users: WRITE_DAC WRITE_OWNER ACCESS_SYSTEM_SECURITY FILE_GENERIC_WRITE FILE_ADD_FILE FILE_ADD_SUBDIRECTORY DELETE.  Note that it is therefore possible to change the owner or the DACL, meaning that read access is also possible.  This allows the affected users to take full control of any file or directory (but not services?).  This privilege is one of the prerequisites for users to be able to load backups of registry hives into the registry (RegLoadKey).  Note that this privilege is normally granted to members of the local administrators group and this does not infer a security weakness as the users have administration rights already.''',
       'recommendation': '''Review the list of users below who hold this privilege.  Revoke it where it is not required - e.g. under 'Restore files and directories'  in secpol.msc.''',
       'supporting_data': {
          'user_powerful_priv': {
             'section': "description",
             'preamble': "The following users hold the privilege:",
          },
          'group_powerful_priv': {
             'section': "description",
             'preamble': "The following groups hold the privilege:",
          },
       }
    },
    'WPC081': {
       'title': "Windows Users/Groups Hold Powerful Privilege: SeShutdownPrivilege",
       'description': '''Some users are allowed to shut down the computer.  This may aid an attacker in exploiting a pre-existing vulnerability - e.g. after replacig a program that run at boot time.  Alone, it probably doesn't constitute a privilege escalation vector.  It could lead to desruption of the system, though.''',
       'recommendation': '''Review the list of users below who hold this privilege.  Revoke it where it is not required - e.g. under 'Shut down the system'  in secpol.msc.''',
       'supporting_data': {
          'user_powerful_priv': {
             'section': "description",
             'preamble': "The following users hold the privilege:",
          },
          'group_powerful_priv': {
             'section': "description",
             'preamble': "The following groups hold the privilege:",
          },
       }
    },
    'WPC082': {
       'title': "Windows Users/Groups Hold Powerful Privilege: SeSyncAgentPrivilege",
       'description': '''TODO SE_SYNC_AGENT_NAME TEXT("SeSyncAgentPrivilege") Required for a domain controller to use the LDAP directory synchronization services. This privilege enables the holder to read all objects and properties in the directory, regardless of the protection on the objects and properties. By default, it is assigned to the Administrator and LocalSystem accounts on domain controllers.''',
       'recommendation': '''Review the list of users below who hold this privilege.  Revoke it where it is not required - e.g. under 'Synchronize directory service data'  in secpol.msc.''',
       'supporting_data': {
          'user_powerful_priv': {
             'section': "description",
             'preamble': "The following users hold the privilege:",
          },
          'group_powerful_priv': {
             'section': "description",
             'preamble': "The following groups hold the privilege:",
          },
       }
    },
    'WPC083': {
       'title': "Windows Users/Groups Hold Powerful Privilege: SeTakeOwnershipPrivilege",
       'description': '''Some users have been granted the ability to take ownership of any object, even if object permissions don't grant them "Take Ownership" rights.  This allows the affected users to take full control of any object (file, directory, service, etc.).  This could trivially lead to the user escallating rights to local administrator.  Note that this privilege is normally granted to members of the local administrators group and this does not infer a security weakness as the users have administration rights already.''',
       'recommendation': '''Review the list of users below who hold this privilege.  Revoke it where it is not required - e.g. under 'Take ownership of files or other objects'  in secpol.msc.''',
       'supporting_data': {
          'user_powerful_priv': {
             'section': "description",
             'preamble': "The following users hold the privilege:",
          },
          'group_powerful_priv': {
             'section': "description",
             'preamble': "The following groups hold the privilege:",
          },
       }
    },
    'WPC084': {
       'title': "Windows Users/Groups Hold Powerful Privilege: SeTcbPrivilege",
       'description': '''TODO SE_TCB_NAME TEXT("SeTcbPrivilege") This privilege identifies its holder as part of the trusted computer base. Some trusted protected subsystems are granted this privilege.''',
       'recommendation': '''Review the list of users below who hold this privilege.  Revoke it where it is not required - e.g. under 'Act as part of the operating system'  in secpol.msc.''',
       'supporting_data': {
          'user_powerful_priv': {
             'section': "description",
             'preamble': "The following users hold the privilege:",
          },
          'group_powerful_priv': {
             'section': "description",
             'preamble': "The following groups hold the privilege:",
          },
       }
    },
    'WPC085': {
       'title': "Windows Users/Groups Hold Powerful Privilege: SeTrustedCredManAccessPrivilege",
       'description': '''TODO SE_TRUSTED_CREDMAN_ACCESS_NAME TEXT("SeTrustedCredManAccessPrivilege") Required to access Credential Manager as a trusted caller.''',
       'recommendation': '''Review the list of users below who hold this privilege.  Revoke it where it is not required - e.g. under 'Access Credential Manager as a trusted caller'  in secpol.msc.''',
       'supporting_data': {
          'user_powerful_priv': {
             'section': "description",
             'preamble': "The following users hold the privilege:",
          },
          'group_powerful_priv': {
             'section': "description",
             'preamble': "The following groups hold the privilege:",
          },
       }
    },
    'WPC086': {
       'title': "Share Level Permissions Allow Access By Non-Admin Users",
       'description': '''The share-level permissions on some Windows file shares allows access by non-administrative users.  This can often be desirable, in which case this issue can be ignored.  However, sometimes it can allow data to be stolen or programs to be maliciously modified.  NB: Setting strong NTFS permissions can sometimes mean that data which seems to be exposed on a share actually isn't accessible.''',
       'recommendation': '''Review the share-level permissions that have been granted to non-administrative users and revoke access where possible.  Share-level permissions can be viewed in Windows Explorer: Right-click folder | Sharing and Security | "Sharing" tab | "Permissions" button (for XP - other OSs may vary slightly).''',
       'supporting_data': {
          'non_admin_shares': {
             'section': "description",
             'preamble': "The following non-admin users have been granted FILE_READ_DATA permission on shares:",
          },
       }
    },
    'WPC087': {
       'title': "Directory Creation Allowed On Drive Root",
       'description': '''Some of the local drive roots allow non-administrative users to create directories.  This could provide attackers with a place to stash hacking tools, or proive legitimacy to malware they are seeking to get other users to run.  It is relatively common to allow the creation of directories in the drive root, but it probably isn't required for normal operation.

NB: This issue has only been reported for NTFS filesystems.  Other non-NTFS file system may also allow this behaviour.  A separate issue is reported for non-NTFS filesystems.''',
       'recommendation': '''Modify the permissions on the drive roots to only allow administrators to create directories.  Revoke this permission from low-privileged users.''',
       'supporting_data': {
          'dir_add_dir': {
             'section': "description",
             'preamble': "The following drives allow non-administrative users to create directories in to their root:",
          },
       }
    },
    'WPC088': {
       'title': "Read Permissions Allowed On Event Log File",
       'description': '''Some of the Event Log files could be read by non-administrative users.  This may allow attackers to view log information they weren't intended to see.  This can help them to determine if they are being monitored or to access information which may help in other attacks.''',
       'recommendation': '''Modify the permissions on the above files to allow only administrators read access.  Revoke read access from low-privileged users.''',
       'supporting_data': {
          'file_read': {
             'section': "description",
             'preamble': "The files below could be changed by non-administrative users:",
          },
       }
    },
    'WPC089': {
       'title': "Missing Security Patches Leave System At Risk From Public Exploit Code",
       'description': '''The system was determined to be missing some security patches.  The patches concerned fix vulnerabilities for which public exploit code exists.''',
       'recommendation': '''Apply the latest security patches.''',
       'supporting_data': {
          'exploit_list': {
             'section': "description",
             'preamble': "The following public exploits are believed to be effective against the system:",
          },
       }
    },
    'WPC090': {
       'title': "Screen Saver Is Not Password Protected",
       'description': '''Some system users were found to not use password protected screen savers.  This may leave unattended systems open to abuse.''',
       'recommendation': '''Ensure that all accounts that are logged into interactively use a password protected screen saver.''',
       'supporting_data': {
          'user_reg_keys': {
             'section': "description",
             'preamble': "The following registry keys indicate the absence of a password-protected screen saver for some users:",
          },
       }
    },
    'WPC091': {
       'title': "Screen Saver Timeout Is Too Long",
       'description': '''The elapsed time before the password-protected screen saver activates is longer than 10 mins for some users.  This may leave unattended systems open to abuse for longer than necessary.''',
       'recommendation': '''For user accounts that are logged into interactively, configure a suitable screen saver timeout to protect idle systems.  The precise timeout required may vary depending on the environment.''',
       'supporting_data': {
          'user_reg_keys': {
             'section': "description",
             'preamble': "The registy keys below show the timeout in seconds:",
          },
       }
    },
    'WPC092': {
       'title': "Host Is In A Domain",
       'description': '''The host audited is in a domain.  While this is a not a security issue in itself, the inherent trust of other systems could mean that this host is vulnerable to attack even if the local security audit identifies no siginficant security issues.''',
       'recommendation': '''Ensure that the systems and accounts trusted by this host are also secure.  This may require significantly more auditing.''',
       'supporting_data': {
          'dc_info': {
             'section': "description",
             'preamble': "The following domain information was retrieved:",
          },
       }
    },
    'WPC093': {
       'title': "Files and Directories Can Be Modified By Non-Admin Users",
       'description': '''Some files and/or directories can be modified by non-admin users.''',
       'recommendation': '''Manual investigation is required to determine any impact.  This is just a generic issue.''',
       'supporting_data': {
          'writable_dirs': {
             'section': "description",
             'preamble': "The following directories were writeable by non-admin users:",
          },
          'writable_files': {
             'section': "description",
             'preamble': "The following files were writeable by non-admin users:",
          },
       }
    },
    'WPC094': {
       'title': "User Access Control Setting Allows Malware to Elevate Without Prompt",
       'description': '''The security policy setting 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Elevate without prompting' or 'Prompt for consent for non-Windows binaries' (default).  This allows malicious programs to elevate without the user agreeing.  Metasploit and other free tools can perform such escalation.''',
       'recommendation': '''Alter security policy to 'Prompt for consent' or stronger setting.''',
       'supporting_data': {
          'reg_key_value': {
             'section': "description",
             'preamble': "The following registry key shows the current policy setting:",
          },
       }
    },
    'WPC095': {
       'title': "User Access Control Is Not Applied To Builtin Administrator Account",
       'description': '''The RID 500 account does not run in admin approval mode.  If this user account were to be compromised, UAC would not provide any mitigation.''',
       'recommendation': '''Enable the security policy setting 'User Account Control: Use Admin Approval Mode for the built-in Administrator account'.''',
       'supporting_data': {
          'reg_key_value': {
             'section': "description",
             'preamble': "The following registry key shows the current policy setting:",
          },
       }
    },
    'WPC096': {
       'title': "User Access Control Not Enabled",
       'description': '''UAC has been disabled on the system.  It will not mitigate the compromise of administrative accounts.  This is not the default configuration.''',
       'recommendation': '''Enable the security policy setting 'User Account Control: Run all administrators in Admin Approval Mode'.''',
       'supporting_data': {
          'reg_key_value': {
             'section': "description",
             'preamble': "The following registry key shows the current policy setting:",
          },
       }
    },
    'WPC097': {
       'title': "User Access Control Does not Prompt on the Secure Desktop",
       'description': '''UAC has not been configured to use the secure desktop when prompting for elevation.  It might be possible to subvert the consent process and trick a user into approving elevation of malware.''',
       'recommendation': '''Enable the security policy setting 'User Account Control: Switch to the secure desktop when prompting for elevation'.''',
       'supporting_data': {
          'reg_key_value': {
             'section': "description",
             'preamble': "The following registry key shows the current policy setting:",
          },
       }
    },
    'WPC098': {
       'title': "LANMan Authentication Level Not Set To Mandate NTLMv2",
       'description': '''The system has not been configured to mandate the use of NTLMv2 when acting as a client and a server.  This leaves network communications more open to attack.''',
       'recommendation': '''Set the security policy setting 'Network security: LAN Manager authentication level' to 'Send NTLMv2 response only\refuse LM & NTLM'.''',
       'supporting_data': {
          'reg_key_value': {
             'section': "description",
             'preamble': "The following registry key shows the current policy setting:",
          },
       }
    },
    'WPC099': {
       'title': "Weak LANMan Password Hash Used In SAM",
       'description': '''LANMan password hashes are stored in the SAM.  If the system were to be compromised, it would be much easier for an attacker to recover passwords than if the use of LANman had been disabled.''',
       'recommendation': '''Set the security policy setting 'Network security: Do not store LAN Manager hash value on next password change' to Enabled.''',
       'supporting_data': {
          'reg_key_value': {
             'section': "description",
             'preamble': "The following registry key shows the current policy setting:",
          },
       }
    },
    'WPC100': {
       'title': "System Caches Logon Credentails",
       'description': '''The system is configured to cache a number of logon credentials in case the domain controller is unavaialble next time a user tries to log in.  Such data can be accessed and potentially used to recover domain passwords in the event of a compromise.''',
       'recommendation': '''Set the security policy setting 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' 0 if possible - though this might not be a usable configuration for laptops.''',
       'supporting_data': {
          'reg_key_value': {
             'section': "description",
             'preamble': "The following registry key shows the current policy setting:",
          },
       }
    },
    'WPC101': {
       'title': "SMB Server Does Not Mandate Packet Signing",
       'description': '''SMB clients that connect to this server are not forced to use signing.  As signing protects data from modification in transit, clients may end up receiving data that has been maliciously altered by an attacker.  This could lead to a compromise of the client if it opens or runs the files accessed - particularly in the case of a domain member access group policy information.''',
       'recommendation': '''Set the security policy setting 'Microsoft network server: Digitally sign communications (always)' to Enabled.''',
       'supporting_data': {
          'reg_key_value': {
             'section': "description",
             'preamble': "The following registry key shows the current policy setting:",
          },
       }
    },
    'WPC102': {
       'title': "SMB Client Does Not Mandate Packet Signing",
       'description': '''SMB connection originating from this host might not negotiate pack signing.  As signing protects data from modification in transit, clients may end up sending or receiving data that has been maliciously altered by an attacker.  This could lead to a compromise of the client or server.''',
       'recommendation': '''Set the security policy setting 'Microsoft network server: Digitally sign communications (always)' to Enabled.''',
       'supporting_data': {
          'reg_key_value': {
             'section': "description",
             'preamble': "The following registry key shows the current policy setting:",
          },
       }
    },
    'WPC103': {
       'title': "Screen Saver Does Not Activate Automatically",
       'description': '''No screensaver was configured for some users.''',
       'recommendation': '''For user accounts that are logged into interactively, configure a suitable screen saver timeout to protect idle systems.  The precise timeout required may vary depending on the environment.''',
       'supporting_data': {
          'user_reg_keys': {
             'section': "description",
             'preamble': "The registy keys below show if the screen saver is active or inactive:",
          },
       }
    },
    'WPC104': {
       'title': "Thread Security Descriptor Allows Access To Non-Admin Users (TODO)",
       'description': '''TODO.  Writeme+Fixme.  This issue currently get false positives about non-priv users being able to change their own process.  Also needs to take account of RESTRICTED processes http://blogs.msdn.com/b/aaron_margosis/archive/2004/09/10/227727.aspx http://msdn.microsoft.com/en-us/library/ms972827.aspx''',
       'recommendation': '''TODO''',
       'supporting_data': {
          'thread_perms': {
             'section': "description",
             'preamble': "TODO",
          },
       }
    },
    'WPC105': {
       'title': "Token Security Descriptor Allows Access To Non-Admin Users (TODO)",
       'description': '''TODO''',
       'recommendation': '''TODO''',
       'supporting_data': {
          'token_perms': {
             'section': "description",
             'preamble': "TODO",
          },
       }
    },
    'WPC106': {
       'title': "Terminal Server Running in Relaxed Security Mode",
       'description': '''The builtin security pricinpal NT AUTHORITY\TERMINAL SERVER USER is being applied to users who log in via Terminal Servies.  This is a powerful security principal able to change ciritical areas of the filesystem and registry.  It is intended to be used for legacy application that do not function properly under Terminal Services.  However, it has the side effect of allowing privilege escalation via tampering with crticial files such as program files.''',
       'recommendation': '''Use Full Security Mode instead of Relaxed Security Mode.''',
       'supporting_data': {
          'reg_key_value': {
             'section': "description",
             'preamble': "The following registry key shows the current policy setting:",
          },
       }
    },
    'WPC107': {
       'title': "Current Working Directory Used For DLL Search - Including Network Locations",
       'description': '''CWDIllegalInDllSearch was set to 0.  This causes applications (by default) to load DLLs from the current directory - even for network locations.  This can lead to malicious DLLs being executed in some attack scenarios.  Note that KB2264107 needs to be installed to enable more secure settings - not checked for.  Also apps can be secured individually - also not checked for.''',
       'recommendation': '''Consider setting CWDIllegalInDllSearch to 1, 2 or 0xFFFFFFFF to improve security - though this may break some applications.  See http://support.microsoft.com/kb/2264107 for further information including how to set CWDIllegalInDllSearch on a per-application basis.''',
       'supporting_data': {
          'reg_key_value': {
             'section': "description",
             'preamble': "The following registry key shows the current policy setting:",
          },
       }
    },
    'WPC108': {
       'title': "User Password Stored Using Reversible Encryption",
       'description': '''TODO UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED was enabled for a user''',
       'recommendation': '''Attackers undertaking post-exploitation activities could recover the cleartext password.  TODO''',
       'supporting_data': {
          'username': {
             'section': "description",
             'preamble': "The following users are affected:",
          },
       }
    },
    'WPC109': {
       'title': "User Password Is Too Old",
       'description': '''TODO The password had not been changed for over 1 year for some accounts that were neither locked nor disabled.''',
       'recommendation': '''TODO''',
       'supporting_data': {
          'password_age': {
             'section': "description",
             'preamble': "The following users are affected:",
          },
       }
    },
    'WPC110': {
       'title': "User Password Not Required",
       'description': '''TODO UF_PASSWD_NOTREQD was set for some accounts that were neither locked nor disabled''',
       'recommendation': '''TODO''',
       'supporting_data': {
          'username': {
             'section': "description",
             'preamble': "The following users are affected:",
          },
       }
    },
    'WPC111': {
       'title': "Some Users Cannot Change Their Password",
       'description': '''TODO UF_PASSWD_CANT_CHANGE was set for some accounts that were neither locked nor disabled''',
       'recommendation': '''TODO''',
       'supporting_data': {
          'username': {
             'section': "description",
             'preamble': "The following users are affected:",
          },
       }
    },
    'WPC112': {
       'title': "Some Users Have Passwords That Don't Expire",
       'description': '''TODO UF_DONT_EXPIRE_PASSWD was set for some accounts that were neither locked nor disabled''',
       'recommendation': '''TODO''',
       'supporting_data': {
          'username': {
             'section': "description",
             'preamble': "The following users are affected:",
          },
       }
    },
    'WPC113': {
       'title': "Some User Accounts Trusted For Delegation",
       'description': '''TODO UF_TRUSTED_FOR_DELEGATION was set for some accounts that were neither locked nor disabled''',
       'recommendation': '''TODO''',
       'supporting_data': {
          'username': {
             'section': "description",
             'preamble': "The following users are affected:",
          },
       }
    },
    'WPC114': {
       'title': "Some User Accounts Trusted To Authenticate For Delegation",
       'description': '''TODO UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION was set for some accounts that were neither locked nor disabled''',
       'recommendation': '''TODO''',
       'supporting_data': {
          'username': {
             'section': "description",
             'preamble': "The following users are affected:",
          },
       }
    },
    'WPC115': {
       'title': "Non-Admin Can Change Registry Keys Containing Executables",
       'description': '''A walk of the registry found some registry keys that can be changed by non-admin users (KEY_SET_VALUE permission).  The data in some of those keys appears to be an executable (e.g. .exe, .py, .dll).  This is a simple regular-expression match so may report false positives.  In some instances it may be possible for an low-privilged user to cause a higher privileged process to launch an executable of their choosing.''',
       'recommendation': '''Set strong registry permissions on any values that high privileged processes use to launch executable code.''',
       'supporting_data': {
          'regkey_value_data_perms': {
             'section': "description",
             'preamble': "The following registry value are affected:",
          },
       }
    },
    'WPC116': {
       'title': "Non-Admin Can Change File Paths In Registry",
       'description': '''A walk of the registry found some registry keys that can be changed by non-admin users (KEY_SET_VALUE permission).  The data in some of those keys appears to be a file or directory path (e.g. c:\..., \\host\share, \\.\pipe\...).  This is a simple regular-expression match so may report false positives.  In some instances it may be possible for an low-privilged user to cause other users to follow a malicious UNC file path, forcing disclosure of their netntlm password hash or SMB relay attack.  Other path-based attacks may also be possible.''',
       'recommendation': '''Set strong registry permissions on any values that high privileged processes use to determine paths.''',
       'supporting_data': {
          'regkey_value_data_perms': {
             'section': "description",
             'preamble': "The following registry value are affected:",
          },
       }
    },
    'WPC117': {
       'title': "Non-Admin Can Change Registry Paths That Are Stored In The Registry",
       'description': '''A walk of the registry found some registry keys that can be changed by non-admin users (KEY_SET_VALUE permission).  The data in some of those keys appears to be a registry path (e.g. SYSTEM\...).  This is a simple regular-expression match so may report false positives.  In some instances it may be possible for an low-privilged user to cause other users to follow read malicious data from the registry.  The may or may not lead to privilege escalation depending on the context.''',
       'recommendation': '''Set strong registry permissions on any values that high privileged processes use to determine registry paths.''',
       'supporting_data': {
          'regkey_value_data_perms': {
             'section': "description",
             'preamble': "The following registry value are affected:",
          },
       }
    },
    'WPC118': {
       'title': "Non-Admin Can Change IP Addresses That Are Stored In The Registry",
       'description': '''A walk of the registry found some registry keys that can be changed by non-admin users (KEY_SET_VALUE permission).  The data in some of those keys appears to be an IP Address.  This is a simple regular-expression match so may report false positives.  In some instances it may be possible for an low-privilged user to cause other users to connect to a malicious IP address.  This may facilitate other attacks such as man-in-the-middle.''',
       'recommendation': '''Set strong registry permissions on any values that high privileged processes use to determine IP addresses.''',
       'supporting_data': {
          'regkey_value_data_perms': {
             'section': "description",
             'preamble': "The following registry value are affected:",
          },
       }
    },
    'WPC119': {
       'title': "Non-Admin Can Change Usernames That Are Stored In The Registry",
       'description': '''A walk of the registry found some registry keys that can be changed by non-admin users (KEY_SET_VALUE permission).  The data in some of those keys appears to be a username.  This is a simple regular-expression match so may report false positives.  In some instances it may be possible for an low-privilged user to cause another process to run as or otherwise affect a different user account.''',
       'recommendation': '''Set strong registry permissions on any values that high privileged processes use to determine usernames.''',
       'supporting_data': {
          'regkey_value_data_perms': {
             'section': "description",
             'preamble': "The following registry value are affected:",
          },
       }
    },
    'WPC120': {
       'title': "Non-Admin Can Change Executable For Scheduled Task",
       'description': '''The NTFS permissions on some of the executables run by scheduled tasks (schtasks /query /xml) allow modification by non-admin users.  For tasks run as low-privileged users, false positives may be reported (bug).''',
       'recommendation': '''Set strong file permissions on programs used by scheduled tasks.''',
       'supporting_data': {
          'scheduled_task_exe_perms': {
             'section': "description",
             'preamble': "The following scheduled tasks are affected:",
          },
       }
    },
}



# TODO: Manage auditing and security log - view and clear security log.  Disable per-object auditing.
# TODO: Log on locally - low priv users can exec commands if they have physical access.  Not required for service accounts.  Too voluminous?