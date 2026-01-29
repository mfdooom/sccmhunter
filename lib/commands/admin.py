import typer
from lib.attacks.cmpivot import CONSOLE
from lib.logger import init_logger

app = typer.Typer()
COMMAND_NAME = 'admin'
HELP = 'Run administrative commands through the AdminService API.'

@app.callback(no_args_is_help=True, invoke_without_command=True)

def main(
    username        : str   = typer.Option(..., "-u",  help="Username"),
    password        : str   = typer.Option(..., '-p',  help="Password or NTLM hash. (LM:NT)"),
    ip              : str   = typer.Option(..., '-ip',  help = "IP address or hostname of site server. Must be hostname for Kerberos authentication"),
    domain          : str   = typer.Option(..., '-d',  help = "Domain"),
    kerberos        : bool  = typer.Option(False, '-k',help='Use Kerberos authentication'),
    dcip            : str   = typer.Option(None, '-dc-ip',help='IP address or FQDN of domain controller/KDC. Required for Kerberos authentication'),
    debug           : bool  = typer.Option(False, '-debug',help='Enable Verbose Logging'),
    auser           : str   = typer.Option(None, '-au', help="Optional script approval username"),
    apassword       : str   = typer.Option(None, '-ap', help="Optional script approval password")
):



    logs_dir = init_logger(debug)
    cmpivot = CONSOLE(username=username, password=password, ip=ip, domain=domain, kerberos=kerberos, dcip = dcip, debug=debug, logs_dir=logs_dir, auser=auser, apassword=apassword)
    cmpivot.run()
