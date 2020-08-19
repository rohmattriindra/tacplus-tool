#!/usr/bin/python3

import paramiko
import getpass
import time
import sys, socket

print("-"*35)
print("Tacacs user configuration tools")
print("-"*35)

orange = "\033[93m{}\033[00m"
green = "\033[92m{}\033[00m"
red = "\033[91m{}\033[00m"
tacplus_path = "/etc/tacacs+/tac_plus.conf"
google_auth_path = "/home/*/.google_authenticator"
list_tac_svr = ["192.168.38.235","192.168.100.235"]

host = str(input("Input IP Address Tacacs: "))
while host not in list_tac_svr:
    print (red.format("Incorret, IP Address that you entered is not tacacs server:"))
    host = str(input("Input IP Address Tacacs: "))
username = input("Username: ")
password = getpass.getpass("Password: ")

try:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname=host, username=username, password=password, timeout=10)
except paramiko.AuthenticationException as error:
    print ("Authentication failed when connecting to " + red.format(host) + ", Please try again") 
    sys.exit(1)
except socket.error as error:
    print (red.format("Connection Timeout"))
    sys.exit(1)

def main_menu():
    print (30 * '-')
    print ("   M A I N - M E N U")
    print (30 * '-')
    print ("A. Show User")
    print ("B. Check Service tacplus")
    print ("C. Create User")
    print ("D. Remove User")
    print ("E. Edit Password")
    print ("F. Exit")
    print (30 * '-')
    choice = input("Input choice: ")
    print()

    if choice == "A" or choice =="a":
        show_configuration()
    elif choice == "B" or choice =="b":
        show_service_tacplus()
    elif choice == "C" or choice =="c":
        add_user()
    elif choice == "D" or choice =="d":
        remove_user()
    elif choice == "E" or choice =="e":
        edit_password()
    elif choice == "F" or choice == "f":
        sys.exit()
    else:
        print(orange.format("Invalid choice!! , Please input based on Menu"))
        print()
        main_menu()

def show_configuration():
    commands = ["cat " + tacplus_path + " | grep user", "ls -al "+ google_auth_path ]
    print ("Read file on tacacs configuration and ownership google_authenticator file")
    print()
    for command in commands:
        stdin, stdout, stderr = ssh.exec_command(command)
        tac = stdout.readlines()
        output = "\n".join([line.rstrip() for line in tac])
        print(green.format(output))
        print()
    main_menu()

def show_service_tacplus():
    stdin, stdout, stderr = ssh.exec_command("systemctl status tacacs_plus.service | grep Active")
    tac = stdout.readlines()
    output = "\n".join([line.rstrip() for line in tac])
    print(75 * "-")
    print (green.format(output))
    print(75 * "-")
    print()
    main_menu()

def add_user():
    print ("Menu Add User")
    user = input("input username: ")
    passwd = getpass.getpass("input password: ")
    member = input ("input roles " + orange.format("[netadmin or netoperator]") + ": ")
    while True:
        try:
            if member in ["netadmin","netoperator"]:                
                stdin, stdout, stderr = ssh.exec_command("useradd -m " + user + " -p $(openssl passwd -1 '"+ passwd + "')")
                time.sleep(3)
                print()
                print("[-] Create user "+ orange.format(user) +" on linux server..."+ green.format(" done"))
                time.sleep(3)
                remote_open_file = ssh.open_sftp()
                fileobject = remote_open_file.file(tacplus_path, 'a')
                fileobject.write("user = " + str(user) + " { member = "+ str(member) + " service = junos-exec { local-user-name = remote-admin }}"+ "\n")
                print("[-] Create user "+ orange.format(user) +" on tacacs configuration ..."+ green.format(" done"))
                time.sleep(3)
                stdin, stdout, stderr = ssh.exec_command("google-authenticator -s /home/"+ user +"/.google_authenticator \
                                                         -t -f -r 3 -R 30 -d -l" + user + " -i Organization-Tacplus -w 17 | grep https")
                print ("[-] Create OTP for user " + orange.format(user) + green.format("...done"))
                otp = stdout.readlines()
                output_otp = "\n".join([line.rstrip() for line in otp])
                time.sleep(3)
                stdin, stdout, stderr = ssh.exec_command("chown -R "+ user +":"+ user + " /home/"+user+"/.google_authenticator")
                print ("[-] Change ownership "+ orange.format("/home/"+user+"/.google_authenticator") + " from root to " + user + green.format("... done"))
                time.sleep(3)
                stdin, stdout, stderr = ssh.exec_command("systemctl restart tacacs_plus.service")
                print("[-] Restart service tacacs_plus...."+ green.format(" done"))
                time.sleep(5)
                print("[-] Completed!")
                print()
                print("Click the link below and then scan QR Code using google_authenticator apps")
                print()
                print("OTP for user " + user + " => " + green.format(output_otp))
                print()
                print(orange.format("!!Once the account created, don't recreate with the same account. it will be replace OTP with new one!!"))
                print()
                main_menu()
            else:
                print (red.format("Not allowed to create that roles !"))
                member = input("input roles [netadadmin, netoperator ] :")
                
    
        except Exception as unknown_error:
            print ("Error") 


def edit_password():
    print ("Edit Password")
    user = input("Please input your username : ")
    pass_edit = getpass.getpass("Please input new password : ")
    while (len(user) == 0) or (len(pass_edit)== 0):
        print(red.format("Empty, Please enter correctly"))
        user = input("Please input your username : ")
        pass_edit = getpass.getpass("Please input new password : ")
    while True:
        try:
            stdin, stdout, stderr = ssh.exec_command("cat " + tacplus_path + " | grep "+ user + "|  awk '{print $3}'")
            tes = stdout.readlines()
            output = "\n".join([line.rstrip() for line in tes])
            if user in output:
                print()
                print("[-] Update password user " + orange.format(user))
                time.sleep(3)
                stdin, stdout, stderr = ssh.exec_command("echo " + user + ":" + "'" + pass_edit + "'" + "| /usr/sbin/chpasswd" )
                print ("[-] Password has been updated!")
                main_menu()
            else:
                print(red.format("User account is not available on tacacs server"))
                while (len(user) == 0) or (len(pass_edit)== 0):
                    print(red.format("Empty, Please enter correctly"))
                    user = input("Please input your username : ")
                    pass_edit = getpass.getpass("Please input new password : ")

        except Exception as unknown_error:
            print ("Error")


def remove_user():
    print ("Menu remove user")
    user = input("Input your username: ")
    while len(user) == 0:
        print ("Username is empty!")
        user = input("Input Username : ")
    while True:
        try:
            stdin, stdout, stderr = ssh.exec_command("cat " + tacplus_path + " | grep "+ user + "|  awk '{print $3}'")
            list_user = stdout.readlines()
            output = "\n".join([line.rstrip() for line in list_user])
            if user in output:
                print("Found the user, please waittt..")
                stdin, stdout, stderr = ssh.exec_command("userdel -r " + user)
                time.sleep(3)
                print("[-] Remove username "+ orange.format(user) + " on linux system" + green.format(" done"))
                time.sleep(3)
                stdin, stdout, stderr = ssh.exec_command("sed -i /.*"+user+"*/d " + tacplus_path)
                print("[-] Remove username "+ orange.format(user) + " on tacacs configuration..."+ green.format(" done"))
                time.sleep(3)
                print("[-] Restart service tacacs_plus...."+ green.format(" done"))
                stdin, stdout, stderr = ssh.exec_command("systemctl restart tacacs_plus.service")
                time.sleep(5)
                print("[-] Completed!")
                time.sleep(2)
                print()
                main_menu()
            else:
                print(red.format("User account is not available on tacacs server"))
                user = input("Input your username: ")
                while len(user) == 0:
                    print ("Username is empty!")
                    user = input("Input Username : ")

        except Exception as unknown_error:
            print ("Error")

if __name__ == "__main__":
    while(True):
        print()
        print(green.format("Sucessfully Login to Server ") + host)
        print()
        main_menu()
