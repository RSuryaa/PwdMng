from  mysql.connector import connect 
from prettytable import PrettyTable
from getpass import getpass
from cryptography.fernet import Fernet
import time, hashlib
import base64

def createUser(cur,username,passwd,host,newUserExist,masterKey):
    if not newUserExist:
        create_user = f"CREATE USER '{username}'@'{host}' IDENTIFIED BY '{passwd}'"
        cur.execute(create_user)
    else:
        try:
            testConnection = login(host,username,passwd)
            testConnection.close()
        except:
            print(f'Invalid MySQL credentials for {username}.')
            return None
    masterKey=hashlib.sha256(masterKey.encode()).hexdigest()
    try:
        cur.execute("INSERT INTO pwdhash VALUES(%s,%s,'NORMAL')", [username, masterKey])
    except:
        print('Error registering user! Check if user already registered in database')
    else:
        cur.execute(f"CREATE TABLE {username} (pid INT PRIMARY KEY, website VARCHAR(40), pwd_encrypted VARCHAR(100), last_updated timestamp)")
        print('User created successfully!', '='*30, sep='\n')

def getMasterKey(prompt='Enter master password (remember to write it down): '):
    # Makes user type master password twice for confirmation
    while True:
        atmpt1 = getpass(prompt)

        # To cancel setup
        if atmpt1 == '':
            return None

        atmpt2 = getpass("Enter Master Password again: ")

        if atmpt1 == atmpt2:
            masterKey = hashlib.sha256(atmpt1.encode()).hexdigest()
            del atmpt1, atmpt2
            break
        else:
            print("Master password does not match\n")
    
    print()
    return masterKey

def setup():
    host = input('Enter host id: ')
    username = 'root' # Only root user can install software for security reasons.
    passwd = getpass('Enter password of MySQL root account: ')

    con = login(host,username,passwd)
    cur = con.cursor()

    cur.execute('CREATE DATABASE IF NOT EXISTS PwdMng')
    cur.execute('USE PwdMng')
    cur.execute('CREATE TABLE IF NOT EXISTS pwdhash(username varchar(20), pwdhashed varchar(64), type varchar(6))')

    masterKey = getMasterKey()

    cur.execute("INSERT INTO pwdhash VALUES('root', %s,'ADMIN')", [masterKey])
    cur.execute('CREATE TABLE IF NOT EXISTS root(pid INT PRIMARY KEY, website VARCHAR(40), pwd_encrypted VARCHAR(100), last_updated timestamp)')
    con.commit()
    con.close()

def login(host_id, username, password, db=None):
    if not db:
        return connect(host=host_id,user=username,passwd=password)
    else:
        return connect(host=host_id,user=username,passwd=password,database=db)

def normalMenu(cur, username, masterKey, passwd):
    raise NotImplementedError

def adminMenu(cur, username, masterKey, passwd):  
    # Options for admin
    key=hashpwdmixer(masterKey,passwd)
    while True:
        print('Logged in as Admin')
        print('='*30)
        print('Options:\n')
        print('1. Create User')
        print('2. Delete New User')
        print('3. Grant/Revoke Privileges to Users')
        print('4. Enter New Password')
        print('5. List your Passwords')
        print('6. Search your Password')
        print('7. Delete your Password')
        print('8. Logout')
        print('='*30)
        ch = input('Enter your choice: ')

        if ch == '1':
            uname = input("Enter new username (must match with MySQL username): ")
            cur.execute('SELECT user from mysql.user')
            user_tuple = cur.fetchall()

            userExists = False
            for i in user_tuple:    # To check if user already exists in MySQL
                if uname in i:
                    userExists = True
                    break

            pwd = input("User's MySQL password: ")
            host = input("User's host: ")
            newMasterKey = getMasterKey("User's Master Key: ")

            createUser(cur, uname, pwd, host, userExists, newMasterKey)

        elif ch == '2':
            target = input('Username to be deleted: ')
            del_table = f'DROP TABLE IF EXISTS {target}'
            cur.execute(del_table)
            cur.execute("DELETE FROM pwdhash WHERE username = %s", [target])
            print('User deleted successfully')

        elif ch == '3':
            print('List of users registered in database:')
            cur.execute('SELECT username FROM pwdhash')
            for i in cur.fetchall():
                print(i[0])
            while True:
                command = input("Enter SQL Command to grant/revoke privilege: ")
                if command == None:
                    break
                cur.execute(command)
                quit = input('Do you want to execute another command? (Y/N): ')
                if quit not in 'yY':
                    break

        elif ch == '4':
            website = input('Website: ')
            webpwd = input('Password to store: ')
            webpwd = encrypt(webpwd,key)
            insertpwd(cur, website, webpwd, username)
            print('Password saved successfully...')
        
        elif ch == '5':
            pwdlist = retrievepwd(cur,username, key)
            table = PrettyTable()
            table.field_names = ['PID', 'Website', 'Password', 'LastUpdated']
            table.add_rows(pwdlist)

            print(table)
        
        else:
            return None

def hashpwdmixer(hash, pwd):
    key=''
    for i in range(min(len(hash),len(pwd))):
        key = key + hash[i] + pwd[i]
    key = key + hash[i+1:] + pwd[i+1:]
    length = len(key)
    while length != 32:
        if length>32:
            key=key[:-1]
        else:
            key=key+'#'
        length = len(key)
    return key

def insertpwd(cur, website, pwd, user):
    cur.execute(f'SELECT COUNT(*) FROM {user}')
    PID = cur.fetchone()[0]+1
    timeStamp = convertTime(time.localtime())
    add_pwd ="INSERT INTO {} VALUES({}, '{}', '{}', '{}')".format(user, PID, website, pwd.decode(), timeStamp)
    cur.execute(add_pwd)
    cur.execute('COMMIT')

def retrievepwd(cur, user, key):
    cur.execute("SELECT * FROM {}".format(user))
    pwdtuple = cur.fetchall()
    pwdlist = []
    for i in range(len(pwdtuple)):
        pwdlist.append(pwdtuple[i][0:2]+(decrypt(pwdtuple[i][2],key),)+ (pwdtuple[i][3],))
    return pwdlist

def encrypt(pwd,key):
    key = bytes(key, 'utf-8')
    key = base64.b64encode(key)
    fernet=Fernet(key)
    return fernet.encrypt(pwd.encode())

def decrypt(encrpwd,key):
    key = bytes(key, 'utf-8')
    key = base64.b64encode(key)
    fernet = Fernet(key)
    return fernet.decrypt(encrpwd).decode()

def convertTime(timetuple):  
    # Converts time to valid format for entry into MYSQL database
    return '{}{}{}{}{}{}'.format(timetuple.tm_year,timetuple.tm_mon,timetuple.tm_mday,timetuple.tm_hour,timetuple.tm_min,timetuple.tm_sec)

#insertpwd(b,input(),input())

def main():
    while True:
        print('Welcome to Password Manager...')
        print('='*30)
        print('Options:')
        print('1. Setup (for fresh installation)')
        print('2. Admin Login (Can create and delete Users)')  # Only admin can delete and create new users
        print('3. Login')
        print('4. Exit')
        print('='*30)

        ch=input('What do you want to do?\n... ')

        if ch == '3':  
            # Logs in as a normal user and hands over control to normalMenu()
            hostid = input('Enter host id: ')
            username = input('Enter username: ')
            passwd = getpass('Enter MySQL Password: ')
            masterKey = getpass('Enter Master Password: ')
            masterKey = hashlib.sha256(masterKey.encode()).hexdigest()

            con = login(hostid, username, passwd, 'pwdmng')
            cur = con.cursor()
            cur.execute("SELECT * FROM pwdhash")
            
            for i in cur.fetchall():
                if i == (username, masterKey):
                    normalMenu(cur, username, masterKey, passwd)
                    break
                else:
                    print('No such User exists in database! Check if account exists!')
            con.close()

        elif ch == '2':  
            # Logs in as an Admin and hands over control to adminMenu()
            # (Requires GRANT, REVOKE, CREATE, CREATE USER and DROP privileges on all tables) 
            hostid = input('Enter hostid: ')
            username = input('Enter username: ')
            passwd = getpass('Enter MySQL Password: ')
            masterKey = getpass('Enter Master Password: ')
            masterKey = hashlib.sha256(masterKey.encode()).hexdigest()

            con = login(hostid, username, passwd, 'pwdmng')
            cur = con.cursor()
            cur.execute("SELECT * FROM pwdhash")
            
            for i in cur.fetchall():
                if i[0:2] == (username, masterKey):
                    adminMenu(cur, username, masterKey, passwd)
                    break
                else:
                    print('No such User exists in database! Check if account exists!')
            con.close()

        elif ch=='1':
            setup()
        
        else:
            print('Exiting the program...')
            break
        print()

main()
