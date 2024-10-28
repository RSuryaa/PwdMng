import mysql.connector as sqltor
from cryptography.fernet import Fernet
import time
import hashlib

def createUser(connection_dict,UserName,Passwd,host,newUserExist,masterKey):
    if not newUserExist:
        command="CREATE USER '{}'@'{}' IDENTIFIED BY '{}'".format(UserName,host,Passwd)
        connection_dict['cursor'].execute(command)
    else:
        try:
            testConnection=login(host,UserName,Passwd)
            testConnection.close()
        except:
            print('Given User already has a MySQL Account. MySQL Credentials do not match. Try again with correct details!.')
            return None
    try:    
        connection_dict['cursor'].execute("INSERT INTO pwdhash VALUES('{}','{}')".format(UserName,masterKey))
    except:
        print('Error registering User! Check if user already registered with Database')
    else:
        connection_dict['cursor'].execute("CREATE TABLE {} (PID int primary key,Website varchar(40),Pwd_Encrypted varchar(100),Last_Updated timestamp)".format(UserName))
        print('User created successfully!\n' + '='*30)

def setup():
    host=input('Enter host id:')
    passwd=input('Enter password of MySQL root account:')
    username='root' # Only root user can install software for security reasons.
    connection_dict={}
    connection_dict['connection']=login(host,username,passwd)
    connection_dict['cursor']=connection_dict['connection'].cursor()
    connection_dict['cursor'].execute('create database PwdMng')
    connection_dict['cursor'].execute('Use PwdMng')
    connection_dict['cursor'].execute('CREATE TABLE pwdhash(Username varchar(20), pwdhashed varchar(64), Type varchar(6))')
    masterKey=input('Enter MasterKey (Remember to write it down):')
    masterKeyHashed=hashlib.sha256(masterKey.encode()).hexdigest()
    connection_dict['cursor'].execute("INSERT INTO pwdhash VALUES('root','{}','ADMIN')".format(masterKeyHashed))
    connection_dict['cursor'].execute('CREATE TABLE root(PID int primary key,Website varchar(40),Pwd_Encrypted varchar(100),Last_Updated timestamp)')
    connection_dict['connection'].commit()
    connection_dict['connection'].close()


def login(host_id,username,password,DB_Name=None):
    if DB_Name == None:
        return sqltor.connect(host=host_id,user=username,passwd=password)
    else:
        return sqltor.connect(host=host_id,user=username,passwd=password,database=DB_Name)

def normalLogin(connection_dict):
    raise NotImplementedError

def adminLogin(connection_dict):  #Displays available functions for adminLogin (Not used for logging in!)
    while True:
        print('(Logged in as Admin)')
        print('\n\n')
        print('='*30)
        print()
        print('Options:')
        print()
        print('1. Create User')
        print('2. Delete New User')
        print('3. Grant/Revoke Privileges to Users')
        print('4. Enter New Password')
        print('5. Search your Password')
        print('6. Delete your Password')
        print('7. Logout')
        print()
        ch=input('Enter your choice:')

        if ch=='1':
            newName=input("Enter New User Name(Must match with MySQL Username):")
            connection_dict['cursor'].execute('SELECT user from mysql.user')
            user_tuple=connection_dict['cursor'].fetchall()
            newUserExists=False
            for i in user_tuple:    # To check if user already exists in MySQL
                if newName in i:
                    newUserExists=True
                    break
            newpwd=input('Enter New User MySQL password:')
            newhost=input("Enter New User's host:")
            newMasterKey=input('Enter New User MasterKey:')
            createUser(connection_dict,newName,newpwd,newhost,newUserExists,newMasterKey)
            del newName, newUserExists, newpwd, newhost, newMasterKey, user_tuple
        if ch=='2':
            delusername = input('Username to be deleted:')
            del_table='DROP TABLE {}'.format(delusername)
            connection_dict['cursor'].execute(del_table)
            connection_dict['cursor'].execute("DELETE FROM pwdhash WHERE User_Name = '{}'".format(delusername))
            del delusername, del_table
            print('User deleted successfully!')
        if ch=='3':
            print('List of Users registered with Database:')
            connection_dict['cursor'].execute('SELECT user_name FROM pwdhash')
            for i in connection_dict['cursor'].fetchall():
                print(i[0])
            while True:
                command = input("Enter SQL Command to grant/revoke privilege:")
                connection_dict['cursor'].execute(command)
                quit = input('Do you want to execute another command?(Y/N):')
                if quit in 'nN':
                    break
        if ch=='4':
            website = input('Enter website:')
            webpwd = input('Enter Password to store')
            insertpwd(connection_dict,website,webpwd)

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

def insertpwd(userLogin, Website, Pwd_Encrypted):  #Needs SELECT and INSERT privilege
    raise NotImplementedError # Tesing required
    userLogin['cursor'].execute('SELECT COUNT(*) FROM User1')
    PID=userLogin['cursor'].fetchone()[0]+1
    timeStamp=convertTime(time.localtime())
    command="INSERT INTO User1 VALUES('{}','{}','{}','{}')".format(PID,Website,Pwd_Encrypted,timeStamp)
    userLogin['cursor'].execute(command)
    userLogin['connection'].commit()

def encrypt(pwd,key):
    fernet=Fernet(key)
    return fernet.encrypt(pwd.encode())

def decrypt(encrpwd,key):
    fernet = Fernet(key)
    return fernet.decrypt(encrpwd).decode()

def convertTime(timetuple):  #Converts time that is in valid format for entry into MYSQL database
    return '{},{},{},{},{},{}'.format(timetuple.tm_year,timetuple.tm_mon,timetuple.tm_mday,timetuple.tm_hour,timetuple.tm_min,timetuple.tm_sec)

#insertpwd(b,input(),input())

def main():
    while True:
        print('Welcome to Password Manager...')
        print('\n'*3)
        print('='*30)
        print('Options:')
        print('1. Setup(Only for fresh installation)')
        print('2. Admin Login (Can Create and Delete Users)')  #Admin only can delete and create new users
        print('3. Login')
        print('4. Exit')
        print()

        ch=input('What do you want to do?\n...')

        if ch=='4':
            print('Exiting the program...')
            break

        if ch=='3':  # Logins the User as a Normal User and hands over control to normalLogin() for further options.
            hostid=input('Enter hostid:')
            userName=input('Enter Username:')
            Passwd=input('Enter MySQL Password:')
            masterKey=input('Enter Master Password:')
            masterKeyHashed = hashlib.sha256(masterKey.encode()).hexdigest()
            Userlogin={}
            Userlogin['connection'] = login(host_id=hostid,username=userName,password=Passwd,DB_Name='PwdMng')
            Userlogin['cursor'] = Userlogin['connection'].cursor()
            Userlogin['cursor'].execute("SELECT * FROM pwdhash")
            
            for i in Userlogin['cursor'].fetchall():
                if i == (userName,masterKey):
                    Userlogin['type']='NORMAL'
                    Userlogin['password']=Passwd
                    Userlogin['userName']=userName
                    Userlogin['hostid']=hostid
                    Userlogin['masterKey']=masterKeyHashed
                    normalLogin(Userlogin)
                    break
                else:
                    print('No such User exists in database! Check if account exists!')
            Userlogin['connection'].close()
            del Userlogin

        if ch=='2':  # Logins the User as an Admin (Shd Have GRANT, REVOKE, CREATE, CREATE USER and DROP privileges on all tables) and hands over control to adminLogin().
            hostid=input('Enter hostid:')
            userName=input('Enter Username:')
            Passwd=input('Enter MySQL Password:')
            masterKey=input('Enter Master Password:')
            masterKeyHashed = hashlib.sha256(masterKey.encode()).hexdigest()

            Userlogin={}
            Userlogin['connection'] = login(host_id=hostid,username=userName,password=Passwd,DB_Name='pwdmng')
            Userlogin['cursor'] = Userlogin['connection'].cursor()
            Userlogin['cursor'].execute("SELECT * FROM pwdhash")
            
            for i in Userlogin['cursor'].fetchall():
                if i[0:2] == (userName,masterKeyHashed):
                    Userlogin['type']='ADMIN'
                    Userlogin['password']=Passwd
                    Userlogin['userName']=userName
                    Userlogin['hostid']=hostid
                    Userlogin['masterKey']=masterKey
                    adminLogin(Userlogin)
                    break
                else:
                    print('No such User exists in database! Check if account exists!')
            Userlogin['connection'].close()
            del Userlogin
        
        if ch=='1':
            setup()
        
        else:
            print('Invalid choice!!!')
main()
