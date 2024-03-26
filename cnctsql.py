import mysql.connector
conn = mysql.connector.connect(host="localhost",user="Felix",password="felix",database="securely")
cursor = conn.cursor()

def login_check(email,password):
    cursor.execute("SELECT password from login_credentials WHERE email = '{}';".format(email))
    pswd = cursor.fetchone()
    if(pswd is None):
        return "Invalid email"
    elif(password != pswd[0]):
        return "Invalid Password"
    else:
        return "Login Successful"
    
def signup(username,email,password):
    cursor.execute("SELECT * from login_credentials WHERE email = '{}';".format(email))
    data = cursor.fetchone()
    if(data is None):
        cursor.execute("INSERT INTO login_credentials VALUES('{}','{}','{}');".format(username,email,password))
        return "Signed Up Successfully"
    elif(data[0] == username):
        return "Username already Taken!!"
    else:
        return "Email already exists"

username = 'Felix1'  
email = 'ma06@gmail.com'
password = 'Fel2005'
print(login_check(email,password))
conn.commit()
cursor.close()
conn.close()