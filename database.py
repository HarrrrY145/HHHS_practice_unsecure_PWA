import sqlite3
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt()

hashed = bcrypt.generate_password_hash("testerP").decode("utf-8")
print(hashed)




connection = sqlite3.Connection('LoginData.db')
cursor = connection.cursor() 

cmd1 = """ CREATE TABLE IF NOT EXISTS USERS(fname TEXT,
                                        lname TEXT,
                                        email TEXT UNIQUE PRIMARY KEY,
                                        password TEXT NOT NULL) """
cursor.execute(cmd1)

cmd2 = """INSERT INTO USERS (fname, lname, email, password) values('tester', 'test','tester@gmail.com','{hashed}')"""


cursor.execute(cmd2)
connection.commit()

ans = cursor.execute("select * from USERS").fetchall()

for i in ans:
    print(i) 