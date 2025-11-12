from flask import Flask, render_template, request, redirect
import sqlite3
import os 
from waitress import serve

app = Flask(__name__)
app.secret_key  = os.urandom(24)

@app.route('/')
def login():
    return render_template('login.html')

@app.route('/login_validation', methods=['POST'])
def login_validation():
    email = request.form.get('email')
    password = request.form.get('password')

    connection =sqlite3.connect('LoginData.db')
    cursor = connection.cursor() 

    user = cursor.execute("SELECT * FROM USERS WHERE email=? AND password=?", (email,password)).fetchall()
    if len(user) > 0:
        return redirect(f'/home?fname={user[0][0]}&lname={user[0][1]}&email={user[0][2]}')
    else:
        return redirect('/')

@app.route('/signUp')
def signUp():
    return render_template('signUp.html')

@app.route('/home')
def home():
    fname = request.args.get('fname')
    lname = request.args.get('lname')
    email = request.args.get('email')

    return render_template('home.html', fname=fname, lname=lname, email=email)

@app.route('/add_user', methods=['POST'])
def add_user():
    fname = request.form.get('fname')
    lname = request.form.get('lname')
    email = request.form.get('email')
    password = request.form.get('password')
    
    connection = sqlite3.connect('LoginData.db')
    cursor = connection.cursor()

    ans = cursor.execute("select * from USERS where email=? AND password =?",(email,password)).fetchall()

    if len(ans) > 0:
        connection.close()
        return render_template('login.html')
    else: 
        cursor.execute("INSERT INTO USERS(first_name,last_name,email,password)values(?,?,?,?)",(fname,lname,email,password))
        connection.commit()
        connection.close()
        return render_template('login.html')

if __name__ == '__main__':
    serve(app, host="0.0.0.0", port=8000)
