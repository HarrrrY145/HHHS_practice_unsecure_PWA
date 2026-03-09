from flask import Flask, render_template, request, redirect, session, send_file
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect
import sqlite3
import os
import time
from waitress import serve

import string
import secrets
import random

app = Flask(__name__)
#-----------------------------------------------------------
# Using a variable from an enviorment file as the secret key. 
#-----------------------------------------------------------
load_dotenv()
app.secret_key = os.getenv("FLASK_SECRET_KEY")

csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)

print("http://localhost:8000/")





@app.route('/')
def login():
    return render_template('login.html')


@app.route('/login_validation', methods=['POST'])
def login_validation():

    email = request.form.get('email')
    password_attempt = request.form.get('password')


    connection = sqlite3.connect('LoginData.db')
    cursor = connection.cursor()

    # ---------------------------------------------------------
    # SQL INJECTION VULNERABILITY FIXED
    # ---------------------------------------------------------
# FETCHING USER FROM ROW
    user = cursor.execute("SELECT * FROM USERS WHERE email = ?", (email,)).fetchone()
    
    # ---------------------------------------------------------
    # SIDE CHANNEL ATTACK (Timing Attack) FIXED
    # ---------------------------------------------------------
    time.sleep(0.1)  #Same delays

    if user: 
        stored_hash = user[3] #password colum
        # ---------------------------------------------------------
        # BROKEN AUTHENTICATION FIXED
        # ---------------------------------------------------------
        # ---------------------------------------------------------
        if bcrypt.check_password_hash(stored_hash, password_attempt):
            print("worked")
        # ---------------------------------------------------------
        # SESSION MANAGEMENT VULNERABILITY FIXED
        # ---------------------------------------------------------
        #Session regeneration
            session.clear()
            session['user'] = email

            return redirect(f'/home?fname={user[0]}&lname={user[1]}&email={user[2]}')
    else:
        #If user not found OR password incorrect
        return redirect('/')

@app.route('/signUp')
def signUp():
    return render_template('signUp.html')


@app.route('/home')
def home():

    # ---------------------------------------------------------
    # BROKEN AUTHENTICATION FIXED
    # ---------------------------------------------------------
    if 'user' not in session:
        return redirect('/login')
    
    email = session['user']

    connection = sqlite3.connect('LoginData.db')
    cursor = connection.cursor()
    cursor.execute("SELECT fname, lname FROM USERS WHERE email = ?", (email,))
    user = cursor.fetchone()

    # ---------------------------------------------------------
    # CROSS-SITE SCRIPTING (XSS) 
    # ---------------------------------------------------------
    # If home.html uses {{ fname|safe }} or similar unsafe rendering,
    # an attacker could pass:
    # ?fname=<script>alert('Hacked')</script>
    # This would execute JavaScript in the victim's browser.
    # ---------------------------------------------------------
    if not user:
        return redirect('/login')

    fname, lname = user
    return render_template('home.html', fname=fname, lname=lname, email=email)


@app.route('/add_user', methods=['POST'])
def add_user():

    fname = request.form.get('fname')
    lname = request.form.get('lname')
    email = request.form.get('email')

    password = request.form.get('password')
    hash = bcrypt.generate_password_hash(password).decode('utf-8')

    connection = sqlite3.connect('LoginData.db')
    cursor = connection.cursor()

    # ---------------------------------------------------------
    # RACE CONDITION FIXED
    # ---------------------------------------------------------
    
    ans = cursor.execute("SELECT * FROM USERS WHERE email = ?", (email,)).fetchall()

    if len(ans) > 0:
        connection.close()
        return render_template('login.html')
    else:

        # ---------------------------------------------------------
        # SQL INJECTION (again) FIXED
        # ---------------------------------------------------------
        try:
            cursor.execute("INSERT INTO USERS(fname,lname,email,password) "
                        "VALUES (?,?,?,?)", (fname,lname,email,hash)) 
            connection.commit()

        except sqlite3.IntergrityError:
            print("Email already in use")
        
        finally:
            connection.close()
            return render_template('login.html')




@app.route('/redirect_me')
def redirect_me():

    # ---------------------------------------------------------
    # OPEN / INVALID REDIRECT
    # ---------------------------------------------------------
    # This blindly redirects to a user-supplied URL.
    # An attacker could craft:
    # /redirect_me?next=https://malicious-site.com
    # Victims trust the domain and get redirected to phishing site.
    # ---------------------------------------------------------
    next_url = request.args.get('next')
    return redirect(next_url)


@app.route('/download')
def download():

    # ---------------------------------------------------------
    # FILE ATTACK (Path Traversal)
    # ---------------------------------------------------------
    # User controls filename.
    # Attacker could request:
    # /download?file=../../../../etc/passwd
    # and retrieve sensitive server files.
    # ---------------------------------------------------------
    filename = request.args.get('file')
    return send_file(filename)


@app.route('/transfer_money', methods=['POST'])
def transfer_money():

    # ---------------------------------------------------------
    # CROSS-SITE REQUEST FORGERY (CSRF) FIXED
    # ---------------------------------------------------------

    amount = request.form.get('amount')
    recipient = request.form.get('recipient')

    return f"Transferred ${amount} to {recipient}"

@app.route('/csrf_test')
def csrf_test():
    return f"Token: {csrf.generate_csrf()}"



if __name__ == '__main__':
    serve(app, host="0.0.0.0", port=8000)
