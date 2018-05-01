# =============================================================================
#   Kennesaw State University Computer Science Department
#   CS4720-01 Internet Programming Group Project
#   Authors: James Patterson, Clay Cain , James Gowdy
#   Project: Meraki
#   Details: Python 3.5, Flask 0.10, Bootstrap 3.3, Jinja 2, HTML 5 compatible
# =============================================================================
# =============================================================================
#
# =============================================================================
from flask import Flask, redirect, render_template, request, url_for, flash, session, send_from_directory
from flask.ext.triangle import Triangle
from flask_mail import Mail
from flask_login import LoginManager
from werkzeug import secure_filename
from flask_sslify import SSLify
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import sha256_crypt
from functools import wraps
from wtforms import Form, BooleanField, TextField, PasswordField, validators
from MySQLdb import escape_string as thwart
from py_files.content_management import Content
from py_files.dbconnect import connection
from py_files.hashing import _hashed256
from py_files.encrypt_string import secret, enc, dec
from up.testing_encryption import encrypt, get_key, decrypt
import gc
import os


# =============================================================================
#   APP DEFINITION
#
#   Instance Path refers to
#
#   Static Path refers to the static folder; js, angular, bootstrap
# =============================================================================
app = Flask(__name__, instance_path = '/home/username/folder/folder1/')
Triangle(app)
# This will hopefully fix the issues that Jinja2 has with AngularJS expressions
# Without this Triangle import, Jinja2 would not recognize the expression
# due to nothing being imported from the server


# =============================================================================
#   Flask-Mail
# =============================================================================
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=465,
    MAIL_USE_SSL=True,
    MAIL_USERNAME = 'username',
    MAIL_PASSWORD = 'password'
    )
mail = Mail(app)


# =============================================================================
#   SSL TLS HTTPS   This will enable SSL connections though pythonanywhere
#                   The HTTPS connection will be an automatic one
# =============================================================================
sslify = SSLify(app)
# app.secret_key = os.urandom(12)
app.secret_key = _hashed256


# =============================================================================
#   UPLOADS
#       -Accepts all major photo, audio, video, compressed, and text files
#       -Will NOT accept exe or any programming files (py, js, html, css, etc)
# =============================================================================
app.config['SESSION_TYPE'] = 'filesystem'
app.config['UPLOAD_FOLDER'] = 'meraki/up/'
app.config['ALLOWED_EXTENSIONS'] = set(['txt', 'doc', 'docx', 'htm', 'rtf', 'wpd', 'wps', 'pps', 'ppt', 'cab', 'rar', 'zip', 'avi', 'mov',
                                        'mpg', 'rm', 'swf', 'wmv', 'pdf', 'db', 'mdb', 'xls', 'bmp', 'dwg', 'dwf', 'fdr', 'gif', 'jpg', 'pic',
                                        'png', 'psd', 'pub', 'tga', 'tif', 'wmf', 'aif', 'aiff', 'au', 'mid', 'mp3', 'mp4', 'ra', 'rmi', 'wav', 'wma'])

app.config['ALLOWED_EXTENSIONS_TWO'] = set(['gif', 'jpg', 'pic', 'png', 'jpeg'])

# =============================================================================
#   The DB connection; SQLAlchemy extension for Flask
#   MySQL is the DB being used
#   299 is the time before a connection is dropped
#   This was used for the comments class
# =============================================================================
SQLALCHEMY_DATABASE_URI = "mysql+mysqlconnector://{username}:{password}@{hostname}/{databasename}".format(
    username="username",
    password="password",
    hostname="hostname",
    databasename="database"
)
app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_POOL_RECYCLE"] = 299
db = SQLAlchemy(app)


# =============================================================================
#   Flask-Login
#       allows the user to be kept logged in until server restart or log out
#
# =============================================================================
login_manager = LoginManager()
login_manager.init_app(app)


# =============================================================================
#   Dictionary of values needed to create dynamic list that will be fed into
#   header.html to display the links to the programming languages categories
#   The file can be modified if it needs to be updated.
#       - meraki/content_management.py
# =============================================================================
page_dict = Content()


# =============================================================================
#   Used for adding comments to the comments database
#   Database has two fields: id and content
#   id is a unique primary number specific to individual comments
#   content is the content of each message typed into the comments section
#       - home/comments tab
#       - header.html
# =============================================================================
class Comment(db.Model):

    __tablename__ = "comments"

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(4096))


# =============================================================================
#                                                                                       Login Required Decorator (wrapper)
#   The login required wrap will check to see if the session returns True
#   for logged_in or not. If true, it will return the proper information, but
#   if logged_in returns false, the user will be redirected to the login_page.html
#   and a message will be flashed, "You need to Log In first, mate"
# =============================================================================
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash("You need to Log In first, mate")
            return redirect(url_for('login_page'))
    return wrap


# =============================================================================
#                                                                                       Function to return username or Guest
#   This function relies on the sole fact that logged_in must return True
#   The identifier un is given the value of the current users session username
#   The string variable is then returned. If logged_in is False, the username
#   that is returned will be Guest.
# =============================================================================
def get_un():
    if 'logged_in' in session:
        un = session['username']
        return un
    else:
        un = "Guest"
        return un


def get_user_information():

    _username = get_un()

    c, conn = connection()
    data = c.execute("SELECT * FROM users WHERE username = (%s)", (thwart(_username),))
    data = c.fetchone()[0]
    _id = data
    conn.commit()
    c.close()
    conn.close()
    gc.collect()

    c, conn = connection()
    data = c.execute("SELECT * FROM users WHERE username = (%s)", (thwart(_username),))
    data = c.fetchone()[3]
    _email = data
    conn.commit()
    c.close()
    conn.close()
    gc.collect()

    return  _id, _username, _email


def get_profile_information():

    _username = get_un()

    c, conn = connection()
    data = c.execute("SELECT * FROM upp WHERE username = (%s)", (thwart(_username),))

    if int(data) > 0:
        data = c.fetchone()[2]
        _f_name = data
        conn.commit()
        c.close()
        conn.close()
        gc.collect()
    else:
        _f_name = "First Name"
        gc.collect()

    c, conn = connection()
    data1 = c.execute("SELECT * FROM upp WHERE username = (%s)", (thwart(_username),))

    if int(data1) > 0:
        data1 = c.fetchone()[3]
        _l_name = data1
        conn.commit()
        c.close()
        conn.close()
        gc.collect()
    else:
        _l_name = "Last Name"
        gc.collect()

    c, conn = connection()
    data2 = c.execute("SELECT * FROM upp WHERE username = (%s)", (thwart(_username),))

    if int(data2) > 0:
        data2 = c.fetchone()[4]
        _filename = data2
        conn.commit()
        c.close()
        conn.close()
        gc.collect()
    else:
        _filename = "coming.jpg"
        gc.collect()

    c, conn = connection()
    data3 = c.execute("SELECT * FROM users WHERE username = (%s)", (thwart(_username),))

    if int(data3) > 0:
        data3 = c.fetchone()[3]
        _email = data3
        conn.commit()
        c.close()
        conn.close()
        gc.collect()
    else:
        _email = "generic@email.com"
        gc.collect()

    return _f_name, _l_name, _filename, _email


def get_about_me():
    un = get_un()
    c, conn = connection()
    checker = c.execute("select * from about where username=(%s)",  (thwart(un),))
    conn.commit(); c.close(); conn.close(); gc.collect()

    if int(checker) > 0:
        c, conn = connection()
        about_me = c.execute("select * from about where username=(%s)",  (thwart(un),))
        about_me = c.fetchone()[2]
        conn.commit(); c.close(); conn.close(); gc.collect()
        return str(about_me)

    elif int(checker) == 0:
        about_me = "This is a default profile. Click on Edit About Me, mate."
        return str(about_me)


def get_online_users():
    c, conn = connection()
    ou = c.execute("select * from users where online='yes'")
    ou = c.fetchall()
    conn.commit(); c.close(); conn.close(); gc.collect()
    online_users = list(ou)
    return online_users


# =============================================================================
#                                                                                       Function to return number of messages available to user
#   get username
#   create a mysql connection and cursor
#   create an identifier to store the results of the sql query
#   convert the query into a int to display the reults dynamically
#   the int is then returned to be used with header.html
#       - Displays how many messages the logged in user has available
#       - Must be passed to every major html page to be displayed at the top
# =============================================================================
def get_number_of_messages():
    un = get_un()
    c, conn = connection()
    n_query = c.execute("SELECT * FROM messages WHERE username_to = (%s)", (thwart(un),))
    number_of_messages = int(n_query)
    return number_of_messages


# =============================================================================
#                                                                                       Function to return number of downloads available to user
#   A function that queries the database, takes those results, converts the
#   results into an int variable, and returns the int representation
#   The number is used to display dynamically how many downloads the user
#   has access to, if they know the passphrase that is.
# =============================================================================
def get_number_of_downloads():
    un = get_un()
    c, conn = connection()
    num_query = c.execute("SELECT filename FROM upload_file WHERE username_to = (%s)", (thwart(un),))
    number_of_downloads = int(num_query)
    return number_of_downloads


# =============================================================================
#   User class to define a username for the currently logged in user
#   The class will return guest if the session does not have an active username
#   Although, effectively pointless due to the login_required wrapper I've written
#   users won't be able to view many sites without being logged in
# =============================================================================
class User:
    def username(self):
        try:
            return str(session['username'])
        except:
            return("guest")

user = User()

def userinformation():
    try:
        client_name = (session['username'])
        guest = False
    except:
        guest = True
        client_name = "Guest"

    if not guest:
        try:
            c,conn = connection()
            c.execute("SELECT * FROM users WHERE username = (%s)",
                    (thwart(client_name)))
            data = c.fetchone()
            settings = data[4]
            tracking = data[5]
            rank = data[6]
        except:
            pass

    else:
        settings = [0,0]
        tracking = [0,0]
        rank = [0,0]

    return client_name, settings, tracking, rank


# =============================================================================
#   The index page that will be displayed for                                           jpatte95.pythonanywhere.com/
# =============================================================================
@app.route('/')
def index():
    # flash("second message") to send another message through
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    return render_template("index.html", page_dict=page_dict, un=un, number_of_message=number_of_messages, number_of_downloads=number_of_downloads)


# =============================================================================
#                                                                                       Dashboard
# =============================================================================
@app.route('/dashboard/', methods=["GET", "POST"])
@login_required
def dashboard():
    #flash(" ")
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    _id, _username, _email = get_user_information()
    _first_name, _last_name, _filename, _email = get_profile_information()
    about_me = get_about_me()
    online_users = get_online_users()

    if request.method == "GET":
        return render_template("dashboard.html", page_dict=page_dict,
                                                    comments=Comment.query.all(),
                                                    un=un,
                                                    number_of_messages=number_of_messages,
                                                    number_of_downloads=number_of_downloads,
                                                    u_id = _id,
                                                    u_name = _username,
                                                    uf_name = _first_name,
                                                    ul_name = _last_name,
                                                    u_filename = _filename,
                                                    u_email = _email,
                                                    u_about_me = about_me,
                                                    online_users=online_users
                                                    )  # htmlfilename=file name here

   # was testing out using mysqlalchemy before I choose to solely use sqlite3
    # creates the Python object that represents the comment
    comment = Comment(content=request.form["contents"])
    # sends the command to the database to store it
    db.session.add(comment)
    # close the transaction and store everything
    db.session.commit()
    # A comment section on the dashboard under the comments tab works perfectly though
    # displays the list of comments from first to last dynamically through python and flask
    return redirect(url_for('dashboard'))


# =============================================================================
#                                                                                       Login
# =============================================================================
@app.route('/login/', methods=["GET","POST"])
def login_page():
    error= "=============Meraki================================="
    try:
        c, conn = connection()
        if request.method == "GET":
            return render_template("login.html", error=error, page_dict=page_dict)

        if request.method == "POST":

            c.execute("UPDATE users SET online='yes' WHERE username=(%s)", (thwart(request.form['username']),))
            conn.commit(); c.close(); conn.close();
            c, conn = connection()
            data = c.execute("SELECT * FROM users WHERE username = (%s)", (thwart(request.form['username']),))
            data = c.fetchone()[2]

            if sha256_crypt.verify(request.form['password'], data):
                session['logged_in'] = True
                session['is_online'] = True
                session['username'] = request.form['username']
                flash("You are now logged in")
                return redirect(url_for("dashboard"))
            else:
                error = ("Invalid Username/Password Combination")
        conn.commit(); c.close(); conn.close(); gc.collect()
        return render_template("login.html", error=error, page_dict=page_dict)
    except Exception as e:
        error = ("=============Meraki=================================")
        return render_template("login/login.html", e=e, error = error, page_dict=page_dict)



# =============================================================================
#                                                                                       Log Out
# =============================================================================
@app.route("/logout/")
@login_required
def logout():
    un = get_un()
    session.pop('logged_in', None)
    session.pop('is_online', None)
    c, conn = connection()
    c.execute("UPDATE users SET online='no' WHERE username=(%s)", (thwart(un),))
    conn.commit(); c.close(); conn.close();
    flash("    You have been logged out, mate")
    gc.collect()
    return redirect(url_for('index'))


# =============================================================================
#                                                                                       Registration
# =============================================================================
class Registration(Form):
    username = TextField('Username', [validators.Length(min=4, max=20)])
    # first = TextField('First', [validators.Length(min=2, max=25)])
    # last = TextField('Last', [validators.Length(min=2, max=25)])
    email = TextField('Email Address', [validators.Length(min=6, max=50)])
    password = PasswordField('New Password', [validators.DataRequired(), validators.EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Repeat Password')
    accept_tos = BooleanField('I accept the specific <a href="/tos/">Terms of Service</a> and the <a href="/privacy/">Privacy Notice</a> (09 December 2016)', [validators.Required()])


@app.route('/register/', methods=["GET", "POST"])
def register_page():
    un = get_un()
    if un == "Guest":
        try:
            form = Registration(request.form)

            if request.method == "POST" and form.validate():
                username = form.username.data
                # first_name = form.first.data
                # last_name = form.last.data
                email = form.email.data
                password = sha256_crypt.encrypt((str(form.password.data)))
                # hash = sha256_crypt.encrypt((str(form.username.data))) + "_|_" + sha256_crypt.encrypt((str(form.first_name.data))) + "_|_" + sha256_crypt.encrypt((str(form.last_name.data)))
                c, conn = connection()

                x_query = c.execute("SELECT * FROM users WHERE username = (%s)", (thwart(username),))

                if int(x_query) > 0:
                    flash("Username has already been picked, mate")
                    return render_template('register.html', form=form)
                else:
                    c.execute("INSERT INTO users (username, password, email, tracking, online) VALUES (%s, %s, %s, %s, %s)",
                    (thwart(username), thwart(password), thwart(email), thwart("/index/"), thwart("yes")))

                    conn.commit()

                    flash("Thanks for registering with Meraki, mate!")
                    c.close()
                    conn.close()
                    gc.collect()

                    session['logged_in'] = True
                    session['username'] = username

                    about = "This is the default profile. Click on Edit About Me to change this, mate!"
                    c, conn = connection()
                    c.execute("INSERT INTO about (username, about_me) VALUES (%s, %s)",
                            (thwart(username), thwart(about)))
                    conn.commit(); c.close(); conn.close(); gc.collect()
                    flash("    Your profile about me section has been updated successfully, mate.")
                    return redirect(url_for('dashboard'))

            return render_template("registration/register.html", form=form, page_dict=page_dict)

        except Exception as e:
            return(str(e))
    else:
        return redirect(url_for('dashboard'))


# =============================================================================
#                                                                                       Change Password
# =============================================================================
@app.route('/user/change-password/', methods=['GET', 'POST'])
@login_required
def change_password():
    try:
        c,conn = connection()

        error = None
        if request.method == 'POST':

            data = c.execute("SELECT * FROM users WHERE username = (%s)",
                    thwart(user.username()))
            data = c.fetchone()[2]


            if sha256_crypt.verify(request.form['password'], data):
                flash('Authentication Successful.')
                if len(request.form['npassword']) > 0:
                    #flash("You wanted to change password")

                    if request.form['npassword'] == request.form['rnpassword'] and len(request.form['npassword']) > 0:
                        try:
                            #flash("new passwords matched")
                            password = sha256_crypt.encrypt((str(request.form['npassword'])))

                            c,conn = connection()

                            data = c.execute("UPDATE users SET password = %s where username = %s", (password,thwart(user.username())))

                            conn.commit()
                            c.close()
                            conn.close()
                            flash("Password changed")
                        except Exception as e:
                            return(str(e))
                    else:
                        flash("Passwords do not match!")

                return render_template('change_password.html', name=user.username(), error=error)

            else:
                flash('Invalid credentials. Try again')
                error = 'Invalid credentials. Try again'
        gc.collect()
        return render_template('change_password.html', name=user.username())#, error=error)
    except Exception as e:
        return(str(e))


# =============================================================================
#                                                                                      Messaging System
# =============================================================================
@app.route('/send_to/', methods=["GET", "POST"])
@login_required
def send_to():
    # This will get the current logged in username
    un = get_un()
    # This will get the number of downloads available to current user
    number_of_downloads = get_number_of_downloads()
    # This will get the number of messages available to the current user
    number_of_messages = int(get_number_of_messages())
    # creates the cursor and the sql connection
    c, conn = connection()
    # query to get the messages from the currently logged in user
    new_query = c.execute("SELECT * FROM messages WHERE username_to = (%s)", (thwart(un),))
    # fetches all of the query results and stores inside the identifier new_query
    new_query = c.fetchall()
    # new query is casted as a list
    new_query = list(new_query)
    # This will only grab the columns from the list that we need
    newer_query = [item[0:4] for item in new_query]
    # commit the changes to db
    conn.commit()
    # close the cursor object
    c.close()
    # close the connection
    conn.close()
    # take care of garbage collection
    gc.collect()

    # The following if statements depend on if the number of messages is equal to 0, 1, or more.
    # It is worth saying that each if statement does the same exact thing, the only differences
    # are the messages displayed at the beginning of the site.
    if number_of_messages == 0:
        # create a cursor and connection
        c, conn = connection()
        # store the received data from the db in identifier
        file_query = c.execute("SELECT username FROM users WHERE username != '" + un + "';")
        # fetch all of the information from the db, which will be a list of all users that are not the currently logged in user
        file_query = c.fetchall()
        # cast the query as a list
        query_list = list(file_query)
        # commit the changes
        conn.commit()
        # close the cursor
        c.close()
        # close the connection
        conn.close()
        # take care of the garbage that might be floating around
        gc.collect()
        # create cursor and connection
        c, conn = connection()
        # store query, all the messages from username_to column that does not equal the currently logged in user
        new_query = c.execute("SELECT * FROM messages WHERE username_to = (%s)", (thwart(un),))
        # fetch all of the results from db
        new_query = c.fetchall()
        # cast results as a list
        new_query = list(new_query)
        # capture only the results from the list that we actually will need or use
        newer_query = [item[0:4] for item in new_query]
        # commit the changes to db
        conn.commit()
        # close the cursor
        c.close()
        # close connection object
        conn.close()
        # collect garbage
        gc.collect()
        # messages that will display if user has no messages
        # the other two if statements only vary by what these two
        # messages say.
        mess = "Send someone a message, mate."
        mess1 = "You'll have a response in no time!"

        # what to do if the server receives a GET request
        if request.method == 'GET':
            # the get handles the dynamic gathering of the "read" portion of the messaging system
            # returns the send_to.html page, with the information required to receive, reply, and delete messages
            return render_template("messaging/send_to.html", page_dict=page_dict,                             # dictionary of dynamic links
                                                    un=un,                                          # username of currently logged in user
                                                    mess=mess,                                      # mess, mess1 are messages displayed for users
                                                    mess1=mess1,                                    # when they have a certain amount of messages
                                                    number_of_messages=number_of_messages,
                                                    query_list=query_list,                          # list fed into send_to.html to use in jinja for loop
                                                    file_query=file_query,                          # list used in jinja looping as well
                                                    new_query=new_query, newer_query=newer_query,   # another list used in jinja looping
                                                    dec=dec,                                        # the decreption algorithm written to decrypt messages
                                                    secret=secret,                                  # universal secret 16 byte secret key
                                                    number_of_downloads=number_of_downloads
                                                    )

    # Post handles the sending of a message. The modal located in send_to.html can post data, and will post to functions written below.
    # The data is grabbed from the input tags on the send_to.html , send message tab and sent back to the function send_to() to handle the request
    # Flask is awesome like that
        if request.method == 'POST':
            u = un
            # grab information from the subject input field
            sub = request.form['subject']
            # grab message input field information
            msg = request.form['message']
            # encrypt the input message using the encryption function written to encrypt
            # a string, and pad the string if it is not a variable of 16 bytes.
            # the algorithm takes a secret 16 byte key and a string(message)
            hash_msg = enc(secret, msg)
            # grab the send to information from the input field
            to = request.form['optionsRadios']
            # create connection and cursor object
            c, conn = connection()
            # use cursor to query the db
            c.execute("INSERT INTO messages (username_from, subject, message, username_to) VALUES (%s, %s, %s, %s)", (thwart(str(u)), thwart(str(sub)), thwart(str(hash_msg)), thwart(str(to))))
            # commit changes
            conn.commit()
            # close the cursor
            c.close()
            # close connection
            conn.close()
            # collect the garbage
            gc.collect()
            # redirect to dashboard once message has been sent
            flash('        Your message has been sent, mate.')
            return redirect(url_for('dashboard'))

    elif number_of_messages == 1:
        c, conn = connection()
        file_query = c.execute("SELECT username FROM users WHERE username != '" + un + "';")
        file_query = c.fetchall()
        query_list = list(file_query)
        conn.commit()
        c.close()
        conn.close()
        gc.collect()

        c, conn = connection()
        new_query = c.execute("SELECT * FROM messages WHERE username_to = (%s)", (thwart(un),))
        new_query = c.fetchall()
        new_query = list(new_query)
        newer_query = [item[0:4] for item in new_query]
        # hashed_msg = c.fetchone()[2]
        conn.commit()
        c.close()
        conn.close()
        gc.collect()
        mess = "Respond to that message, mate."
        mess1 = "You'll have a response in no time!"

        if request.method == 'GET':
            return render_template("messaging/send_to.html", page_dict=page_dict,
                                                    un=un,
                                                    mess=mess,
                                                    mess1=mess1,
                                                    number_of_messages=number_of_messages,
                                                    query_list=query_list,
                                                    file_query=file_query,
                                                    new_query=new_query, newer_query=newer_query,
                                                    dec=dec,
                                                    secret=secret,
                                                    number_of_downloads=number_of_downloads
                                                    )

        if request.method == 'POST':
            u = un
            sub = request.form['subject']
            msg = request.form['message']
            hash_msg = enc(secret, msg)
            to = request.form['optionsRadios']
            te = request.form["action"]

            if request.form["action"] == "Send":

                c, conn = connection()
                c.execute("INSERT INTO messages (username_from, subject, message, username_to) VALUES (%s, %s, %s, %s)", (thwart(str(u)), thwart(str(sub)), thwart(str(hash_msg)), thwart(str(to))))
                conn.commit()
                c.close()
                conn.close()
                gc.collect()
                flash('        Your message has been sent, mate.')
                return redirect(url_for('dashboard'))

            if request.form["action"] == "Read":

                c, conn = connection()
                c.execute("INSERT INTO msg (testing) VALUES (%s)", [thwart(te)])
                conn.commit()
                c.close()
                conn.close()
                gc.collect()
                flash('        Your message has been sent, mate.')
                return redirect(url_for('dashboard'))


    else:
        c, conn = connection()
        file_query = c.execute("SELECT username FROM users WHERE username != '" + un + "';")
        file_query = c.fetchall()
        query_list = list(file_query)
        conn.commit()
        c.close()
        conn.close()
        gc.collect()

        c, conn = connection()
        new_query = c.execute("SELECT * FROM messages WHERE username_to = (%s)", (thwart(un),))
        new_query = c.fetchall()
        new_query = list(new_query)
        newer_query = [item[0:4] for item in new_query]
        # hashed_msg = c.fetchone()[2]
        conn.commit()
        c.close()
        conn.close()
        gc.collect()
        mess = "Respond to those messages, mate."
        mess1 = "You'll have a response in no time!"

        if request.method == 'GET':
            return render_template("messaging/send_to.html", page_dict=page_dict,
                                                    un=un,
                                                    mess=mess,
                                                    mess1=mess1,
                                                    number_of_messages=number_of_messages,
                                                    query_list=query_list,
                                                    file_query=file_query,
                                                    new_query=new_query, newer_query=newer_query,
                                                    dec=dec,
                                                    secret=secret,
                                                    number_of_downloads=number_of_downloads
                                                    )

        if request.method == 'POST':
            u = un
            sub = request.form['subject']
            msg = request.form['message']
            hash_msg = enc(secret, msg)
            to = request.form['optionsRadios']

            c, conn = connection()
            c.execute("INSERT INTO messages (username_from, subject, message, username_to) VALUES (%s, %s, %s, %s)", (thwart(str(u)), thwart(str(sub)), thwart(hash_msg), thwart(str(to))))
            conn.commit()
            c.close()
            conn.close()
            gc.collect()
            flash('        Your message has been sent, mate.')
            return redirect(url_for('dashboard'))


# =============================================================================
#                                                                                       Delete Message/Reply to Message
# =============================================================================
@app.route('/delete_message/', methods=["GET", "POST"])
@login_required
def delete_message():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    # delete message's GET requests are fed information from the send_to.html page
    # information on username_from, subject, hashed messages, and username_to are all directly linked
    # Post; the id, username_from, subject, message, and username_to are all stored as variables(identifiers)
    # to be used with the confirmation.html page.
    # The user will click on reply/delete on the delete_message.html page, and be redirected to confirmation.html
    # which will hide all the information below in hidden input tags, but will handle the db functions bahind the scenes
    if request.method == 'POST':
            _id = request.form['_id']
            _username_from = request.form['_username_from']
            _subject = request.form['_subject']
            _message = request.form['_message']
            _username_to = request.form['_username_to']

            return render_template("messaging/confirmation.html",
                                            page_dict=page_dict,
                                            un=un,
                                            number_of_messages=number_of_messages,
                                            _id=_id,
                                            _username_from=_username_from,
                                            _subject=_subject,
                                            _message=_message,
                                            _username_to=_username_to,
                                            number_of_downloads=number_of_downloads
                                            )


# =============================================================================
#
# =============================================================================
# Runs if the user wants to delete a message
# the app is fed a uid, which is an integer
@app.route('/delete_message/yes_<int:uid>', methods=["GET", "POST"])
@login_required
def delete_message1(uid):

    if request.method == 'POST':
            # private identifier that is set equal to the integer value we passed in
            # which is the id for the message being replied to/deleted
            _id = uid
            # create connection and cursor
            c, conn = connection()
            # delete from messages where id=uid;
            c.execute("DELETE FROM messages WHERE id = (%s)", (thwart(str(_id)),))
            conn.commit()
            c.close()
            conn.close()
            gc.collect()
            # redirect back to send_to.html to continue messages transactions
            flash('        Your message has been deleted, mate.')
            return redirect(url_for('send_to'))

# =============================================================================
#
# =============================================================================
@app.route('/delete_message/no_<int:uid>', methods=["GET", "POST"])
@login_required
def del_message(uid):
    if request.method == 'POST' and uid != None:
            gc.collect()
            flash('        Your message has been kept, mate.')
            return redirect(url_for('send_to'))


# =============================================================================
#
# =============================================================================
# If the user wishes to reply to the message
# the id is fed into the function once again
@app.route('/delete_message/reply_<int:uid>', methods=["GET", "POST"])
def delete_message3(uid):

    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()

    # Post: The id, username_to, message, creation of encrypted message, and username_from variables are stored from the
    # input tags of the reply_to_message.html page
    if request.method == 'POST':

            _id = request.form['_id']
            _username_to = request.form['_username_from']
            _subject = request.form['_subject']
            _message = request.form['_message']
            # Encrypts the message entered into a 16byte encrypted string
            # _hash_msg = enc(secret, _message)
            _username_from = request.form['_username_to']

            return render_template("messaging/reply_to_message.html",
                                            page_dict=page_dict,
                                            un=un,
                                            number_of_messages=number_of_messages,
                                            _id=_id,
                                            _username_from=_username_from,
                                            _subject=_subject,
                                            _message=_message,
                                            _username_to=_username_to,
                                            number_of_downloads=number_of_downloads
                                            )


# =============================================================================
#
# =============================================================================
# View used to ensure the user has sent the message correctly
@app.route('/reply_confirmation/', methods=["GET", "POST"])
def reply_confirmation():
    if request.method == 'POST':
            un = get_un()
            # gather all the data required to be stored into the db from the reply
            _username_to = request.form['_username_to']
            _subject = request.form['_subject']
            _message = request.form['_message']
            # encrypt the message before storing into db
            # plaintext sensitive data will never be saved
            _hash_msg = enc(secret, _message)
            # create connection and cursor
            c, conn = connection()
            # query to store the information gathered from the reply into the messages db table
            c.execute("INSERT INTO messages (username_from, subject, message, username_to) VALUES (%s, %s, %s, %s)", (thwart(str(un)), thwart(str(_subject)), thwart(str(_hash_msg)), thwart(str(_username_to))))
            conn.commit()
            c.close()
            conn.close()
            # redirect the user back to the messages homepage, send_to.html
            flash('        Your reply has been sent, mate.')
            return redirect(url_for('send_to'))


# =============================================================================
#
# =============================================================================
@app.route('/read_message/', methods=["GET", "POST"])
@login_required
def read_message():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()

    if request.method == 'POST':
        _id = request.form['_id']
        _username_from = request.form['_username_from']
        _subject = request.form['_subject']
        _message = request.form['_message']
        _username_to = request.form['_username_to']

        return render_template("messaging/read.html",
                                        page_dict=page_dict,
                                        un=un,
                                        number_of_messages=number_of_messages,
                                        dec=dec,
                                        secret=secret,
                                        _id=_id,
                                        _username_from=_username_from,
                                        _subject=_subject,
                                        _message=_message,
                                        _username_to=_username_to,
                                        number_of_downloads=number_of_downloads
                                        )


# =============================================================================
#                                                                                       500 Error
# =============================================================================
@app.errorhandler(500)
def internal_error(e):
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    return render_template("error/500.html", error=e, page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)


# =============================================================================
#                                                                                       405 Error
# =============================================================================
@app.errorhandler(405)
def method_not_found(e):
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    return render_template("error/405.html", error=e, page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)


# =============================================================================
#                                                                                       404 Error
# =============================================================================
@app.errorhandler(404)
def page_not_found(e):
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    return render_template("error/404.html", error=e, page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)


# =============================================================================
#                                                                                       upload a File
# =============================================================================
def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1] in app.config['ALLOWED_EXTENSIONS']


@app.route('/uploads/')
@login_required
def uploads():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    # the uploads html page is a form page that will send
    # the data required to upload a file
    # the actual saving and encrypting of the file is done below in uploader
    # create connection and a cursor
    c, conn = connection()
    # a query to get the usernames that do not equal the current logged in user
    file_query = c.execute("SELECT username FROM users WHERE username != '" + un + "';")
    # fetch all the information
    file_query = c.fetchall()
    # commit the changes
    conn.commit()
    # close the cursor
    c.close()
    # close the connection
    conn.close()
    # collect the garbage
    gc.collect()
    # will display the uploaded fules the user has access to
    return render_template("upload_download/uploads.html", page_dict=page_dict, file_query=file_query, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)


@app.route('/uploader/', methods=["GET", "POST"])
@login_required
def upload_file():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    # handles what happens if there is information sent in a POST request
    # This function only handles POST request though
    if request.method == "POST":
        # store the file being uploaded in a memory location
        file = request.files["file"]
        # grab the entered key to use to encrypt
        entered_key = request.form['key']
        # grab the input values for the send_to
        entered_to = request.form['send_to']
        # the key is assigned to a private variable and cast as a string
        # there is a possibility of the data being encoded in utf-8
        # which we will possibly need to decode the data
        # so, cast the information as a string to avoid
        _key = str(entered_key)
        # cast the username as a string to avoid encoding errors
        _username_to = str(entered_to)
        # allow_file just makes sure the file being uploaded is an acceptable
        # allowed file type. (eg. .jpg, .avi, .ppt, etc)
        if file and allowed_file(file.filename):
            # return a proper string for the filename
            # removes the path and the / at the end of the path
            filename = secure_filename(file.filename)
            # save the file in the up folder
            file.save(os.path.join("meraki/up/", filename))
            # meraki/up/filename
            # find the length of the filename to be used later
            filename_len = len(filename)
            # encrypt the uploaded file to a 16byte encoded version of itself with
            # a passphrase required
            encrypt(get_key(_key), os.path.join(app.config['UPLOAD_FOLDER'], filename), filename_len)
            # The file name for the file that was uploaded
            file_name = str(filename)
            # The username for the user who uploaded a file
            session_username = session['username']
            # create cursor and connection
            c, conn = connection()
            # query to see if the file being uploaded has been uploaded by the current user already
            checker = c.execute("select * from upload_file where username_from=(%s) and filename=(%s)",  (thwart(session_username), thwart(file_name),))
            # if not 0, the user has uploaded a file for the current user
            if int(checker) > 0:
                # will flash a message to the user
                flash("The File has already been uploaded by you, mate.")
                # collect garbage
                gc.collect()
                # return uploads
                return render_template('upload_download/uploads.html', page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)
            else:
                # query to insert the information required for the uploads
                # username_from, filename, username_to
                c.execute("INSERT INTO upload_file (username_from, filename, username_to) VALUES (%s, %s, %s)",
                    (thwart(session_username), thwart(file_name), thwart(_username_to)))
                # commit changes
                conn.commit()
                # close the cursor
                c.close()
                # close the connection
                conn.close()
                # garbage collection
                gc.collect()
                os.remove(os.path.join("meraki/up/", file_name))
                flash("    Your file has been uploaded successfully, mate.")
                return redirect(url_for('dashboard'))


# =============================================================================
#                                                                                       upload a profile Photo
# =============================================================================
def allowed_file_two(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1] in app.config['ALLOWED_EXTENSIONS_TWO']


@app.route('/upload_profile_photo/', methods=["GET", "POST"])
@login_required
def upload_profile_photo():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    _id, _username, _email = get_user_information()

    if request.method == "POST":

        f_name = request.form['f_name']
        l_name = request.form['l_name']
        file = request.files["file"]

        if file and allowed_file_two(file.filename):

            c, conn = connection()
            checker = c.execute("select * from upp where username=(%s)",  (thwart(un),))
            conn.commit(); c.close(); conn.close(); gc.collect()

            if int(checker) > 0:
                filename = secure_filename(file.filename)
                file.save(os.path.join("meraki/static/profile/", _username + ".jpg"))
                file_name = str(_username + ".jpg")
                c, conn = connection()
                c.execute("UPDATE upp SET username=(%s), f_name=(%s), l_name=(%s), filename=(%s), email=(%s) WHERE username=(%s)",
                        (thwart(un), thwart(f_name), thwart(l_name), thwart(file_name), thwart(_email), thwart(un)) )
                conn.commit(); c.close(); conn.close(); gc.collect()
                flash("    Your profile photo has been updated successfully, mate.")
                return redirect(url_for('dashboard'))

            else:

                filename = secure_filename(file.filename)
                file.save(os.path.join("meraki/static/profile/", _username + ".jpg"))
                file_name = str(_username + ".jpg")
                c, conn = connection()
                c.execute("INSERT INTO upp (username, f_name, l_name, filename, email) VALUES (%s, %s, %s, %s, %s)",
                        (thwart(un), thwart(f_name), thwart(l_name), thwart(file_name), thwart(_email)))
                conn.commit(); c.close(); conn.close(); gc.collect()
                flash("    Your profile photo has been uploaded successfully, mate.")
                return redirect(url_for('dashboard'))
        else:
            flash("    Your must upload the proper format, mate.")
            return redirect(url_for('dashboard'))


# =============================================================================
#                                                                                       About Me
# =============================================================================
@app.route('/about_me/')
@login_required
def about_me():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    about_me = get_about_me()

    if request.method == 'GET':
        try:
            return render_template("users/about_me.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads, about_me=about_me)

        except Exception as e:
            return(str(e))


# =============================================================================
#                                                                                       Edit Information
# =============================================================================
@app.route('/edit_information/')
@login_required
def edit_information():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    about_me = get_about_me()
    _id, _username, _email = get_user_information()
    _first_name, _last_name, _filename, _email = get_profile_information()

    if request.method == 'GET':
        try:
            return render_template("users/edit_information.html", username=_username, email=_email, first=_first_name, last=_last_name, page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads, about_me=about_me)

        except Exception as e:
            return(str(e))


# =============================================================================
#                                                                                       About Me Functionality
# =============================================================================
@app.route('/about_me2/', methods=['GET','POST'])
@login_required
def about_me2():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()

    if request.method == 'POST':
        try:
            c, conn = connection()
            checker = c.execute("select * from about where username=(%s)",  (thwart(un),))
            conn.commit(); c.close(); conn.close(); gc.collect()

            if int(checker) > 0:

                username = request.form['username']
                about = request.form['about']
                c, conn = connection()
                c.execute("UPDATE about SET username=(%s), about_me=(%s) WHERE username=(%s)",
                        (thwart(username), thwart(about), thwart(username)) )
                conn.commit(); c.close(); conn.close(); gc.collect()
                flash("    Your profile about me section has been updated successfully, mate.")
                return redirect(url_for('dashboard'))

            else:
                username = request.form['username']
                about = request.form['about']
                c, conn = connection()
                c.execute("INSERT INTO about (username, about_me) VALUES (%s, %s)",
                        (thwart(username), thwart(about)))
                conn.commit(); c.close(); conn.close(); gc.collect()
                flash("    Your profile about me section has been updated successfully, mate.")
                return redirect(url_for('dashboard'))

        except Exception as e:
            return(str(e))


@app.route('/about_me3/', methods=['GET','POST'])
@login_required
def about_me3():
    un = get_un()
    # number_of_messages = get_number_of_messages()
    # number_of_downloads = get_number_of_downloads()
    email = request.form['email']
    first = request.form['first']
    last = request.form['last']
    filename = (str(un) + ".jpg")
    c, conn = connection()
    c.execute("UPDATE users SET username=(%s), email=(%s) WHERE username=(%s)",
            (thwart(un), thwart(email), thwart(un)) )
    conn.commit(); c.close(); conn.close(); gc.collect()
    c, conn = connection()
    c.execute("UPDATE upp SET username=(%s), f_name=(%s), l_name=(%s), filename=(%s), email=(%s) WHERE username=(%s)",
            (thwart(un), thwart(first), thwart(last), thwart(filename), thwart(email), thwart(un)) )
    conn.commit(); c.close(); conn.close(); gc.collect()
    flash("    Your profile information section has been updated successfully, mate.")
    return redirect(url_for('dashboard'))


# =============================================================================
#                                                                                       Protected downloads
# =============================================================================
def special_requirement(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        try:
            if 'python' == session['username']:
                return f(*args, **kwargs)
            else:
                return redirect(url_for('dashboard'))
        except:
            return redirect(url_for('dashboard'))
    return wrap


# =============================================================================
#
# =============================================================================
@app.route('/downloads/')
@login_required
def downloads():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        c, conn = connection()
        # query to show the files that are available to the currently logged in user
        file_query = c.execute("SELECT filename FROM upload_file WHERE username_to = '" + un + "';")
        # fetchall the information
        file_query = c.fetchall()
        # cast as a list
        query_list = list(file_query)
        # commit the changes
        conn.commit()
        # close the cursor
        c.close()
        # close the connection
        conn.close()
        # garbage collection
        gc.collect()
        # returns downloads.html with the information displayed for the current user that is logged in
        return render_template("upload_download/downloads.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads, query_list=query_list, file_query=file_query)

    except Exception as e:
        return(str(e))


# =============================================================================
#
# =============================================================================
# function view to help with downloading the file
@app.route('/key/<path:filename>')
@login_required
def key(filename):
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    return render_template('upload_download/key.html', filename=filename, page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)


# =============================================================================
#
# =============================================================================
@app.route('/downloads/<path:filename>', methods=['GET','POST'])
@login_required
def download_file(filename):

    if request.method == 'POST':
        try:
            _filename = secure_filename(filename)
            _original_filename = str(filename)                                      # original filename
            _original_filename_len = len(filename)                                  # original filename length
            _enc_filename = "enc_" + _filename                                      # encrypted filename
            _modified_filename_len = len(_enc_filename)                             # encrypted filename length
            entered_key = request.form['key']                                       # key entered from the user
            _key = str(entered_key)                                                 # cast as string
            _path = os.path.join(app.config['UPLOAD_FOLDER'], _enc_filename)        # create path to encrypted file
            _dec_filename = "dec_" + _original_filename                             # create decrypted filename string
            # function used to decrypt the filename
            # decrypt(16 byte key, path to file, filename, filename length, encrypted filename, and encrypted filename length
            decrypt(get_key(_key), _path, _original_filename, _original_filename_len, _enc_filename, _modified_filename_len)
            # removes the file from the up folder
            os.remove(os.path.join("meraki/up/", "enc_" + _original_filename))
            # returns the file to the user who requests the data to be decrypted
            gc.collect()
            return send_from_directory(os.path.join(app.instance_path, ''), _dec_filename, as_attachment=True)

        except Exception:
            return redirect(url_for('dashboard'))


# =============================================================================
#
# =============================================================================
@app.route('/downloads/remove_downloads/<path:filename>', methods=['GET','POST'])
@login_required
def remove_downloads(filename):
    if request.method == 'GET':
        # creates a string from the file path
        fn = secure_filename(filename)
        # returns True if the file exists in memory
        questionEnc = os.path.exists("meraki/up/enc_" + fn)
        # returns true if the file exists in memory
        questionDec = os.path.exists("meraki/up/dec_" + fn)

        # If both files exist
        if questionEnc and questionDec == True:
            try:
                # remove both the decrypted and encrypted data once user requests a deletion
                os.remove(os.path.join("meraki/up/", "dec_" + fn))
                os.remove(os.path.join("meraki/up/", "enc_" + fn))
                # delete from upload_file where filename="file";
                c, conn = connection()
                # delete record form db where filename = the original filename uploaded
                c.execute("delete from upload_file where filename= '" + fn + "';")
                # commit changes
                conn.commit()
                # close the cursor
                c.close()
                # close the connection
                conn.close()
                # garbage collection
                gc.collect()
                # return a message to the user through the dashboard
                flash("    Your file has been removed successfully, mate.")
                # redirect the user to the dashboard
                return redirect(url_for('dashboard'))

            except Exception as e:
                return(str(e))

        elif questionEnc == True and questionDec == False:
            try:
                # remove the encrypted file from the up folder
                os.remove(os.path.join("meraki/up/", "enc_" + fn))
                # create cursor and connection
                c, conn = connection()
                # query to delete from the upload_file table where the filename equals the original filename
                c.execute("delete from upload_file where filename= '" + fn + "';")
                # commit the changes
                conn.commit()
                # close the cursor
                c.close()
                # close the connection
                conn.close()
                # garbage collection
                gc.collect()
                # message that is flashed once the user has removed the file
                flash("    Your file has been removed successfully, mate.")
                # returns the user to the dashboard
                return redirect(url_for('dashboard'))

            except Exception as e:
                return(str(e))


        elif questionEnc == False and questionDec == True:
            try:
                # remove the encrypted file from the up folder
                os.remove(os.path.join("meraki/up/", "dec_" + fn))
                # create cursor and connection
                c, conn = connection()
                # query to delete from the upload_file table where the filename equals the original filename
                c.execute("delete from upload_file where filename= '" + fn + "';")
                # commit the changes
                conn.commit()
                # close the cursor
                c.close()
                # close the connection
                conn.close()
                # garbage collection
                gc.collect()
                # message that is flashed once the user has removed the file
                flash("    Your file has been removed successfully, mate.")
                # returns the user to the dashboard
                return redirect(url_for('dashboard'))

            except Exception as e:
                return(str(e))

    return redirect(url_for('dashboard'))


# =============================================================================
#                                                                                       Meraki group information
# =============================================================================
@app.route('/group_information_changebacklater/')
def group_information():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("group_information/group_information.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


# =============================================================================
#                                                                                       TOS
# =============================================================================
@app.route('/tos/')
def tos():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("legal/tos.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


# =============================================================================
#                                                                                       Privacy
# =============================================================================
@app.route('/privacy/')
def privacy():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("legal/privacy.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


# =============================================================================
#                                                                                       Java
# =============================================================================
@app.route('/Java/')
@app.route('/Java/introduction/')
def java_introduction():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Java/introduction.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Java/syntax/')
@login_required
def java_syntax():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Java/syntax.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Java/comments/')
@login_required
def java_comments():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Java/comments.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Java/objects_classes/')
@login_required
def java_objects_classes():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Java/objects_classes.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Java/variables/')
@login_required
def java_variables():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Java/variables.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Java/data_structures/')
@login_required
def java_data_structures():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Java/data_structures.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Java/modifiers/')
@login_required
def java_modifiers():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Java/modifiers.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Java/operators/')
@login_required
def java_operators():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Java/operators.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Java/loop_control/')
@login_required
def java_loop_control():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Java/loop_control.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Java/decision_making/')
@login_required
def java_decision_making():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Java/decision_making.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Java/imports/')
@login_required
def java_imports():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Java/imports.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Java/files_io/')
@login_required
def java_files_io():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Java/files_io.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Java/exceptions/')
@login_required
def java_exceptions():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Java/exceptions.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Java/final_thoughts/')
@login_required
def java_final_thoughts():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Java/final_thoughts.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


# =============================================================================
#                                                                                       Python
# =============================================================================
@app.route('/Python/')
@app.route('/Python/introduction/')
def python_introduction():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Python/introduction.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Python/syntax/')
@login_required
def python_syntax():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Python/syntax.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Python/comments/')
@login_required
def python_comments():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Python/comments.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Python/data_types/')
@login_required
def python_data_types():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Python/data_types.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Python/objects_classes/')
@login_required
def python_objects_classes():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Python/objects_classes.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Python/variables/')
@login_required
def python_variables():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Python/variables.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Python/data_structures/')
@login_required
def python_data_structures():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Python/data_structures.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Python/functions/')
@login_required
def python_functions():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Python/functions.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Python/operators/')
@login_required
def python_operators():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Python/operators.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Python/loop_control/')
@login_required
def python_loop_control():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Python/loop_control.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Python/decision_making/')
@login_required
def python_decision_making():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Python/decision_making.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Python/imports/')
@login_required
def python_imports():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Python/imports.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Python/files_io/')
@login_required
def python_files_io():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Python/files_io.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Python/exceptions/')
@login_required
def python_exceptions():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Python/exceptions.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Python/final_thoughts/')
@login_required
def python_final_thoughts():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Python/final_thoughts.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


# =============================================================================
#                                                                                       C++
# =============================================================================
@app.route('/C_plusplus/')
@app.route('/C_plusplus/introduction/')
def c_plusplus_introduction():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/C_plusplus/introduction.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/C_plusplus/syntax/')
@login_required
def c_plusplus_syntax():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/C_plusplus/syntax.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/C_plusplus/comments/')
@login_required
def c_plusplus_comments():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/C_plusplus/comments.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/C_plusplus/objects_classes/')
@login_required
def c_plusplus_objects_classes():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/C_plusplus/objects_classes.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/C_plusplus/variables/')
@login_required
def c_plusplus_variables():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/C_plusplus/variables.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/C_plusplus/data_structures/')
@login_required
def c_plusplus_data_structures():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/C_plusplus/data_structures.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/C_plusplus/modifiers/')
@login_required
def c_plusplus_modifiers():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/C_plusplus/modifiers.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/C_plusplus/operators/')
@login_required
def c_plusplus_operators():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/C_plusplus/operators.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/C_plusplus/loop_control/')
@login_required
def c_plusplus_loop_control():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/C_plusplus/loop_control.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/C_plusplus/decision_making/')
@login_required
def c_plusplus_decision_making():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/C_plusplus/decision_making.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/C_plusplus/imports/')
@login_required
def c_plusplus_imports():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/C_plusplus/imports.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/C_plusplus/files_io/')
@login_required
def c_plusplus_files_io():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/C_plusplus/files_io.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/C_plusplus/exceptions/')
@login_required
def c_plusplus_exceptions():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/C_plusplus/exceptions.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/C_plusplus/final_thoughts/')
@login_required
def c_plusplus_final_thoughts():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/C_plusplus/final_thoughts.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


# =============================================================================
#                                                                                       C#
# =============================================================================
@app.route('/C_sharp/')
@app.route('/C_sharp/introduction/')
def c_sharp_introduction():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/C_sharp/introduction.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/C_sharp/introduction2/')
def c_sharp_introduction2():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/C_sharp/introduction2.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/C_sharp/syntax/')
@login_required
def c_sharp_syntax():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/C_sharp/syntax.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/C_sharp/comments/')
@login_required
def c_sharp_comments():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/C_sharp/comments.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/C_sharp/objects_classes/')
@login_required
def c_sharp_objects_classes():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/C_sharp/objects_classes.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/C_sharp/variables/')
@login_required
def c_sharp_variables():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/C_sharp/variables.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/C_sharp/data_structures/')
@login_required
def c_sharp_data_structures():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/C_sharp/data_structures.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/C_sharp/modifiers/')
@login_required
def c_sharp_modifiers():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/C_sharp/modifiers.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/C_sharp/operators/')
@login_required
def c_sharp_operators():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/C_sharp/operators.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/C_sharp/loop_control/')
@login_required
def c_sharp_loop_control():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/C_sharp/loop_control.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/C_sharp/decision_making/')
@login_required
def c_sharp_decision_making():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/C_sharp/decision_making.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/C_sharp/imports/')
@login_required
def c_sharp_imports():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/C_sharp/imports.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/C_sharp/files_io/')
@login_required
def c_sharp_files_io():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/C_sharp/files_io.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/C_sharp/exceptions/')
@login_required
def c_sharp_exceptions():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/C_sharp/exceptions.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/C_sharp/final_thoughts/')
@login_required
def c_sharp_final_thoughts():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/C_sharp/final_thoughts.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


# =============================================================================
#                                                                                       SQL
# =============================================================================
@app.route('/SQL/introduction/')
def sql_introduction():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/SQL/introduction.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/SQL/syntax/')
@login_required
def sql_syntax():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/SQL/syntax.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


# =============================================================================
#                                                                                       HTML
# =============================================================================
@app.route('/HTML/introduction/')
def html_introduction():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/HTML/introduction.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/HTML/syntax/')
def html_syntax():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/HTML/syntax.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


# =============================================================================
#                                                                                       AngularJS
#
#   There has been issues getting AngularJS to work properly on Pythonanywhere
#   For now, no interactive code within the tutorial
#   The code will have to be enough
# =============================================================================
@app.route('/AngularJS/introduction/')
def angularjs_introduction():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/AngularJS/introduction.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/AngularJS/environment/')
def angularjs_environment():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/AngularJS/environment.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/AngularJS/architecture/')
def angularjs_architecture():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/AngularJS/architecture.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/AngularJS/expressions/')
def angularjs_expressions():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/AngularJS/expressions.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


# =============================================================================
#                                                                                       Javascript
# =============================================================================
@app.route('/Javascript/introduction/')
def javascript_introduction():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Javascript/introduction.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Javascript/installation/')
def javascript_installation():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Javascript/installation.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Javascript/output/')
def javascript_output():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Javascript/output.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Javascript/syntax/')
def javascript_syntax():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Javascript/syntax.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Javascript/statements/')
def javascript_statements():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Javascript/statements.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Javascript/comments/')
def javascript_comments():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Javascript/comments.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Javascript/variables/')
def javascript_variables():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Javascript/variables.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Javascript/operators/')
def javascript_operators():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Javascript/operators.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Javascript/arithmetic/')
def javascript_arithmetic():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Javascript/arithmetic.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Javascript/assignment/')
def javascript_assignment():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Javascript/assignment.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Javascript/data_types/')
def javascript_data_types():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Javascript/data_types.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Javascript/functions/')
def javascript_functions():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Javascript/functions.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Javascript/objects/')
def javascript_objects():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Javascript/objects.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Javascript/scope/')
def javascript_scope():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Javascript/scope.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Javascript/events/')
def javascript_events():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Javascript/events.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Javascript/strings/')
def javascript_strings():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Javascript/strings.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Javascript/string_methods/')
def javascript_string_methods():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Javascript/string_methods.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Javascript/numbers/')
def javascript_numbers():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Javascript/numbers.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Javascript/number_methods/')
def javascript_number_methods():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Javascript/number_methods.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


@app.route('/Javascript/math/')
def javascript_math():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("languages/Javascript/math.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


# =============================================================================
#                                                                                       Portfolio
# =============================================================================

@app.route('/portfolio2/')
def portfolio():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("users/xRzy/portfolio.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


# =============================================================================
#                                                                                       Portfolio 2.0
# =============================================================================

@app.route('/portfolio/')
def portfolio2():
    un = get_un()
    try:
        return render_template("users/xRzy/port.html",un=un)

    except Exception as e:
        return(str(e))


# =============================================================================
#                                                                                       testing AngularJS Only
# =============================================================================

@app.route('/test/')
def test():
    un = get_un()
    try:
        return render_template("test.html",un=un)

    except Exception as e:
        return(str(e))


@app.route('/interview/')
def interview():
    un = get_un()
    number_of_messages = get_number_of_messages()
    number_of_downloads = get_number_of_downloads()
    try:
        return render_template("users/xRzy/interview.html", page_dict=page_dict, un=un, number_of_messages=number_of_messages, number_of_downloads=number_of_downloads)

    except Exception as e:
        return(str(e))


# =============================================================================
#   It is OKAY to run app.run() within the function on pythonanywhere
#   DO NOT RUN app.run() outside of the python main function
# =============================================================================
if __name__ == "__main__":
    app.run(debug=True)