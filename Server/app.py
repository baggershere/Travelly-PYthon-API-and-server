from flask import Flask, jsonify, request, url_for, jsonify, redirect, session, render_template, make_response, redirect, render_template, abort
import re
import random
from psycopg2.extensions import AsIs
import psycopg2
import sys
import json
import datetime
import collections
import re
import os


# so that we can implement csrf tokens, we need to create a session as soon as someone visits the login or create a post page (if they don't have one already).
# with GET request for each page, we can:

# Check for an existing session: yes/no
# if no:
# create a new session and a new csrf token and store together in db (username blank). Then render relavent page with session cookie holding sid and csrf token being sent into html form.
# if yes:
# check if there is a username with the session ID in db.
# If there is, for login:
# render index.html
# for post:
# get csrf token from db where username= username and render page along with csrf token which is added to the form (need to insert hidden field into each form)
# if not, get csrf token where sessiondid= sessionid and return it with login.html\create_post.html

# for the POST request for each page, we then just need to get the CSRF token from the sumitted data and check it in the db against the sessionID

# Look at checking to make sure session is still valid before carrying out actions- at the moment session is only removed at logout?

def delete_tags(string):
    deleted = re.compile('<.*?>')
    return re.sub(deleted, '', string)


def escape(s):
    s = s.replace("&", "&amp;")
    s = s.replace("<", "&lt;")
    s = s.replace(">", "&gt;")
    s = s.replace("\"", "&quot;")
    s = s.replace("'", "&#x27;")
    s = s.replace("@", "&commat;")
    s = s.replace("=", "&equals;")
    s = s.replace("`", "&grave;")
    return s


def escape_email(s):
    s = s.replace("&", "&amp;")
    s = s.replace("<", "&lt;")
    s = s.replace(">", "&gt;")
    s = s.replace("\"", "&quot;")
    s = s.replace("'", "&#x27;")
    s = s.replace("=", "&equals;")
    s = s.replace("`", "&grave;")
    return s


app = Flask(__name__)
app.config['DEBUG'] = True
search_path = "SET SEARCH_PATH TO travelly;"
app.config['SECRET_KEY'] = 'Thisisasecret!'

# there's another copy of this function further down
# def createRandomId():
#   random_digits = 'abcdefghijklmnopABCDEFGHIJKLMNOP123456789'
#  sess_id=''
# for i in range(len(random_digits)):
#    random_digit = random.choice(random_digits)
#   sess_id += random_digit
# return sess_id
dirname = os.path.dirname(__file__)
filename = os.path.join(dirname, '..\password.txt')
f = open(filename, "r")
password = f.readline()
f.close()

def getcon():
    connStr = "host='localhost' user='postgres' dbname='Travelly' password=" + password
    conn=psycopg2.connect(connStr) 
    return conn


def error_handler(err):
    errors = {
        'error': ''
    }
    err_type, err_obj, traceback = sys.exc_info()
    # get the line number when exception occured
    line_num = traceback.tb_lineno
    # print the connect() error
    print("\npsycopg2 ERROR:", err, "on line number:", line_num)
    print("psycopg2 traceback:", traceback, "-- type:", err_type)
    # psycopg2 extensions.Diagnostics object attribute
    print("\nextensions.Diagnostics:", err.diag)
    # print the pgcode and pgerror exceptions
    print("pgerror:", err.pgerror)
    print("pgcode:", err.pgcode, "\n")


def check_if_record_exists(table, column, string):
    try:
        conn = getcon()
        cur = conn.cursor()
        cur.execute(search_path)
        cur.execute("""SELECT %s FROM %s WHERE %s = %s;""", [
                    AsIs(column), AsIs(table), AsIs(column), string])
        return cur.fetchone() is not None
    except Exception as e:
        print(e)


def insert_sessionID(sessionID, column, username):
    expire = datetime.datetime.now() + datetime.timedelta(hours=0.5)
    conn = getcon()
    cur = conn.cursor()
    cur.execute(search_path)
    cur.execute("""INSERT INTO %s VALUES(%s,%s,%s);""", [
                AsIs(column), sessionID,  username, str(expire)])
    conn.close()


def get_salt_from_db(username):
    try:
        conn = getcon()
        cur = conn.cursor()
        cur.execute(search_path)
        # using min here means 1 row will be sent back even if there is no salt (then it will send back a row saying null)
        cur.execute(
            "SELECT coalesce(min(salt),'1') FROM tr_users WHERE username = %s;", [username])
        # this keeps the time exactly the same whether there is salt or not and stops errors later one. Coalesce stops it from returning NULL for line 94.
        return cur.fetchone()[0]
    except Exception as e:
        error_handler(e)


def get_password_from_db(username):
    try:
        conn = getcon()
        cur = conn.cursor()
        cur.execute(search_path)
        cur.execute(
            "SELECT password FROM tr_users WHERE username = %s", [username])
        password = cur.fetchone()
        return password
    except Exception as e:
        print(e)


def remove_session(username):
    conn = getcon()
    cur = conn.cursor()
    cur.execute(search_path)
    cur.execute("""DELETE FROM %s WHERE username = %s""",
                [AsIs('tr_session'), username])
    conn.commit()
    conn.close()
    return


def insert_session(sid, username, time):
    conn = getcon()
    cur = conn.cursor()
    cur.execute(search_path)
    cur.execute("""INSERT INTO %s VALUES(%s,%s,%s);""", [
                AsIs('tr_session'), sid, username, time])
    conn.commit()
    return


def session_auth(cookies):
    session = cookies.get('sessionID')
    if (session):
        conn = getcon()
        cur = conn.cursor()
        cur.execute(search_path)
        cur.execute("SELECT sid FROM tr_session WHERE sid = %s", [session])
        resp = cur.fetchone()
        conn.commit()
        if (resp):
            cur.execute(search_path)
            cur.execute(
                "SELECT expires FROM tr_session WHERE sid = %s", [session])
            conn.commit()
            expires = cur.fetchone()[0]
            if datetime.datetime.now() < expires:
                cur.execute(search_path)
                cur.execute(
                    "SELECT username FROM tr_session WHERE sid = %s", [session])
                username = cur.fetchone()[0]
                if username != 'NULL':
                    return True
                else:
                    return False
            else:
                cur.execute(search_path)
                cur.execute("DELETE FROM %s WHERE sid=%s",
                            [AsIs('tr_session'), session])
                conn.commit()
                return False
        else:
            return False
    else:
        return False


def session_auth_not_loggedin(cookies):
    session = cookies.get('sessionID')
    if (session):
        conn = getcon()
        cur = conn.cursor()
        cur.execute(search_path)
        cur.execute("SELECT sid FROM tr_session WHERE sid = %s", [session])
        resp = cur.fetchone()
        conn.commit()
        if (resp):
            return True
        else:
            return False
    else:
        return False


def get_username_from_session(sessionID):
    conn = getcon()
    cur = conn.cursor()
    cur.execute(search_path)
    cur.execute("SELECT username FROM tr_session WHERE sid = %s", [sessionID])
    user = cur.fetchone()
    conn.commit()
    if (user):
        return user[0]
    else:
        return 'No user'


def get_unused_pid():
    conn = getcon()
    cur = conn.cursor()
    cur.execute(search_path)
    cur.execute("SELECT MAX(pid) FROM tr_post;")
    conn.commit()
    return cur.fetchone()


def insert_post(post_info):
    title, country, author, content, date = post_info['title'], post_info[
        'country'], post_info['author'], post_info['content'], post_info['date'],
    title = escape(title)
    country = escape(country)
    content = escape(content)
    conn = getcon()
    cur = conn.cursor()
    cur.execute(search_path)
    cur.execute("INSERT INTO tr_post (title, country, author, content, date) VALUES (%s,%s,%s,%s,%s)", [
                title, country, author, content, date])
    conn.commit()


def fetch_all_posts():
    conn = getcon()
    cur = conn.cursor()
    cur.execute(search_path)
    cur.execute("SELECT * FROM tr_post ORDER BY date DESC")
    posts = cur.fetchall()
    posts_array = []
    for post in posts:
        posts_array.append({
            "pid": post[0],
            "title": post[1],
            "country": post[2],
            "author": post[3],
            "content": post[4],
            "date": post[5]
        })
    return posts_array


def fetch_banned_ip():
    conn = getcon()
    cur = conn.cursor()
    cur.execute(search_path)
    cur.execute(
        "SELECT DISTINCT ip_address FROM ip_ban WHERE date >= now() - INTERVAL '30 minute'")
    resp = cur.fetchall()
    return resp


def insert_into_ip_ban(username, ip):
    conn = getcon()
    cur = conn.cursor()
    cur.execute(search_path)
    cur.execute("INSERT INTO ip_ban (ip_address,username,date) VALUES (%s,%s,NOW())", [
                ip, username])
    conn.commit()
    conn.close()


def ip_ban_or_no_ip_ban(ip):
    conn = getcon()
    cur = conn.cursor()
    cur.execute(search_path)
    cur.execute(
        "SELECT COUNT(*) FROM ip_ban WHERE ip_address = %s AND date >= now() - INTERVAL '30 minute'", [ip])
    resp = cur.fetchone()[0]
    if resp > 100:
        return True
    else:
        return False


def fetch_most_recent_user_posts(username):
    conn = getcon()
    cur = conn.cursor()
    cur.execute(search_path)
    cur.execute(
        "SELECT * FROM tr_post WHERE author=%s ORDER BY date DESC", [username])
    posts = cur.fetchall()[:10]
    posts_array = []
    for post in posts:
        posts_array.append({
            "pid": post[0],
            "title": post[1],
            "country": post[2],
            "author": post[3],
            "content": post[4],
            "date": post[5]
        })
    return posts_array


def fetch_individual_post(id):
    conn = getcon()
    cur = conn.cursor()
    cur.execute(search_path)
    cur.execute("SELECT * FROM tr_post WHERE pid=%s", [id])
    post = cur.fetchone()
    return {
        "pid": post[0],
        "title": post[1],
        "country": post[2],
        "author": post[3],
        "content": post[4],
        "date": post[5]
    }


def fetch_five_most_pop():
    conn = getcon()
    cur = conn.cursor()
    cur.execute(search_path)
    cur.execute(
        "SELECT country FROM %s GROUP BY country ORDER BY COUNT(*) DESC LIMIT 5", [AsIs('tr_post')])
    conn.commit()
    resp = cur.fetchall()
    five_most_pop_string = " ".join([i[0] for i in resp])
    countries = five_most_pop_string.split()
    return countries


def get_user_information(sessionID):
    conn = getcon()
    cur = conn.cursor()
    cur.execute(search_path)
    cur.execute("SELECT username FROM tr_session WHERE sid = %s", [sessionID])
    username = cur.fetchone()
    cur.execute("SELECT * FROM tr_users WHERE username=%s", [username])
    user_details = cur.fetchone()
    return {
        "username": user_details[0],
        "name": user_details[1],
        "surname": user_details[2],
        "email": user_details[3],
    }


def lockout_or_no_lockout(username):
    conn = getcon()
    cur = conn.cursor()
    cur.execute(search_path)
    cur.execute(
        "SELECT COUNT(*) FROM tr_lockout WHERE username = %s AND date >= now() - INTERVAL '1 minute'", [username])
    resp = cur.fetchone()[0]
    print(resp)
    if resp > 3:
        return True
    else:
        return False


def username_right_password_wrong(username, password):
    cur = getcon().cursor()
    cur.execute(search_path)
    cur.execute(
        "SELECT COUNT(*) FROM tr_users WHERE username = %s", [username])
    username_exists_or_not = cur.fetchone()[0]
    if (username_exists_or_not != 0):
        cur.execute(
            "SELECT password from tr_users WHERE username = %s", [username])
        return True if password != cur.fetchone()[0] else False
    else:
        return False


def get_csrf_token(sessionID):
    conn = getcon()
    cur = conn.cursor()
    cur.execute(search_path)
    cur.execute("SELECT csrf FROM tr_session WHERE sid = %s", [sessionID])
    csrf_token = cur.fetchone()[0]
    return csrf_token


def get_username_from_pid(pid):
    conn = getcon()
    cur = conn.cursor()
    cur.execute(search_path)
    cur.execute("SELECT author FROM tr_post WHERE pid = %s", [pid])
    conn.commit()
    username = cur.fetchone()
    return username[0] if username != None else None


def is_admin(username):
    conn = getcon()
    cur = conn.cursor()
    cur.execute(search_path)
    cur.execute(
        "SELECT COUNT(*) FROM tr_users WHERE username = %s AND admin = 'true'", [username])
    res = cur.fetchone()
    return res[0]


def session_is_admin(cookies):
    sessionID = cookies.get('sessionID')
    if (sessionID):
        conn = getcon()
        cur = conn.cursor()
        cur.execute(search_path)
        username = get_username_from_session(sessionID)
        if (username and is_admin(username)):
            return True
    else:
        return False


@app.errorhandler(404)
def page_not_found(e):
    # note that we set the 404 status explicitly
    return render_template('notfound.html'), 404


@app.route('/notfound')
def error_test():
    abort(404)


def fetch_all_countries():
    conn = getcon()
    cur = conn.cursor()
    cur.execute(search_path)
    cur.execute("SELECT country FROM tr_post")
    resp = cur.fetchall()
    return resp



@app.route('/', methods = ['GET'])
def default_home():
    return redirect(url_for('home')), 200


@app.route('/home', methods=['GET'])
def home():
    home_buttons = False
    posts = fetch_all_posts()
    session = session_auth(request.cookies)
    countries = fetch_five_most_pop()
    all_countries_with_posts = fetch_all_countries()
    if (session):
        sessionID = request.cookies.get('sessionID')
        csrf_token = createRandomId()
        conn = getcon()
        cur = conn.cursor()
        cur.execute(search_path)
        sql = "UPDATE tr_session SET csrf = %s WHERE sid= %s"
        data = (csrf_token, sessionID)
        cur.execute(sql, data)
        conn.commit()
        #private_user_information = get_user_information(sessionID)
        return render_template('home.html', countries=all_countries_with_posts, len=len(posts), posts=posts, create_form=True, home_buttons=True, fav_countries=countries, len_countries=len(countries), csrf_token=csrf_token, admin_btn=True if is_admin(get_username_from_session(request.cookies.get('sessionID'))) else False)
    else:
        return render_template('home.html', countries=all_countries_with_posts, len=len(posts), posts=posts, fav_countries=countries, len_countries=len(countries))


# Make a post - POST /createpost


@app.route('/home', methods=['POST'])
def createpost():
    # Check that session exists and is valid. However, this could be removed as this check should be run
    # Before actually accessing the createpost page. To do this, run session auth on the /createpost
    # GET request and either redirect or allow post creation
    if (request.cookies.get('sessionID') and session_auth(request.cookies)):
        sessionID = request.cookies.get('sessionID')
        user_csrf_token = get_csrf_token(sessionID)
        csrf_token_received = request.form['csrf_token'].strip('/')
        if user_csrf_token == csrf_token_received:
            user_session = request.cookies.get('sessionID')
            # Useful data that can be accessed from the request object. Data sent as JSON for testing purposes
            input_data = {

                'title': delete_tags(str(request.form['post-title'].lower())),
                'country': str(request.form.get('country').lower()),
                'content': delete_tags(str(request.form['post-content'].lower())),
                'date': datetime.datetime.now()

            }
            # In order to completed the input_data object with the missing data needed to
            # insert the post, we can use the session to access the author of the post.
            input_data['author'] = get_username_from_session(user_session)
            #input_data['pid'] = get_unused_pid()[0] + 1
            # Insert the data to tr_post table
            insert_post(input_data)
            return redirect(url_for('home'))
        else:
            return jsonify(status='csrf tokens do not match')
    else:
        return jsonify(status='bad or no session')


@app.route('/logout', methods=['GET'])
def logout():
    try:
        session = request.cookies['sessionID']
    except:
        return redirect(url_for('get_login'))

    if (session and request.method == 'GET'):
        conn = getcon()
        cur = conn.cursor()
        cur.execute(search_path)
        cur.execute("DELETE FROM %s WHERE sid=%s",
                    [AsIs('tr_session'), session])
        conn.commit()
        return redirect(url_for('home'))
    else:
        return redirect(url_for('get_login'))


@app.route('/home/<country>')
def return_counry_posts(country):
    country = [word.capitalize() for word in escape(country).split('_')]
    session = session_auth(request.cookies)
    countries = fetch_five_most_pop()
    all_countries_with_posts = fetch_all_countries()
    conn = getcon()
    cur = conn.cursor()
    cur.execute(search_path)

    cur.execute("SELECT * FROM tr_post WHERE country=%s", [' '.join(country)])

    conn.commit()
    res = cur.fetchall()
    posts = []
    for p in res:
        post = {
            "pid": p[0],
            "title": p[1],
            "country": p[2],
            "author": p[3],
            "content": p[4],
            "date": p[5]
        }
        posts.append(post)
    if (session):
        sessionID = request.cookies.get('sessionID')
        return render_template('home.html', countries=all_countries_with_posts, len=len(posts), posts=posts, create_form=False, home_buttons=True, fav_countries=countries, len_countries=len(countries))
    else:
        return render_template('home.html', countries=all_countries_with_posts, len=len(posts), posts=posts, fav_countries=countries, len_countries=len(countries))

# IF a user has logged in, they can view the most recent posts from any user in the application.


@app.route('/user/<username>')
def user_page(username):
    session = session_auth(request.cookies)
    user_posts = fetch_most_recent_user_posts(escape(username))
    return render_template('userpage.html', posts=user_posts, len=len(user_posts))


@app.route('/post/<id>')
def individual_post(id):
    individual_post = fetch_individual_post(id)
    return render_template('postpage.html', post=individual_post)


@app.route('/profile')
def profile_page():
    session = session_auth(request.cookies)
    if (session):
        sessionID = request.cookies.get('sessionID')
        private_user_information = get_user_information(sessionID)
        user_posts = fetch_most_recent_user_posts(
            private_user_information["username"])
        return render_template('profile.html', user_info=private_user_information, posts=user_posts, len=len(user_posts))
    else:
        return redirect(url_for('get_login'))


@app.route('/login')
def get_login():
    session_exists = session_auth_not_loggedin(request.cookies)
    if session_exists:
        sessionID = request.cookies.get('sessionID')
        username = get_username_from_session(sessionID)
        if username != 'NULL':
            return redirect(url_for('home'))
        else:
            conn = getcon()
            cur = conn.cursor()
            cur.execute(search_path)
            cur.execute("DELETE FROM %s WHERE sid=%s", [
                        AsIs('tr_session'), sessionID])
            conn.commit()
            sessionID = createRandomId()
            csrf_token = createRandomId()
            expire = datetime.datetime.now() + datetime.timedelta(hours=0.5)
            sql = "INSERT into tr_session VALUES (%s, %s, %s, %s)"
            data = (sessionID, 'NULL', expire, csrf_token)
            conn = getcon()
            cur = conn.cursor()
            cur.execute(search_path)
            cur.execute(sql, data)
            conn.commit()
            resp = make_response(render_template(
                'login.html', csrf_token=csrf_token))
            resp.set_cookie('sessionID', sessionID)
            return resp
    else:
        sessionID = createRandomId()
        csrf_token = createRandomId()
        expire = datetime.datetime.now() + datetime.timedelta(hours=0.5)
        sql = "INSERT into tr_session VALUES (%s, %s, %s, %s)"
        data = (sessionID, 'NULL', expire, csrf_token,)
        conn = getcon()
        cur = conn.cursor()
        cur.execute(search_path)
        cur.execute(sql, data)
        conn.commit()
        resp = make_response(render_template(
            'login.html', csrf_token=csrf_token))
        resp.set_cookie('sessionID', sessionID)
        return resp


@app.route('/login', methods=['POST'])
def post_login():
    # get csrf token from form and check it against the one in the db for this session ID
    # if match proceed, if not block.
    user_csrf_token = request.form['csrf_token'].strip("/")
    sessionID = request.cookies.get('sessionID')
    csrf_token = get_csrf_token(sessionID)
    if csrf_token == user_csrf_token:
        data = {
            'username': request.form['username'].lower(),
            'password': request.form['password']
        }
        expire = datetime.datetime.now() + datetime.timedelta(hours=0.5)
        try:
            # The count sends back 0 or 1 as a result, depending on whether the pw and username are correct
            sql = "SELECT count(*) from tr_users WHERE username =%s and password= %s"
            user_input_password = pw_hash_salt(
                data['password'], (get_salt_from_db(data['username'])))
            query_data = (data['username'], (user_input_password))
            conn = getcon()
            cur = conn.cursor()
            cur.execute(search_path)
            cur.execute(sql, query_data)
            conn.commit()
            check_account = cur.fetchone()[0]

            # if there is a result, the pw and username were correct
            print(request.environ.get('HTTP_X_REAL_IP', request.remote_addr))
            print(ip_ban_or_no_ip_ban(request.environ.get(
                'HTTP_X_REAL_IP', request.remote_addr)))
            if (ip_ban_or_no_ip_ban(request.environ.get('HTTP_X_REAL_IP', request.remote_addr))):
                return render_template('login.html', check_input='IP BANNED', csrf_token=csrf_token)

            if (username_right_password_wrong(data['username'], user_input_password)):
                cur.execute("INSERT INTO tr_lockout VALUES (%s, %s)", [
                            data['username'], datetime.datetime.now()])
                conn.commit()
                insert_into_ip_ban(data['username'], request.environ.get(
                    'HTTP_X_REAL_IP', request.remote_addr))

            if (lockout_or_no_lockout(data['username'])):
                return render_template('login.html', check_input='Your account has been temporarily locked out', csrf_token=csrf_token)

            if check_account != 0:
                conn = getcon()
                cur = conn.cursor()
                cur.execute(search_path)
                cur.execute("DELETE FROM %s WHERE sid=%s", [
                            AsIs('tr_session'), sessionID])
                conn.commit()
                cur.execute(search_path)
                cur.execute("""DELETE FROM %s WHERE username = %s""", [
                            AsIs('tr_session'), data['username']])
                # may need to add csrf token here if we do it for create_post form
                sessionID = createRandomId()
                cur.execute("""INSERT INTO %s VALUES(%s,%s,%s);""", [
                            AsIs('tr_session'), sessionID, data['username'], str(expire)])
                conn.commit()
                resp = make_response(redirect('/home'))
                resp.set_cookie('sessionID', sessionID,
                                samesite='Lax', httponly=True)
                return resp
            else:
                insert_into_ip_ban(data['username'], request.environ.get(
                    'HTTP_X_REAL_IP', request.remote_addr))
                return render_template('login.html', check_input='Incorrect username or password', csrf_token=csrf_token)

        except Exception as e:
            print(e)
            return render_template('login.html', check_input='Something happened BAD!')
    else:
        return render_template('login.html', check_input='CSRF tokens do not match.')


@app.route('/signup', methods=['GET', 'POST'])
def signup_form():
    if request.method == 'GET':
        session_exists = session_auth_not_loggedin(request.cookies)
        if session_exists:
            sessionID = request.cookies.get('sessionID')
            username = get_username_from_session(sessionID)
            if username != 'NULL':
                return redirect(url_for('home'))
            else:
                return render_template('signup.html', name="", surname="", username="", email="", dob="", r_answer="")
        else:
            return render_template('signup.html')
    else:
        user_sign_up = {
            'firstname':  request.form['name'].lower(),
            'lastname': request.form['surname'].lower(),
            'username': request.form['username'].lower(),
            'email': request.form['email'].lower(),
            'dob': request.form['birthdate'],
            'password': request.form['password'],
            'recovery_question': request.form['recovery-question'],
            'recovery_answer': request.form['recovery-answer'],
            'salt': pw_salt(),
            'r_salt': pw_salt()
        }
        r_answer = user_sign_up['recovery_answer']
        # print(user_sign_up)
        # first check user inputs are valid firstname, lastname, username, email and password
        check_input = input_validation(user_sign_up)
        # print(check_input)
        if check_input == True:
            # hash and salt password before sending it to database
            user_sign_up['password'] = pw_hash_salt(
                user_sign_up['password'], user_sign_up['salt'])
            user_sign_up['recovery_answer'] = pw_hash_salt(
                user_sign_up['recovery_answer'], user_sign_up['r_salt'])
            # insert user details to database. It returns a message whether the user is successfully
            # inserted or not
            return render_template('signup.html', name=user_sign_up['firstname'], surname=user_sign_up['lastname'],
                                   username=user_sign_up['username'], email=user_sign_up['email'],
                                   dob=user_sign_up['dob'], r_answer=r_answer,
                                   check_input=insert_user(user_sign_up))
        else:
            # Give error message to user
            return render_template('signup.html',
                                   name=user_sign_up['firstname'], surname=user_sign_up['lastname'],
                                   username=user_sign_up['username'], email=user_sign_up['email'],
                                   dob=user_sign_up['dob'], r_answer=user_sign_up['recovery_answer'],
                                   check_input=check_input)


@app.route('/api/deletepost', methods=['POST'])
def delete_post():
    #session = session_auth(request.cookies)
    pid = request.json['pid']
    # Check that username from session is equal to username of the post
    sessionID = request.cookies.get('sessionID')
    resp = make_response('unauthorised', 401)
    if (sessionID != None and session_auth(request.cookies)):
        username_from_session = get_username_from_session(sessionID)
        username_from_pid = get_username_from_pid(pid)
        if (((username_from_session != None and username_from_pid != None) and (username_from_session == username_from_pid)) or (is_admin(get_username_from_session(sessionID)))):
            conn = getcon()
            cur = conn.cursor()
            cur.execute(search_path)
            cur.execute("DELETE FROM tr_post WHERE pid=%s", [pid])
            conn.commit()
            resp = make_response('added', 201)
            return resp
        else:
            return resp
        return resp
    return resp


@app.route('/api/deleteuser', methods=['POST'])
def del_user():
    sessionID = request.cookies.get('sessionID')
    user_to_delete = request.json['user']
    if (sessionID and is_admin(get_username_from_session(sessionID)) and user_to_delete != 'tradmin'):
        conn = getcon()
        cur = conn.cursor()
        cur.execute(search_path)
        cur.execute("DELETE FROM tr_users WHERE username = %s",
                    [user_to_delete])
        conn.commit()
        return
    else:
        return


@app.route('/accountrecovery', methods=['GET'])
def get_account_recover():
    try:
        sessionID = request.cookies.get('sessionID')
        session = session_auth(request.cookies)
        if (session and sessionID):
            return redirect(url_for('home'))
        else:
            return render_template('accountrecovery.html', recovery_form=True, question_form=False, password_form=False)
    except:
        pass


@app.route('/recoveryquestion', methods=['POST'])
def post_account_recover():

    account_recovery = {
        'email': escape_email(request.form['email'].lower()),
        'dob': escape(request.form['birthdate'])
    }
    user_credentials = check_email_dob(account_recovery)
    if user_credentials:
        recovery_question = user_credentials[0][0]
        return render_template('accountrecovery.html', recovery_form=False, password_form=True, recovery_question=recovery_question)
    else:
        return render_template('accountrecovery.html', recovery_form=True, check_input="Please, check your credentials again!")


@app.route('/changepassword', methods=['POST'])
def change_account_password():
    user_change_password = {
        'username': escape(request.form['username'].lower()),
        'recovery-answer':  escape(request.form['recovery-answer']),
        'new_password': request.form['password'],
        'salt': pw_salt()
    }
    user_name = user_change_password['username']
    user_credentials = check_username(user_name)
    if user_credentials:
        recovery_answer = user_credentials[0][1]
        recovery_answer_salt = user_credentials[0][2]
        user_input_salted_answer = pw_hash_salt(
            user_change_password['recovery-answer'], recovery_answer_salt)
        if is_valid_password(user_credentials, user_change_password['new_password']):
            if user_input_salted_answer == recovery_answer:
                username = user_credentials[0][0]
                salted_pw = pw_hash_salt(
                    user_change_password['new_password'], user_change_password['salt'])
                update_password(username, salted_pw, user_change_password['salt'])
                return redirect('home')
            else:
                return render_template('accountrecovery.html', password_form=True, check_input="Please, check your answer again!")
        else:
            return render_template('accountrecovery.html', password_form=True, check_input="Please, enter a valid password!")
    else:
        return render_template('accountrecovery.html', password_form=True, check_input="Please, check your username")


def is_valid_password(user_data, password):
    firstname = user_data[0][1]
    lastname = user_data[0][2]
    if (firstname.lower() in password.lower()) or (lastname.lower() in password.lower()):
        return False
    elif not bool(re.fullmatch('^(?=.{10,20})(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+*!=]).*$', password)):
        return False
    else:
        return True


def check_email_dob(account_recovery):
    conn = getcon()
    cur = conn.cursor()
    cur.execute(search_path)
    sql = """SELECT recoveryquestion FROM tr_users WHERE email = %s and dob = %s;"""
    data = (account_recovery['email'], account_recovery['dob'])
    cur.execute(sql, data)
    conn.commit()
    res = cur.fetchall()
    return res


def check_username(user_name):
    conn = getcon()
    cur = conn.cursor()
    cur.execute(search_path)
    sql = """SELECT username, recoveryanswer, r_salt FROM tr_users WHERE username =  '%s' """ % user_name
    cur.execute(sql)
    conn.commit()
    res = cur.fetchall()
    return res


def update_password(username, password, salt):
    conn = getcon()
    cur = conn.cursor()
    cur.execute(search_path)
    sql = """UPDATE tr_users SET (password, salt) = (%s, %s) WHERE username = %s """
    data = (password, salt, username)
    cur.execute(sql, data)
    conn.commit()


def fetch_users():
    conn = getcon()
    cur = conn.cursor()
    cur.execute(search_path)
    cur.execute("SELECT username, firstname, lastname, email FROM tr_users")
    conn.commit()
    res = cur.fetchall()
    return res


@app.route('/admin', methods=['GET'])
def admin_page():
    if (session_is_admin(request.cookies)):
        list_of_users = fetch_users()
        user_posts = fetch_all_posts()
        banned_ips = fetch_banned_ip()
        return render_template('admin.html', users=list_of_users, posts=user_posts, banned_ips=banned_ips)
    else:
        return render_template('notfound.html')


@app.route('/api/unbanip', methods=['POST'])
def unban_ip():
    print('ran')
    sessionID = request.cookies.get('sessionID')
    ip_to_unban = request.json['ip']
    if (sessionID and is_admin(get_username_from_session(sessionID))):
        conn = getcon()
        cur = conn.cursor()
        cur.execute(search_path)
        cur.execute("DELETE FROM ip_ban WHERE ip_address = %s", [ip_to_unban])
        conn.commit()
        return
    else:
        return

def insert_user(data):
    try:
        conn = getcon()
        cur = conn.cursor()
        username = escape(data['username'])
        firstname = escape(data['firstname'])
        lastname = escape(data['lastname'])
        email = escape_email(data['email'])
        recovery_answer = escape(data['recovery_answer'])
        sql = """SET SEARCH_PATH TO travelly;
                    INSERT INTO tr_users (username, firstname, lastname, email, dob, password, recoveryquestion, recoveryanswer, salt, r_salt) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s);"""
        data = (username, firstname, lastname, email, data['dob'], data['password'],
                data['recovery_question'], recovery_answer, data['salt'], data['r_salt'])
        cur.execute(sql, data)
        conn.commit()
        return 'Your account is successfully created!'
    except psycopg2.IntegrityError as e:
        #err_resp = error_handler(e)
        return 'Username or email already exists! Please, try again.'


def input_validation(user_sign_up):
    if not bool(re.fullmatch('[A-Za-z]{2,25}( [A-Za-z]{2,25})?', user_sign_up['firstname'])):
        return "Your name is invalid. Please, type it again."
    elif not bool(re.fullmatch('[A-Za-z]{2,25}( [A-Za-z]{2,25})?', user_sign_up['lastname'])):
        return "Your surname is invalid. Please, type it again."
    elif not bool(re.fullmatch('^[A-Za-z0-9_-]*$', user_sign_up['username'])):
        return "Username must include letters and numbers."
    elif not bool(re.fullmatch('^(?=.{10,20})(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+*!=]).*$', user_sign_up['password'])):
        return "Check your password again."
    elif (user_sign_up['firstname'].lower() in user_sign_up['password'].lower()) or (user_sign_up['lastname'].lower() in user_sign_up['password'].lower()):
        return "Your password must not include your name or surname."
    elif not bool(re.fullmatch('[A-Za-z]{2,25}( [A-Za-z]{2,25})?', user_sign_up['recovery_answer'])):
        return "Account recovery answer must include only letters."
    else:
        return True


def pw_salt():
    random_digits = '''abcdeg_+]|,./;:>'''
    pw_salt = ''
    i = 0
    while i <= len(random_digits):
        random_digit = random.choice(random_digits)
        pw_salt += str(ord(random_digit))
        i = i+1
    return int(pw_salt)


def pw_hash_salt(unhashed_pw, pw_salt=0):
    num = 31
    hashed_pw = 0
    for i in range(0, len(unhashed_pw)):
        hashed_pw += ((num * hashed_pw) + ord(unhashed_pw[i]))
    hashed_salted_pw = str(hashed_pw) + str(pw_salt)
    return hashed_salted_pw


def createRandomId():
    random_digits = 'abcdefghijklmnopABCDEFGHIJKLMNOP123456789'
    sess_id = ''
    i = 0

    while i <= len(random_digits):
        random_digit = random.choice(random_digits)
        sess_id += random_digit
        i += 1

    return sess_id


if __name__ == '__main__':
    app.run(port=80, debug=True)
