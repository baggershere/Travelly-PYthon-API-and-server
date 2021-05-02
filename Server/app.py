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


def delete_tags(string):
    '''removes tags from content'''
    deleted = re.compile('<.*?>')
    return re.sub(deleted, '', string)


def escape(s):
   ''' escapes certain characters before sending content to the database'''
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
     ''' escapes certain characters before sending email addresses to the database'''
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



dirname = os.path.dirname(__file__)
filename = os.path.join(dirname, '..\password.txt')
f = open(filename, "r")
password = f.readline()
f.close()


def getcon():
''' used to conntect to database'''
    connStr = "host='localhost' user='postgres' dbname='Travelly' password=" + password
    conn=psycopg2.connect(connStr) 
    cur = conn.cursor()
    cur.execute(search_path)
    print(cur, conn)
    return conn, cur

def error_handler(err):
'''handles errors sent by the database'''
    errors = {
        'error': ''
    }
    err_type, err_obj, traceback = sys.exc_info()
    line_num = traceback.tb_lineno
    print("\npsycopg2 ERROR:", err, "on line number:", line_num)
    print("psycopg2 traceback:", traceback, "-- type:", err_type)
    print("\nextensions.Diagnostics:", err.diag)
    print("pgerror:", err.pgerror)
    print("pgcode:", err.pgcode, "\n")


def get_salt_from_db(username):
    try:
        conn, cur = getcon()
       ''' Query below selects the salt from the user table based on the given username.
       Using min means 1 row will be sent back even if there is no salt to return (it will send back a row saying null)
        This keeps the time exactly the same whether there is salt or not and stops errors later on. 
        Coalesce makes it return 1 instead of NULL which stops erros in login process.'''
        cur.execute(
            "SELECT coalesce(min(salt),'1') FROM tr_users WHERE username = %s;", [username])
        
        return cur.fetchone()[0]
    except Exception as e:
        error_handler(e)


def get_password_from_db(username):
 '''returns the password saved in the db based on given username'''
    try:
        conn, cur = getcon()
        cur.execute(
            "SELECT password FROM tr_users WHERE username = %s", [username])
        password = cur.fetchone()
        return password
    except Exception as e:
        print(e)


def session_auth(cookies):
'''used to manage sessions'''
    session = cookies.get('sessionID')
    ''' if there is a session ID in the cookie'''
    if (session):
        conn, cur = getcon()
        ''' checks that session exists in database and is therefore valid'''
        cur.execute("SELECT sid FROM tr_session WHERE sid = %s", [session])
        resp = cur.fetchone()
        conn.commit()
        if (resp):
            '''checks that session has not expired'''
            cur.execute(
                "SELECT expires FROM tr_session WHERE sid = %s", [session])
            conn.commit()
            expires = cur.fetchone()[0]
            if datetime.datetime.now() < expires:
                '''checks if user is logged in by seeing if username = NULL or not'''
                cur.execute(
                    "SELECT username FROM tr_session WHERE sid = %s", [session])
                username = cur.fetchone()[0]
                if username != 'NULL':
                    return True
                else:
                    return False
            else:
                '''if session has expired it is deleted from db'''
                cur.execute("DELETE FROM %s WHERE sid=%s",
                            [AsIs('tr_session'), session])
                conn.commit()
                return False
        else:
            '''if session does not exist  in db'''
            print('session not valid')
            return False
    else:
        '''if there is no session in the cookie'''
        return False


def session_auth_not_loggedin(cookies):
'''used to manage sessions before user logs in'''
    session = cookies.get('sessionID')
    if (session):
        conn, cur = getcon()

        cur.execute("SELECT sid FROM tr_session WHERE sid = %s", [session])
        resp = cur.fetchone()
        conn.commit()
        if (resp):
            return True
        else:
            return False
    else:
        return False

def session_r_auth_not_loggedin(cookies):
'''used to manage sessions for account recovery pages'''
    session = cookies.get('r_sessionID')
    if (session):
        conn, cur = getcon()

        cur.execute("SELECT r_sid FROM tr_r_session WHERE r_sid = %s", [session])
        resp = cur.fetchone()
        conn.commit()
        if (resp):
            return True
        else:
            return False
    else:
        return False

def get_username_from_session(sessionID):
'''selects username based on given sessionID'''
    conn, cur = getcon()
    cur.execute("SELECT username FROM tr_session WHERE sid = %s", [sessionID])
    user = cur.fetchone()
    conn.commit()
    if (user):
        return user[0]
    else:
        return 'No user'

def get_username_from_r_session(r_sessionID):

'''gets username based on account recovery page session ID'''
    conn, cur = getcon()

    cur.execute("SELECT username FROM tr_r_session WHERE r_sid = %s", [r_sessionID])
    user = cur.fetchone()
    conn.commit()
    if (user):
        return user[0]
    else:
        return 'No user'

def insert_post(post_info):
'''insets post content into db, escaping it first'''
    title, country, author, content, date = post_info['title'], post_info[
        'country'], post_info['author'], post_info['content'], post_info['date'],
    title = escape(title)
    country = escape(country)
    content = escape(content)
    conn, cur = getcon()

    cur.execute("INSERT INTO tr_post (title, country, author, content, date) VALUES (%s,%s,%s,%s,%s)", [
                title, country, author, content, date])
    conn.commit()

def fetch_all_posts():

'''retrieves all posts from the db to display on the page, ordering them by date'''
    conn, cur = getcon()

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

'''selects all IP addresses from the banned ip address table'''
    conn, cur = getcon()

    cur.execute(
        "SELECT DISTINCT ip_address FROM ip_ban WHERE date >= now() - INTERVAL '30 minute'")
    resp = cur.fetchall()
    return resp

def insert_into_ip_ban(username, ip):

'inserts a user into the banned ip address table'''
    conn, cur = getcon()

    cur.execute("INSERT INTO ip_ban (ip_address,username,date) VALUES (%s,%s,NOW())", [
                ip, username])
    conn.commit()
    conn.close()

def ip_ban_or_no_ip_ban(ip):

'''checks if an IP address is banned or not'''
    conn, cur = getcon()

    cur.execute(
        "SELECT COUNT(*) FROM ip_ban WHERE ip_address = %s AND date >= now() - INTERVAL '30 minute'", [ip])
    resp = cur.fetchone()[0]
    if resp > 100:
        return True
    else:
        return False


def fetch_most_recent_user_posts(username):

'''sleects all posts from a given user and orders them by date'''
    conn, cur = getcon()

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
    conn, cur = getcon()
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
'''selects the 5 countries with the most posts'''
    conn, cur = getcon()
    cur.execute(
        "SELECT country FROM %s GROUP BY country ORDER BY COUNT(*) DESC LIMIT 5", [AsIs('tr_post')])
    conn.commit()
    resp = cur.fetchall()
    five_most_pop_string = " ".join([i[0] for i in resp])
    countries = five_most_pop_string.split()
    return countries


def get_user_information(sessionID):

 '''selects user informaiton based on the sessionID'''
    conn, cur = getcon()

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

''' confirms if a given user has been locked out or not'''
    conn, cur = getcon()

    cur.execute(
        "SELECT COUNT(*) FROM tr_lockout WHERE username = %s AND date >= now() - INTERVAL '1 minute'", [username])
    resp = cur.fetchone()[0]
    print(resp)
    if resp > 3:
        return True
    else:
        return False


def username_right_password_wrong(username, password):

'''checks if username exists, then if password given is correct'''
    conn, cur = getcon()

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

''' gets csrf token for given session'''
    conn, cur = getcon()

    cur.execute("SELECT csrf FROM tr_session WHERE sid = %s", [sessionID])
    csrf_token = cur.fetchone()[0]
    return csrf_token

def get_r_csrf_token(r_sessionID):

    ''' gets csrf token for given session for account recovery page'''
    conn, cur = getcon()

    cur.execute("SELECT csrf FROM tr_r_session WHERE r_sid = %s", [r_sessionID])
    csrf_token = cur.fetchone()[0]
    return csrf_token

def get_username_from_pid(pid):

'''gets username for a given post ID'''
    conn, cur = getcon()

    cur.execute("SELECT author FROM tr_post WHERE pid = %s", [pid])
    conn.commit()
    username = cur.fetchone()
    return username[0] if username != None else None


def is_admin(username):

'''checks if a user has admin rights or not based on username'''
    conn, cur = getcon()

    cur.execute(
        "SELECT COUNT(*) FROM tr_users WHERE username = %s AND admin = 'true'", [username])
    res = cur.fetchone()
    return res[0]


def session_is_admin(cookies):
 '''checks if there is a session or not then is a user is admin or not'''
    sessionID = cookies.get('sessionID')
    if (sessionID):
        conn, cur = getcon()

        username = get_username_from_session(sessionID)
        if (username and is_admin(username)):
            return True
    else:
        return False


@app.errorhandler(404)
def page_not_found(e):
   '''note that we set the 404 status explicitly'''
    return render_template('notfound.html'), 404


@app.route('/notfound')
def error_test():
    abort(404)


def fetch_all_countries():

 '''selects all countries that have a post written about them'''
    conn, cur = getcon()
    cur.execute("SELECT DISTINCT(country) FROM tr_post ORDER BY country")

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
    '''if there is a session'''
        sessionID = request.cookies.get('sessionID')
        csrf_token = createRandomId()
        conn, cur = getcon()

        ''' send csrf token to db for given session'''

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
    ''' if there is a valid session, compare csrf token recieved in form to the one saved in the db for given session'''
        sessionID = request.cookies.get('sessionID')
        user_csrf_token = get_csrf_token(sessionID)
        csrf_token_received = request.form['csrf_token'].strip('/')
        if user_csrf_token == csrf_token_received:
            user_session = request.cookies.get('sessionID')
            # Useful data that can be accessed from the request object. Data sent as JSON for testing purposes
            input_data = {


                'title': delete_tags(str(request.form['post-title'])),
                'country': str(request.form.get('country')),
                'content': delete_tags(str(request.form['post-content'])),
                'date': datetime.datetime.now()
            }
            print(input_data)

            '''In order to completed the input_data object with the missing data needed to
            insert the post, we can use the session to access the author of the post.'''

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
''' if there is a session, log user out. If not redirect to login page'''
    try:
        session = request.cookies['sessionID']
    except:
        return redirect(url_for('get_login'))

    if (session and request.method == 'GET'):

    ''' if there is a session, delete session from db and redirect user to homepage'''
        conn, cur = getcon()
        cur.execute("DELETE FROM %s WHERE sid=%s",
                    [AsIs('tr_session'), session])
        conn.commit()
        resp= make_response(redirect(url_for('home')))
        resp.set_cookie('sessionID', '', max_age= 0)
        return resp
    else:
        return redirect(url_for('get_login'))


@app.route('/home/<country>')
def return_counry_posts(country):
'''display posts for given country'''
    country = [word.capitalize() for word in escape(country).split('_')]
    session = session_auth(request.cookies)
    countries = fetch_five_most_pop()
    all_countries_with_posts = fetch_all_countries()
    conn, cur = getcon()
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


@app.route('/user/<username>')
def user_page(username):
'''display posts for given username'''
    session = session_auth(request.cookies)
    user_posts = fetch_most_recent_user_posts(escape(username))
    return render_template('userpage.html', posts=user_posts, len=len(user_posts))

@app.route('/profile')
def profile_page():
'''display user information based on username linked to given session id'''
    session = session_auth(request.cookies)
    if (session):
        sessionID = request.cookies.get('sessionID')
        private_user_information = get_user_information(sessionID)
        user_posts = fetch_most_recent_user_posts(
            private_user_information["username"])
        return render_template('profile.html', user_info=private_user_information, posts=user_posts, len=len(user_posts))
    else:
        return redirect(url_for('home'))


@app.route('/login')
def get_login():
    session_exists = session_auth_not_loggedin(request.cookies)
    if session_exists:
        sessionID = request.cookies.get('sessionID')
        username = get_username_from_session(sessionID)
        if username != 'NULL':
        ''' if there is a session and username does not equal 'NULL', redirect to homepage'''
            return redirect(url_for('home'))
        else:

            '''delete current session and create a new one with a csrf token'''
            conn, cur = getcon()
            cur.execute("DELETE FROM %s WHERE sid=%s", [
                        AsIs('tr_session'), sessionID])
            conn.commit()
            sessionID = createRandomId()
            csrf_token = createRandomId()
            expire = datetime.datetime.now() + datetime.timedelta(hours=0.5)
            sql = "INSERT into tr_session VALUES (%s, %s, %s, %s)"
            data = (sessionID, 'NULL', expire, csrf_token)
            conn, cur = getcon()
            cur.execute(sql, data)
            conn.commit()
            '''render login.html and send csrf token to form'''
            resp = make_response(render_template(
                'login.html', csrf_token=csrf_token))
            resp.set_cookie('sessionID', sessionID,samesite='Lax', httponly=True)
            return resp
    else:
    '''if no session exists yet, create one and add to db with csrf token'''
        sessionID = createRandomId()
        csrf_token = createRandomId()
        expire = datetime.datetime.now() + datetime.timedelta(hours=0.5)
        sql = "INSERT into tr_session VALUES (%s, %s, %s, %s)"
        data = (sessionID, 'NULL', expire, csrf_token,)
        conn, cur = getcon()
        cur.execute(sql, data)
        conn.commit()
        resp = make_response(render_template(
            'login.html', csrf_token=csrf_token))
        resp.set_cookie('sessionID', sessionID,samesite='Lax', httponly=True)
        return resp


@app.route('/login', methods=['POST'])
def post_login():
    '''get csrf token from form and check it against the one in the db for this session ID
     if match proceed, if not block.'''
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
            '''The count sends back 0 or 1 as a result, depending on whether the pw and username are correct'''
            sql = "SELECT count(*) from tr_users WHERE username =%s and password= %s"
            user_input_password = pw_hash_salt(
                data['password'], (get_salt_from_db(data['username'])))
            query_data = (data['username'], (user_input_password))
            conn, cur = getcon()

            cur.execute(sql, query_data)
            conn.commit()
            check_account = cur.fetchone()[0]

           '''checks IP address to see if it is banned or not'''
        
            print(request.environ.get('HTTP_X_REAL_IP', request.remote_addr))
            print(ip_ban_or_no_ip_ban(request.environ.get(
                'HTTP_X_REAL_IP', request.remote_addr)))
            if (ip_ban_or_no_ip_ban(request.environ.get('HTTP_X_REAL_IP', request.remote_addr))):
                return render_template('login.html', check_input='IP BANNED', csrf_token=csrf_token)
            
            '''if the pw entered is incorrect, uswrname and time added to lockout table'''
            if (username_right_password_wrong(data['username'], user_input_password)):
                cur.execute("INSERT INTO tr_lockout VALUES (%s, %s)", [
                            data['username'], datetime.datetime.now()])
                conn.commit()
                insert_into_ip_ban(data['username'], request.environ.get(
                    'HTTP_X_REAL_IP', request.remote_addr))
                
            '''if username is in lockout table, message is sent to user'''
            if (lockout_or_no_lockout(data['username'])):
                return render_template('login.html', check_input='Your account has been temporarily locked out', csrf_token=csrf_token)
            
            '''if there is a result, the pw and username were correct'''
            if check_account != 0:
                conn, cur = getcon()

                cur.execute("DELETE FROM %s WHERE sid=%s", [
                            AsIs('tr_session'), sessionID])
                conn.commit()
                cur.execute(search_path)
                cur.execute("""DELETE FROM %s WHERE username = %s""", [
                            AsIs('tr_session'), data['username']])
                '''new session is created for when user is logged in'''
                sessionID = createRandomId()
                cur.execute("""INSERT INTO %s VALUES(%s,%s,%s);""", [
                            AsIs('tr_session'), sessionID, data['username'], str(expire)])
                conn.commit()
                resp = make_response(redirect('/home'))
                resp.set_cookie('sessionID', sessionID,
                                samesite='Lax', httponly=True)
                return resp
            else:
                '''if the password was incorrect, username and IP address sent to db'''
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
            'firstname':  request.form['name'].lower().replace(" ", ""),
            'lastname': request.form['surname'].lower().replace(" ", ""),
            'username': request.form['username'].lower().replace(" ", ""),
            'email': request.form['email'].lower().replace(" ", ""),
            'dob': request.form['birthdate'],
            'password': request.form['password'].replace(" ", ""),
            'recovery_question': request.form['recovery-question'],
            'recovery_answer': request.form['recovery-answer'].replace(" ", ""),
            'salt': pw_salt(),
            'r_salt': pw_salt()
        }
        r_answer = user_sign_up['recovery_answer']
        '''first check user inputs are valid firstname, lastname, username, email and password'''
        check_input = input_validation(user_sign_up)
        if check_input == True:
           '''hash and salt password before sending it to database'''
            user_sign_up['password'] = pw_hash_salt(
                user_sign_up['password'], user_sign_up['salt'])
            user_sign_up['recovery_answer'] = pw_hash_salt(
                user_sign_up['recovery_answer'], user_sign_up['r_salt'])
            '''insert user details to database. It returns a message whether the user is successfully
           inserted or not'''
            return render_template('signup.html', name=user_sign_up['firstname'], surname=user_sign_up['lastname'],
                                   username=user_sign_up['username'], email=user_sign_up['email'],
                                   dob=user_sign_up['dob'], r_answer=r_answer,
                                   check_input=insert_user(user_sign_up))
        else:
            '''Give error message to user'''
            return render_template('signup.html',
                                   name=user_sign_up['firstname'], surname=user_sign_up['lastname'],
                                   username=user_sign_up['username'], email=user_sign_up['email'],
                                   dob=user_sign_up['dob'], r_answer=user_sign_up['recovery_answer'],
                                   check_input=check_input)


@app.route('/api/deletepost', methods=['POST'])
def delete_post():
    #session = session_auth(request.cookies)
    pid = request.json['pid']
   
    sessionID = request.cookies.get('sessionID')
    resp = make_response('unauthorised', 401)
    if (sessionID != None and session_auth(request.cookies)):
        username_from_session = get_username_from_session(sessionID)
        username_from_pid = get_username_from_pid(pid)
        
        '''Check that username from session is equal to username of the post, or if user is an admin user'''
        if (((username_from_session != None and username_from_pid != None) and (username_from_session == username_from_pid)) or (is_admin(get_username_from_session(sessionID)))):
            conn, cur = getcon()

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
    '''check there is a session ID and the user is admin, and user to delete is not admin username'''
    if sessionID and is_admin(get_username_from_session(sessionID)) and user_to_delete != 'tradmin':
        conn, cur = getcon()

        cur.execute("DELETE FROM tr_users WHERE username = %s",
                    [user_to_delete])
        conn.commit()
        return
    '''check if user requested to deactivate their account'''
    if user_to_delete == get_username_from_session(sessionID):
        conn, cur = getcon()

        cur.execute("DELETE FROM tr_users WHERE username = %s",
                    [user_to_delete])
        cur.execute("DELETE FROM tr_session WHERE username = %s", [user_to_delete])
        conn.commit()
        resp = make_response('success', 200)
        return resp
    else:
        resp = make_response('unsuccessful', 401)
        return resp


@app.route('/accountrecovery', methods=['GET'])
def get_account_recover():
    try:
        sessionID = request.cookies.get('sessionID')
        session = session_auth(request.cookies)
        if (session and sessionID):
            return redirect(url_for('home'))
        else:
            session_exists = session_r_auth_not_loggedin(request.cookies)
            print(session_exists)
            if session_exists:
            '''if there is a session, update csrf token for given sessionid and send token to form'''
                sessionID = request.cookies.get('r_sessionID')
                csrf_token = createRandomId()
                conn, cur = getcon()

                sql = "UPDATE tr_r_session SET csrf = %s WHERE r_sid= %s"
                data = (csrf_token, sessionID)
                cur.execute(sql, data)
                conn.commit()
                return render_template('accountrecovery.html', recovery_form=True, question_form=False, password_form=False, csrf_token= csrf_token)
            else:
                ''' if there is no session, create one'''
                r_sessionID = createRandomId()
                csrf_token = createRandomId()
                expire = datetime.datetime.now() + datetime.timedelta(hours=0.5)
                sql = "INSERT into tr_r_session VALUES (%s, %s, %s, %s)"
                data = (r_sessionID, 'NULL', expire, csrf_token,)
                conn, cur = getcon()
                cur.execute(sql, data)
                conn.commit()
                resp = make_response(render_template('accountrecovery.html', recovery_form=True, question_form=False, password_form=False, csrf_token= csrf_token))
                resp.set_cookie('r_sessionID', r_sessionID,samesite='Lax', httponly=True)
                return resp
    except Exception as e:
        error_handler(e)



@app.route('/recoveryquestion', methods=['POST'])
def post_account_recover():
    r_sessionID = request.cookies.get('r_sessionID')
    csrf_token = get_r_csrf_token(r_sessionID)
    account_recovery = {
        'email': escape_email(request.form['email'].lower()),
        'dob': escape(request.form['birthdate'])
    }
    ''' check details given by user match those in the db'''
    user_credentials = check_email_dob(account_recovery)
    if user_credentials:
    ''' if they do, set recovery question to the one they hose at sign-up'''
        recovery_question = user_credentials[0][0]
        username = user_credentials[0][1]
        ''' set username equal to the one provided for this session ID'''
        update_username_from_r_session(username, r_sessionID)
        return render_template('accountrecovery.html', recovery_form=False, password_form=True, recovery_question=recovery_question, csrf_token=csrf_token)
    else:
        return render_template('accountrecovery.html', recovery_form=True, check_input="Please, check your credentials again!",csrf_token=csrf_token)


@app.route('/changepassword', methods=['POST'])
def change_account_password():
    try:
        r_sessionID = request.cookies.get('r_sessionID')
        ''' get username for given session ID'''
        username = get_username_from_r_session(r_sessionID)
        '''if username = 'NULL', user has not yet signed up for an account, so redirect to homepage'''
        if username == 'NULL':
            return redirect(url_for('home'))
        else:
            user_csrf_token = request.form['csrf_token'].strip("/")
            r_sessionID = request.cookies.get('r_sessionID')
            csrf_token = get_r_csrf_token(r_sessionID)
            '''check csrf tokens match'''
            if csrf_token == user_csrf_token:
                user_change_password = {
                    'username': username,
                    'recovery-answer':  escape(request.form['recovery-answer']),
                    'new_password': request.form['password'],
                    'salt': pw_salt()
                }
                user_name = user_change_password['username']
                ''' check username given matches db'''
                user_credentials = check_username(user_name)
                if user_credentials:
                    recovery_answer = user_credentials[0][1]
                    recovery_answer_salt = user_credentials[0][2]
                    user_input_salted_answer = pw_hash_salt(
                        user_change_password['recovery-answer'], recovery_answer_salt)
                    '''check that new password is formatted correctly then if the answer given matches the answer in the db'''
                    if is_valid_password(user_credentials, user_change_password['new_password']):
                        if user_input_salted_answer == recovery_answer:
                            username = user_credentials[0][0]
                            salted_pw = pw_hash_salt(
                                user_change_password['new_password'], user_change_password['salt'])
                            ''' update password, delete session and redirect to login page'''
                            update_password(username, salted_pw, user_change_password['salt'])
                            delete_r_sessionID(r_sessionID)
                            return redirect('login')
                        else:
                            return render_template('accountrecovery.html', password_form=True, check_input="Please, check your answer again!",csrf_token=csrf_token)
                    else:
                        return render_template('accountrecovery.html', password_form=True, check_input="Please, enter a valid password!",csrf_token=csrf_token)
                else:
                    return render_template('accountrecovery.html', password_form=True, check_input="Please, check your username",csrf_token=csrf_token)
            else:
                    return render_template('accountrecovery.html', password_form=True,check_input='CSRF tokens do not match.',csrf_token=csrf_token)
    except:
        return render_template('accountrecovery.html', invalid_session = True)


def is_valid_password(user_data, password):
''' check password does not contain any part of name and has the correct format'''
    firstname = user_data[0][1]
    lastname = user_data[0][2]
    if (firstname.lower() in password.lower()) or (lastname.lower() in password.lower()):
        return False
    elif not bool(re.fullmatch('^(?=.{10,20})(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+*!=]).*$', password)):
        return False
    else:
        return True


def check_email_dob(account_recovery):
'''get recovery question and username for given email and dob'''
    conn, cur = getcon()
    sql = """SELECT recoveryquestion, username FROM tr_users WHERE email = %s and dob = %s;"""
    data = (account_recovery['email'], account_recovery['dob'])
    cur.execute(sql, data)
    conn.commit()
    res = cur.fetchall()
    return res


def check_username(user_name):
''' get recovery details for given username'''
    conn, cur = getcon()
    sql = """SELECT username, recoveryanswer, r_salt FROM tr_users WHERE username =  '%s' """ % user_name
    cur.execute(sql)
    conn.commit()
    res = cur.fetchall()
    return res


def update_password(username, password, salt):
 ''' update passowrd and salt for given username'''
    conn, cur = getcon()
    sql = """UPDATE tr_users SET (password, salt) = (%s, %s) WHERE username = %s """
    data = (password, salt, username)
    cur.execute(sql, data)
    conn.commit()

def update_username_from_r_session(username, r_sessionID):
'''update username for given session ID so it is no longer 'null' '''
    conn, cur = getcon()
    sql = """UPDATE tr_r_session SET username = %s WHERE r_sid = %s """
    data = (username, r_sessionID)
    cur.execute(sql, data)
    conn.commit()

def delete_r_sessionID(session):
''' delete session for recovery page'''
    conn, cur = getcon()
    cur.execute("DELETE FROM %s WHERE r_sid=%s",
                    [AsIs('tr_r_session'), session])
    conn.commit()


def fetch_users():
''' get user information from user table'''
    conn, cur = getcon()
    cur.execute("SELECT username, firstname, lastname, email FROM tr_users")
    conn.commit()
    res = cur.fetchall()
    return res


@app.route('/admin', methods=['GET'])
def admin_page():
    if (session_is_admin(request.cookies)):
    ''' if user has admin rights, list users, their posts and banned ip addresses'''
        list_of_users = fetch_users()
        user_posts = fetch_all_posts()
        banned_ips = fetch_banned_ip()
        return render_template('admin.html', users=list_of_users, posts=user_posts, banned_ips=banned_ips)
    else:
        return render_template('notfound.html')


@app.route('/api/wipeinactive', methods=['POST'])
def wipe_all():
    if(session_is_admin(request.cookies)):
    ''' if user has admin rights, delete users who havent posted in last 30 mins?? '''
        conn, cur = getcon()
        cur.execute("SELECT author FROM tr_post WHERE tr_post.date >= now() - INTERVAL '30 minutes'")
        users = cur.fetchall()
        cur.execute("DELETE FROM tr_users WHERE username IN (SELECT author FROM tr_post WHERE tr_post.date >= now() - INTERVAL '30 minutes')")
        conn.commit()
        resp = make_response('success', 200)
        data = list(set([user[0] for user in users]))
        print(data)
        return make_response(jsonify({'users': data}), 200)
    else:
        resp = make_response('unsuccessful', 401)
        return resp

@app.route('/api/unbanip', methods=['POST'])
def unban_ip():
    print('ran')
    sessionID = request.cookies.get('sessionID')
    ip_to_unban = request.json['ip']
    ''' if there is a session and user has admin rights, remove given ip address form the banned ip list'''
    if (sessionID and is_admin(get_username_from_session(sessionID))):
        conn, cur = getcon()

        cur.execute("DELETE FROM ip_ban WHERE ip_address = %s", [ip_to_unban])
        conn.commit()
        return
    else:
        return

def insert_user(data):
''' insert user details into database once they have been escaped. If username or email already in db, send message to user.'''
    try:
        conn, cur = getcon()
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
        return 'Username or email already exists! Please, try again.'


def input_validation(user_sign_up):
''' check user input meets expected format'''
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
    elif not bool(re.fullmatch('^[A-Za-z0-9_-]*$', user_sign_up['recovery_answer'])):
        return "Account recovery answer must include only letters and numbers."
    else:
        return True

def pw_salt():
'''create password salt'''
    random_digits = '''abcdeg_+]|,./;:>'''
    pw_salt = ''
    i = 0
    while i <= len(random_digits):
        random_digit = random.choice(random_digits)
        pw_salt += str(ord(random_digit))
        i = i+1
    return int(pw_salt)


def pw_hash_salt(unhashed_pw, pw_salt=0):
''' hash password then add salt'''
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
