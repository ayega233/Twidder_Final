import sqlite3
from flask import g

DATABASE_URI = 'database.db'

def get_db():
    db = getattr(g, 'db', None)
    if db is None:
        db = g.db = sqlite3.connect(DATABASE_URI)
    return db

def disconnect_db():
    db = getattr(g, 'db', None)
    if db is not None:
        g.db.close()
        g.db = None

def sign_in(email, token):
    try:
        get_db().execute("insert into loggedinusers values(?,?);",[email,token])
        get_db().commit()
        return True
    except sqlite3.Error as er:
        print(er)
        return False

def get_loggedinuser(email):
    cursor = get_db().execute('select * from loggedinusers where email like ?', [email])
    rows = cursor.fetchall()
    cursor.close()
    result = []
    for index in range(len(rows)):
        result.append({'email': rows[index][0], 'token': rows[index][1]})
    return result

def get_contact(email):
    cursor = get_db().execute('select * from contact where email like ?', [email])
    #cursor = get_db().execute('select * from contact')
    rows = cursor.fetchall()
    cursor.close()
    result = []
    for index in range(len(rows)):
        result.append({'firstname': rows[index][0], 'familyname': rows[index][1],
                       'gender': rows[index][2], 'city': rows[index][3], 'country': rows[index][4],
                       'email': rows[index][5], 'password': rows[index][6]})
    return result

def sign_up(firstname, familyname, gender, city, country, email, password):
    try:
        get_db().execute("insert into contact values(?,?,?,?,?,?,?);",
        [firstname, familyname, gender, city, country, email, password])
        get_db().commit()
        return True
    except:
        return False

def sign_out(token):
    try:
        get_db().execute("delete from loggedinusers where token like ?", [token])
        get_db().commit()
        return True
    except sqlite3.Error as er:
        print("sign_out",er)
        return False

def get_old_password(email):
    cursor = get_db().execute('select * from contact where email like ?', [email])
    rows = cursor.fetchall()
    cursor.close()
    return rows[0][6]


def get_email_from_token(token):
    cursor = get_db().execute('select * from loggedinusers where token like ?', [token])
    rows = cursor.fetchall()
    cursor.close()
    return rows[0][0]

def check_token(token):
    a = get_db().execute('select * from loggedinusers where token like ?', [token]).fetchall()
    get_db().commit()
    if a:
        return True
    else:
        return False


def change_password(email,newPassword):
    try:
        get_db().execute("UPDATE contact SET password = ? WHERE email like ?", [newPassword, email])
        get_db().commit()
        return True
    except:
        return False

def get_user_data_by_email(email):
    cursor = get_db().execute('select * from contact where email like ?', [email])
    rows = cursor.fetchmany(size=6)
    cursor.close()
    result = []
    for index in range(len(rows)):
        result.append({'firstname': rows[index][0], 'familyname': rows[index][1],
                       'gender': rows[index][2], 'city': rows[index][3], 'country': rows[index][4],
                       'email': rows[index][5]})
    return result


def get_user_messages_by_email(email):
    cursor = get_db().execute('select * from wall_data where email like ?', [email])
    rows = cursor.fetchall()
    cursor.close()
    result = []
    for index in range(len(rows)):
        result.append({'email': rows[index][0], 'writer': rows[index][1], 'content': rows[index][2]})
    return result

def post_message(email, writer, content):
    try:
        get_db().execute("insert into wall_data values(?,?,?);", [email, writer, content])
        get_db().commit()
        return True
    except sqlite3.Error as er:
        print(er)
        return False

