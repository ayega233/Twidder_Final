from flask import Flask, render_template, request, jsonify
import database_helper
import json
import string
import random
import re
from flask_sock import Sock

app = Flask(__name__)
sock=Sock(app)
app.debug = True

clients = {}

@app.teardown_request
def after_request(exception):
    database_helper.disconnect_db()

@app.route('/')
def getHomePage():
    return render_template(
        "client.html"
    )

@sock.route('/check_login')
def check_login(sock):
    while True:
            data = sock.receive()
            print("check_login",data,clients)
            clients[data]=sock
            print("after check_login",data,clients)
            sock.send(data)


def randomToken(stringLength):
    lettersAndDigits = string.ascii_letters + string.digits
    return ''.join(random.choice(lettersAndDigits) for i in range(stringLength))

def email_validation(email):
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
    if(re.fullmatch(regex, email)):
        return True
    else:
        return False

#sing in function @websocket used to sign out from previouse login.
#post method 
#parameters username(email) and password
@app.route('/sign_in/', methods=['POST'])
def sign_in():
    data = request.get_json()
    if 'username' in data and data['username'] and email_validation(data['username']) and 'password' in data and data['password']:
        contact_data = database_helper.get_contact(data['username'])
        if(len(contact_data)>0):
            contact = contact_data[0]
            if(contact['password'] == data['password']):
                token = randomToken(30)
            else:
                return jsonify({"success": "false", "message": "invaliddata"}), 400

            logged_inuser=database_helper.get_loggedinuser(data['username'])
            print("sign_in logged_inuser",logged_inuser)
            if(len(logged_inuser)):
                old_token = logged_inuser[0]['token']
                print("sign_in old_token",old_token)
               
            #if(len(logged_inuser)>0):                
                #return jsonify({"success": "false", "message": "Already loggedin.!"}), 200
            #else:
                wb_socket=clients.get(data['username'])
                print("sign_in clients",clients)
                print("sign_in wb_socket",wb_socket)
               
                if(wb_socket is not None and len(clients)>0):                    
                    try:
                         wb_socket.close() 
                    except RuntimeError as err:
                        print("Connection is Closed",err)                                       
                                      
                    del clients[data['username']]
                    print("After RFemoving",clients)                    
                    database_helper.sign_out(old_token)
                else:
                    database_helper.sign_out(old_token)
                    #return jsonify({"success": "false", "message": "Already loggedin.!"}), 200

            result = database_helper.sign_in(contact["email"], token)
            for client in clients:
                wb_socket1=clients.get(client)
                if wb_socket1 is not None:
                    wb_socket1.send("1")

            print("After Login",result)
            if (result):                   
                return jsonify({"success": "true", "message": "Successfully signed in.", "data": token}), 200
            else:
                return jsonify({"success": "false", "message": "servererror"}), 500
        else:
             return jsonify({"success": "false", "message": "nosignup"}), 400
    else:
        return jsonify({"success": "false", "message": "invaliddata"}), 400


#sing up function @create new user using user details.
#post method 
#parameters username(emai),firstname,familyname,city,gender,country, password
@app.route('/sign_up', methods=['POST'])
def sign_up():
    data = request.get_json()
    if('email' in data and data['email'] and 1< len(data['email']) <= 30 and email_validation(data['email'])):
        user = database_helper.get_contact(data['email'])
        if(user):
            return jsonify({"success": "false", "message": "userexist"}), 409
        else:
            if 'firstname' in data and 'familyname' in data and 'gender' in data and 'city' in data and 'country' in data and 'email' in data and 'password' in data:
                if  data['firstname'] and 1< len(data['firstname']) <= 100 and data['familyname'] and 1< len(data['familyname']) <= 100 and data['gender'] and 1< len(data['gender']) <= 30 and data['city'] and 1< len(data['city']) <= 30 and data['country'] and 1< len(data['country']) <= 30 and  data['password'] and 5 <= len(data['password']) <= 30:
                    result = database_helper.sign_up(data['firstname'], data['familyname'],data['gender'],data['city'], data['country'], data['email'], data['password'])
                    if result == True:
                        return jsonify({"success": "true","message":"Successfully created a new user."}), 201
                    else:
                        return jsonify({"success": "false", "message": "servererror"}), 500
                else:
                    return jsonify({"success": "false", "message": "emptydata"}), 400
            else:
                return jsonify({"success": "false", "message": "emptydata"}), 400
    else:
        return jsonify({"success":"false","message":"invalidemail"}),400



#sing out using login user token.
#delete method 
@app.route('/sign_out/', methods=['DELETE'])
def sign_out():
    token = request.headers.get('Authorization')
    if token and database_helper.check_token(token):
        result = database_helper.sign_out(token)
        if result == True:
            for client in clients:
                wb_socketso=clients.get(client)
                if wb_socketso is not None:
                    wb_socketso.send("0")
            return jsonify({"success": "true","message":"Successfully signed out."}), 200
        else:
            return jsonify({"success": "false", "message": "servererror"}), 500
    else:
        return jsonify({"success": "false", "message": "tokennotexist"}), 401


@app.route('/change_password', methods=['PUT'])
def change_password():
    data = request.get_json()
    token=request.headers.get('Authorization')
    if token and 'oldpassword' in data and 'newpassword' in data:
        if database_helper.check_token(token):
            email = database_helper.get_email_from_token(token)
            old_password = database_helper.get_old_password(email)
            if email and data['oldpassword'] == old_password and data['newpassword'] and 5 <= len(data['newpassword']) <= 30:
                result = database_helper.change_password(email, data['newpassword'])
                if result == True:
                    return jsonify({"success": "true", "message": "Password changed!"}), 200
                else:
                    return jsonify({"success": "false", "message": "Something went wrong!"}), 500
            else:
                return jsonify({"success": "false", "message": "passwordnotmatch"}), 400
        else:
            return jsonify({"success": "false", "message": ""}), 401
    else:
        return jsonify({"success": "false", "message": "emptydata"}), 400


@app.route('/get_user_data_by_token', methods=['GET'])
def get_user_data_by_token():
    token = request.headers.get('Authorization')
    if token and database_helper.check_token(token):
        email = database_helper.get_email_from_token(token)
        if email:
            result = database_helper.get_user_data_by_email(email)
            if (len(result)>0):
                return jsonify({"success": "true", "message": "User data retrieved.", "data": result[0]}), 200
            else:
                return jsonify({"success": "false", "message": "Something went wrong!"}), 500
        else:
            return jsonify({"success": "false", "message": "emailnotfound"}), 400
    else:
        return jsonify({"success": "false", "message": ""}), 401


@app.route('/get_user_data_by_email/<email>', methods=['GET'])
def get_user_data_by_email(email):
    token = request.headers.get('Authorization')
    if token and database_helper.check_token(token):
        if(email is not None and email_validation(email)):
            database_helper.addviews(email)
            result = database_helper.get_user_data_by_email(email)
            if email in clients:
                websockserch=clients[email]
                websockserch.send("searched")
            if (len(result)>0):
                return jsonify({"success": "true", "message": "User data retrieved.", "data": result[0]}), 200
            elif (len(result)==0):
                return jsonify({"success": "false", "message": "nouserfound", "data": result}), 400
            else:
                return jsonify({"success": "false", "message": "Not registered user found.!"}), 500
        else:
            return jsonify({"success": "false", "message": "emailnotfound"}), 400
    else:
        return jsonify({"success": "false", "message": ""}), 401


@app.route('/get_user_messages_by_token', methods=['GET'])
def Get_user_messages_by_token():
    token = request.headers.get('Authorization')
    if token and database_helper.check_token(token):
        email = database_helper.get_email_from_token(token)
        if(email):
            result = database_helper.get_user_messages_by_email(email)
            #if result:
            return jsonify({"success": "true", "message": "User messages retrieved.", "data": result}), 200
            #else:
            #    return jsonify({"success": "false", "message": "Something went wrong!"}), 500
        else:
            return jsonify({"success": "false", "message": "emailnotfound"}), 400
    else:
        return jsonify({"success": "false", "message": ""}), 401


@app.route('/get_user_messages_by_email/<email>', methods=['GET'])
def get_user_messages_by_email(email):

    token = request.headers.get('Authorization')
    if token and database_helper.check_token(token):
        result = database_helper.get_user_messages_by_email(email)
        if (len(result)>0):
            return jsonify({"success": "true", "message": "User messages retrieved.", "data": result}), 200
        elif (len(result)==0):
            return jsonify({"success": "false", "message": "nomessages", "data": result}), 400
        else:
            return jsonify({"success": "false", "message": "Something went wrong!"}), 500
    else:
        return jsonify({"success": "false", "message": ""}), 401
    

@app.route('/post_message', methods=['POST'])
def post_message():
    data = request.get_json()
    token = request.headers.get('Authorization')
    if token and token is not None and database_helper.check_token(token):
        writer = database_helper.get_email_from_token(token)
        if writer:
            if('email' in data and data['email'] is not None):
                toemail = data['email']
            else:
                toemail=writer
            result = database_helper.get_user_data_by_email(toemail)        
            if (len(result)>0):
                if('message' in data and data['message'] is not None and len(data['message'])>0):
                    result = database_helper.post_message(toemail, writer, data['message'])
                    if result:
                        if toemail in clients:
                            websockpost = clients[toemail]
                            websockpost.send("wallpost")
                        return jsonify({"success": "true", "message": "Message sent.", "data": result}), 200
                    else:
                        return jsonify({"success": "false", "message": "Something went wrong!"}), 500
                else:
                    return jsonify({"success": "false", "message": "emptydata"}), 400
            else:
                return jsonify({"success": "false", "message": "nouserfound"}), 400
            #else:
               # return jsonify({"success": "false", "message": "Empty email!."}), 200                                                             
        else:
            return jsonify({"success": "false", "message": "nouserfound"}), 400
    else:
        return jsonify({"success": "false", "message": ""}), 401
    
@app.route('/get_profile_views',methods=['GET'])
def get_profile_views():
    token = request.headers.get('Authorization')
    if token and token is not None and database_helper.check_token(token):
        email=database_helper.get_email_from_token(token)
        result = database_helper.get_views_byemail(email) 
        if result:
            return jsonify({"success": "true", "message": "Message sent.", "data": result}), 200
        else:
            return jsonify({"success": "false", "message": "Something went wrong!"}), 500
    else:
        return jsonify({"success": "false", "message": ""}), 401
    
@app.route('/get_online_users',methods=['GET'])
def get_online_users():
    token = request.headers.get('Authorization')
    if token and token is not None and database_helper.check_token(token):
        result=database_helper.get_numberof_onlineusers() 
        print(result)
        if result:
            return jsonify({"success": "true", "message": "Message sent.", "data": result}), 200
        else:
            return jsonify({"success": "false", "message": "Something went wrong!"}), 500
    else:
        return jsonify({"success": "false", "message": ""}), 401
 
if __name__ == '__main__':
    app.run()