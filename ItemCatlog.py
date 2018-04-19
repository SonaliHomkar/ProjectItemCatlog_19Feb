""" import database and sqlalchemy for CRUD operations """
import re
import sys
import logging
import traceback
import hmac
import random
import hashlib
import os
from ItemCatlog_configPath import DBPATH, CLIENT_FILE
from string import ascii_letters, ascii_uppercase,  digits
from database_setup import Base, Category, Item, User
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from flask import session as login_session
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from flask import make_response
import httplib2
import json
import requests
from functools import wraps
from flask import Flask, render_template,  request,  redirect,  url_for, flash
from flask import jsonify
app = Flask(__name__)

CLIENT_ID = json.loads(
    open(CLIENT_FILE, 'r').read())['web']['client_id']

""" create session and connect to database """
engine = create_engine('sqlite:///' + DBPATH)
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
SECRET = 'imsosecret'
USERNAME = ""


""" these functions are used for password hashing and salt techniques """


def make_salt(length=5):
    return ''.join(random.choice(ascii_letters) for x in range(length))


def make_pw_hash(name,  pw,  salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256((name + pw + salt).encode('utf-8')).hexdigest()
    return '%s|%s' % (salt,  h)


def valid_pw(name,  password,  h):
    salt = h.split('|')[0]
    return h == make_pw_hash(name,  password,  salt)


def make_secure_val(val):
    return '%s|%s' % (val,  hmac.new(SECRET,  val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def checkUser(strName):
        """ This function is used to check if the user already exist """
        objUser = session.query(User).filter_by(userName=strName).one_or_none()
        return objUser


def validateUser(strName, strPassword):
    """This function is used to validate the user has entered
       required fields """
    if strName == "" or strPassword == "":
        return True


def set_secure_cookie(name,  val):
    """ This function creates cookie once user logs in """
    cookie_val = make_pw_hash(name,  val)
    app.response_class.set_cookie(self, UserId,  cookie_val, path="/")


def login_required(function):
    """This function works as wrapper class checkcookie class"""
    @wraps(function)
    def wrapper(*args, **kwargs):
        if login_session.get('username'):
            return function(*args, **kwargs)
        else:
            flash('A user must be logged to add a new item.')
            return redirect(url_for('loginUser'))
    return wrapper


def validateCategory(strCategory):
    """ This function is used to validate category """
    if strCategory != "":
        return True


def validateItem(itemName):
    """ This function is used to validate items """
    if itemName != "":
        return True


@app.route('/login',  methods=['GET', 'POST'])
def loginUser():
        """ This function displays the login page """
        if request.method == 'POST':
                error = ""
                params = dict(error=error)
                invalidUser = validateUser(request.form['txtName'],
                                           request.form['txtpassword'])

                if invalidUser:
                    params['error'] = "Please enter User name or password"
                    return render_template('loginUser.html', **params)

                objUser = checkUser(request.form['txtName'])

                if objUser:
                    hashstr = valid_pw(request.form['txtName'],
                                       request.form['txtpassword'],
                                       objUser.userPassword)
                    if hashstr:
                            red_to_index = redirect(url_for('showCategory'))
                            response = app.make_response(red_to_index)
                            cookie_val = request.form['txtName']
                            response.set_cookie("UserId", cookie_val)
                            login_session['provider'] = "app"
                            login_session['username'] = request.form['txtName']
                            return response
                    else:
                        params['error'] = "Incorrect password please \
                                            enter again!!"
                        return render_template('loginUser.html', **params)
                else:
                        params['error'] = "User id does not exist..\
                                        please sign up for new user!!"
                        return render_template('loginUser.html', **params)
        else:
            state = ''.join(random.choice(ascii_uppercase + digits)
                            for x in range(32))
            login_session['state'] = state
            return render_template('loginUser.html', STATE=state)


@app.route('/showUsers',  methods=['GET', 'POST'])
@login_required
def showUser():
        """ This function displays the all users """
        objUsers = session.query(User).all()
        return render_template('showUsers.html', objUsers=objUsers)


@app.route('/getCategory/<int:cat_id>',  methods=['GET', 'POST'])
@login_required
def getCategory(cat_id):
    """ This function retrieves items for selected category """
    items = session.query(Item).filter_by(category_id=cat_id).all()
    return jsonify(items=[i.serialize for i in items])


@app.route('/userSignUp',  methods=['GET', 'POST'])
def usersSignUp():
    """ This function displays the User sign up page """
    if request.method == 'POST':
        strname = request.form['txtName']
        strpassword = request.form['txtpassword']
        strvarpassword = request.form['txtrepassword']
        stremail = request.form['txtemail']

        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        PWD_RE = re.compile(r"^.{3,20}$")
        EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
        have_error = False
        params = dict(strname=strname, strpassword=strpassword,
                      strvarpassword=strvarpassword, stremail=stremail)

        if not (strname and USER_RE.match(strname)):
            params['msg'] = "That's not a valid user name.."
            have_error = True
        if not (strname and PWD_RE.match(strpassword)):
            params['pwdmsg'] = "That's not a valid password"
            have_error = True
        if strpassword != strvarpassword:
            params['varmsg'] = "verify password do not match"
            have_error = True
        if stremail != "" and not EMAIL_RE.match(stremail):
            params['emailmsg'] = "That's not a valid email"
            have_error = True
        if have_error:
            return render_template("UserSignUp.html", **params)
        else:
            if(checkUser(strname)):
                params['error'] = "User already exist"
                return render_template("UserSignUp.html", **params)
            else:
                newUser = User(
                                userName=strname,
                                userPassword=make_pw_hash(
                                                strname, strpassword),
                                userEmail=stremail
                                )
                session.add(newUser)
                session.commit()
                flash("New user created!!!")
                return redirect(url_for('loginUser'))
    else:
        return render_template('UserSignUp.html')


@app.route('/logout')
def logout():
    """ This function logs out user from the system and displays login page """
    try:
        redirect_to_index = redirect(url_for('loginUser'))
        response = app.make_response(redirect_to_index)

        if login_session['provider'] == "google":
            gdisconnect()
        else:
            del login_session['provider']
            del login_session['username']
        flash("You have been successfully logged out!!")
        return response
    except:
        e = sys.exc_info()[1]
        return "error : " + str(e)


@app.route('/')
@login_required
def showCategory():
        """ This function displays the home page with categories and newly """
        """ added categories."""
        category = session.query(Category).all()
        items = session.query(Item).order_by(Item.id.desc()).limit(8).all()
        return render_template(
                'category.html', category=category, items=items,
                username=login_session['username'])


@app.route('/ItemCatlog/<int:cat_id>/')
@login_required
def getItems(cat_id):
        """ This function prints the Items of provided category
             in JSON format """
        items = session.query(Item).filter_by(category_id=cat_id).all()
        return jsonify(items=[i.serialize for i in items])


@app.route('/ItemCatlog/newCategory/',  methods=['GET', 'POST'])
@login_required
def newCategory():
        """ This function adds a new category to the database """
        if request.method == 'POST':
            if validateCategory(request.form['category']):
                newItem = Category(catName=request.form['category'],
                                   userName=request.cookies.get("UserId"))
                session.add(newItem)
                session.commit()
                flash("New Category created!!!")
                return redirect(url_for('showCategory'))
            else:
                error = "Please enter Category"
                return render_template('newCategory.html', error=error)
        else:
            return render_template('newCategory.html')


@app.route('/ItemCatlog/<int:cat_id>/edit/',  methods=['GET', 'POST'])
@login_required
def editCategory(cat_id):
        """ This function updates selected category """
        editedItem = session.query(Category).filter_by(id=cat_id).one()
        if editedItem.userName != login_session['username']:
            flash("You are not authorized to edit this category. "
                  "Please create your own category to edit it")
            return redirect(url_for('showCategory'))
        if request.method == 'POST':
            if validateCategory(request.form['category']):
                editedItem.catName = request.form['category']
                editedItem.userName = request.cookies.get("UserId")
                session.add(editedItem)
                session.commit()
                flash("Category edited!!!")
                return redirect(url_for('showCategory'))
            else:
                error = "Please enter Category!!"
                return render_template('editCategory.html', error=error,
                                       cat_id=cat_id, i=editedItem)
        else:
            return render_template('editCategory.html', cat_id=cat_id,
                                   i=editedItem)


@app.route('/ItemCatlog/<int:cat_id>/delete/',  methods=['GET', 'POST'])
@login_required
def deleteCategory(cat_id):
        """ This function deletes category """
        deletedItem = session.query(Category).filter_by(id=cat_id).one()
        if deletedItem.userName != login_session['username']:
            flash("You are not authorized to delete this category. "
                  "Please create your own category to delete it")
            return redirect(url_for('showCategory'))
        if request.method == 'POST':
            session.delete(deletedItem)
            session.commit()
            flash("Category Deleted!!!")
            return redirect(url_for('showCategory'))
        else:
            return render_template('deleteCategory.html', cat_id=cat_id,
                                   i=deletedItem)


@app.route('/ItemCatlog/addItem/',  methods=['GET', 'POST'])
@login_required
def addItem():
    """ This function adds new Item to the category """
    if request.method == 'POST':
        if validateItem(request.form['itemName']):
            newItem = Item(itemName=request.form['itemName'],
                           description=request.form['description'],
                           userName=login_session['username'],
                           category_id=request.form['ddlCategory'])
            session.add(newItem)
            session.commit()
            flash("New Item created!!")
            return redirect(url_for('showCategory'))
        else:
            error = "Please enter Item Title!!"
            category = session.query(Category).all()
            return render_template('addNewItem.html', error=error,
                                   categories=category)
    else:
            category = session.query(Category).all()
            return render_template('addNewItem.html', categories=category)


@app.route('/ItemCatlog/<int:cat_id>/displayItem/',  methods=['GET', 'POST'])
@login_required
def displayItem(cat_id):
    """ This function displays category details """
    Author = False
    category = session.query(Category).all()
    items = session.query(Item).filter_by(category_id=cat_id).all()
    return render_template('category.html', category=category,
                           items=items, Author=Author)


@app.route('/ItemCatlog/<int:item_id>/displayItemDetail/',
           methods=['GET', 'POST'])
@login_required
def displayItemDetails(item_id):
    """ This function displays item details """
    Author = False
    items = session.query(Item.id, Item.description,
                          Item.itemName,
                          Category.catName,
                          Item.userName).join(
                              Category,
                              Category.id == Item.category_id).filter(
                                  Item.id == item_id).all()
    if(login_session['username'] == items[0].userName):
        Author = True
    return render_template('itemDetails.html', items=items, Author=Author)


@app.route('/ItemCatlog/<int:item_id>/EditItem/',
           methods=['GET', 'POST'])
@login_required
def editItemDetails(item_id):
    """ This function is intended for editing items """
    if request.method == 'POST':
        if validateItem(request.form['itemName']):
            editedItem = session.query(Item).filter_by(id=item_id).one()
            editedItem.itemName = request.form['itemName']
            editedItem.description = request.form['description']
            editedItem.category_id = request.form['ddlCategory']
            session.add(editedItem)
            session.commit()
            flash("Item edited!!")
            return redirect(url_for('showCategory'))
        else:
            error = "Please enter Item !!"
            category = session.query(Category).all()
            items = session.query(Item.id, Item.description,
                                  Item.itemName, Category.catName,
                                  Item.category_id, Item.userName).join(
                                  Category, Category.id == Item.category_id
                                  ).filter(Item.id == item_id).all()
            return render_template(
                    'editItemDetails.html', items=items,
                    category=category, error=error)
    else:
        category = session.query(Category).all()
        items = session.query(Item.id, Item.description,
                              Item.itemName, Category.catName,
                              Item.category_id, Item.userName).join(
                                  Category, Category.id == Item.category_id
                                  ).filter(Item.id == item_id).all()
        if items[0].userName != login_session['username']:
            flash("You are not allowed to edit this item. "
                  "Please enter your own item to edit it.")
            return redirect(url_for('showCategory'))
        return render_template(
                    'editItemDetails.html', items=items, category=category)


@app.route('/ItemCatlog/<int:item_id>/DeleteItem/',  methods=['GET', 'POST'])
@login_required
def DeleteItem(item_id):
    """ This function deletes item for provided item id """
    deletedItem = session.query(Item).filter_by(id=item_id).one()
    if request.method == 'POST':
        session.delete(deletedItem)
        session.commit()
        flash("Item Deleted!!")
        return redirect(url_for('showCategory'))
    else:
        if deletedItem.userName != login_session['username']:
            flash("You are not allowed to delete this item. "
                  "Please enter your own item to delete it.")
            return redirect(url_for('showCategory'))
        return render_template('DeleteItem.html')


@app.route('/ItemCatlog/JSON')
@login_required
def categoryJason():
    """ Making an API endpoint(get request) to get all categories
        with their list of items """
    catlist = []
    jsonstr = ""
    category = session.query(Category).all()
    for j in category:
        items = session.query(Item).filter_by(category_id=j.id).all()
        itemlist = []
        for i in items:
            itemlist.append(i.serialize)
        idict = {"id": j.id, "Name": j.catName, "items": itemlist}
        catlist.append(idict)
    return jsonify({"categories": catlist})


@app.route('/ItemCatlog/Catlist')
@login_required
def categoryListJason():
    """ Making an API endpoint(get request) to get all categories """
    catlist = []
    jsonstr = ""
    category = session.query(Category).all()
    return jsonify(categories=[i.serialize for i in category])


@app.route('/ItemCatlog/<int:cat_id>/CatItems/')
@login_required
def categoryItemJason(cat_id):
    """ Making an API endpoint(get request) to get items
        for a given category """
    items = session.query(Item).filter_by(category_id=cat_id).all()
    return jsonify(Items=[i.serialize for i in items])


@app.route('/ItemCatlog/<int:item_id>/Items/')
@login_required
def ItemJason(item_id):
    """ Making an API endpoint(get request) to get information
        for a given item """
    items = session.query(Item).filter_by(id=item_id).all()
    return jsonify(Items=[i.serialize for i in items])


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """ a method to call the google server to run the api """
    if request.method == 'POST':
        """ Validate state token """
        if request.args.get('state') != login_session['state']:
            response = make_response(json.dumps
                                     ('Invalid state parameter'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response
        """ Obtain authorization code """
        code = request.data
        try:
            strScope = 'https://www.googleapis.com/auth/gmail.readonly'
            oauth_flow = flow_from_clientsecrets('client_secrets.json',
                                                 scope=strScope)
            oauth_flow.redirect_uri = 'postmessage'
            credentials = oauth_flow.step2_exchange(code)
        except FlowExchangeError:
            response = make_response(json.dumps('Failed to upgrade' +
                                                'the authorization code'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        """ check that access token is valid """
        try:
            strUrl = "https://www.googleapis.com/oauth2/v1" \
                     "/tokeninfo?access_token=%s"
            access_token = credentials.access_token
            url = (strUrl % access_token)
            h = httplib2.Http()
            result = json.loads(h.request(url, 'GET')[1])
            """ If there was an error in the access token info,  abort."""
            if result.get('error') is not None:
                response = make_response(json.dumps(result.get('error')), 501)
                response.headers['Content-Type'] = 'application/json'
                return response
            """ Verify that the access token is used for the intended user."""
            gplus_id = credentials.id_token['sub']
            if result['user_id'] != gplus_id:
                    response = make_response(json.dumps("Token's user id" +
                                                        "doesn't match given" +
                                                        "user id"),  401)
                    response.headers['Content-Type'] = 'application/json'
                    return response
            """Verify that the access token is valid for this app."""
            if result['issued_to'] != CLIENT_ID:
                    response = make_response(json.dumps("Token's clinet id" +
                                                        "doesn't match " +
                                                        "app's id"), 401)
                    print ("Token's id doesn't match app's id")
                    response.headers['Content-Type'] = 'application/json'
                    return response
            """check to see if the user is already logged in"""
            stored_access_token = login_session.get('access_token')
            stored_gplus_id = login_session.get('gplus_id')
            if stored_access_token is not None and gplus_id == stored_gplus_id:
                login_session['provider'] = "google"
                response = make_response(
                    json.dumps('Current user is already connected.'), 200)
                response.headers['Content-Type'] = 'application/json'
                return response
            """ Store the access token in the session for later use."""
            login_session['access_token'] = credentials.access_token
            login_session['gplus_id'] = gplus_id
            """ Get user info"""
            userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
            params = {'access_token': credentials.access_token,  'alt': 'json'}
            answer = requests.get(userinfo_url,  params=params)
            data = answer.json()
            login_session['provider'] = "google"
            login_session['username'] = data['name']
            login_session['picture'] = data['picture']
            login_session['email'] = data['email']
            user_id = getUserId(login_session['username'])
            if not user_id:
                user_id = createUser(login_session)
                strUser = "New User"
            else:
                strUser = ("User Already exist")

            login_session['user_id'] = user_id
            output = ''
            output += '<h1>Welcome,  '
            output += login_session['username']
            output += '!</h1>'
            output += '<img src="'
            output += login_session['picture']
            output += 'status : ' + strUser
            output += ' " style = "width: 300px; height: 300px; \
                    border-radius: 150px;-webkit-border-radius: 150px; \
                    -moz-border-radius: 150px;"> '
            flash("you are now logged in as %s" % login_session['username'])
            return output
        except:
            return traceback.print_exc()


@app.route("/gdisconnect")
def gdisconnect():
        """ This method calls google server to disconnect the user
            with google id """
        access_token = login_session.get('access_token')
        if access_token is None:
                response = make_response(json.dumps("Current user is already" +
                                                    "not connected"), 401)
                response.headers['Content-Type'] = 'application/json'
                return response
        strUrl = 'https://accounts.google.com/o/oauth2/revoke?token=%s'
        url = strUrl % login_session['access_token']
        h = httplib2.Http()
        result = h.request(url,  'GET')[0]
        if result['status'] == '200':
                del login_session['access_token']
                del login_session['gplus_id']
                del login_session['username']
                del login_session['picture']
                del login_session['email']
                response = make_response(
                    json.dumps('Successfully disconnected'), 200)
                response.headers['Content-Type'] = 'application/json'
                return response
        else:
                response = make_response(
                    json.dumps('Failed to revoke token for a given user'), 400)
                response.headers['Content-Type'] = 'application/json'
                return response


def createUser(login_session):
        """ This method creates a new user profile """
        newUser = User(userName=login_session['username'],
                       userEmail=login_session['email'])
        session.add(newUser)
        session.commit()
        user = session.query(User).filter_by(id=newUser.id).one()
        return user.id


def getUserId(username):
        """ This method gets the user Id for provided username """
        try:
            user = session.query(User).filter_by(userName=username).one()
            return user.userName
        except:
                return None


if __name__ == "__main__":
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0',  port=5500)
