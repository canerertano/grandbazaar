from flask import Flask, request, redirect, url_for, flash
from flask import jsonify, render_template, abort
from database_setup import Base, Item, Category, User
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from flask import session as login_session
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from flask import make_response
import random
import string
import json
import httplib2
import requests


engine = create_engine('sqlite:///itemcatalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

app = Flask(__name__)
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "GrandBazaar"


# csrf token control function
@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = login_session.pop('_csrf_token', None)

        request_token = ""
        if 'gconnect' in request.url:
            request_token = json.loads(request.data)['_csrf_token']
        else:
            request_token = request.form.get('_csrf_token')

        if not token or token != request_token:
            print "Cross-Site Request Forgery tokens doesn't match!"
            abort(403)


def generate_csrf_token():
    if '_csrf_token' not in login_session:
        login_session['_csrf_token'] = random_string()
    return login_session['_csrf_token']


def random_string():
    return ''.join(random.choice(string.ascii_uppercase + string.digits)
                   for x in xrange(32))


# Create anti-forgery state token
def generateNewState():
    state = random_string()
    login_session['state'] = state
    return state


# Google OAuth #
###############
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = json.loads(request.data)['data']
    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = "Success"
    return output

# User Helper Functions


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
        'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one_or_none()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
        # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        # Reset the user's sesson.
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']

        state = generateNewState()
        return redirect(url_for('allObjects'))
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


def getState():
    if login_session['state'] is None:
        return generateNewState()
    else:
        return login_session['state']

# APIs #
########


@app.route('/API/categories/')
def categoriesJSON():
    categories = session.query(Category).all()
    json = jsonify(categories=[i.serialize for i in categories])
    return json


@app.route('/API/categories/<int:category_id>/')
def categoryJSON(category_id):
    category = session.query(Category).filter_by(id=category_id).one_or_none()

    json = "No data found"
    if category != None:
        json = jsonify(item=category.serialize)
    return json


@app.route('/API/categories/<int:category_id>/items/')
def itemsOfACategoryJSON(category_id):
    items = session.query(Item).filter_by(category_id=category_id).all()
    json = jsonify(items=[i.serialize for i in items])
    return json


@app.route('/API/categories/<int:category_id>/items/<int:item_id>/')
def itemOfACategoryJSON(category_id, item_id):
    item = session.query(Item).filter_by(
        category_id=category_id, id=item_id).one_or_none()

    json = "No data found"
    if item != None:
        json = jsonify(item=item.serialize)
    return json


@app.route('/API/items/')
def itemsJSON():
    items = session.query(Item).all()
    json = jsonify(items=[i.serialize for i in items])
    return json


@app.route('/API/items/<int:id>/')
def itemJSON(id):
    item = session.query(Item).filter_by(id=id).one_or_none()

    json = "No data found"
    if item != None:
        json = jsonify(item=item.serialize)
    return json


## Views ##
###########


# This method returns all categories and items
@app.route('/')
def allObjects():
    state = getState()
    user = None
    if login_session.get('user_id') is not None:
        user = getUserInfo(login_session['user_id'])

    categories = session.query(Category)
    items = session.query(Item)

    return render_template('index.html', STATE=state, user=user, categories=categories, givenCategory=None, items=items)


# This method returns categories, selected category and items of selected
# category
@app.route('/categories/<int:category_id>/')
@app.route('/categories/<int:category_id>/items/')
def itemsForGivenCategory(category_id):
    state = getState()

    user = None
    if login_session.get('user_id') is not None:
        user = getUserInfo(login_session['user_id'])

    categories = session.query(Category)
    givenCategory = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(category_id=givenCategory.id)

    return render_template('index.html', STATE=state, user=user, categories=categories, givenCategory=givenCategory, items=items)


# This method adds new category to database
@app.route('/categories/addCategory/', methods=['POST'])
def addCategory():
    if request.method == 'POST':
        name = request.form['category']
        user = getUserInfo(login_session['user_id'])
        category = Category(name=name, owner_id=user.id, owner=user)
        session.add(category)
        session.commit()
        redirect_url = "/categories/%s/" % category.id
        return redirect(redirect_url, code=302)


# This method updates given category's information in database
@app.route('/categories/<int:category_id>/edit/', methods=['POST'])
def editCategory(category_id):
    if request.method == 'POST':
        category = session.query(Category).filter_by(
            id=category_id).one_or_none()
        user = getUserInfo(login_session['user_id'])
        if category is not None:
            if (user is not None) and (user.id == category.owner_id):
                category.name = request.form['categoryName']
                session.add(category)
                session.commit()

                redirect_url = "/categories/%s/" % category.id
                return redirect(redirect_url, code=302)
            else:
                flash("You are not authorized to edit this category!", "danger")
                redirect_url = "/categories/%s/" % category.id
                return redirect(redirect_url, code=302)
        else:
            flash("Couldn't find a category for given id", "warning")
            redirect_url = url_for('allObjects')
            return redirect(redirect_url, code=302)


# This method deletes the given category from database
@app.route('/categories/<int:category_id>/delete/', methods=['POST'])
def deleteSelectedCategory(category_id):
    if request.method == 'POST':
        category = session.query(Category).filter_by(
            id=category_id).one_or_none()
        user = getUserInfo(login_session['user_id'])
        if category is not None:
            if (user is not None) and (user.id == category.owner_id):
                items = session.query(Item).filter_by(category_id=category.id)

                for item in items:
                    session.delete(item)

                session.delete(category)
                session.commit()

                redirect_url = url_for('allObjects')
                return redirect(redirect_url, code=302)
            else:
                flash("You are not authorized to delete this category!", "danger")
                redirect_url = "/categories/%s/" % category.id
                return redirect(redirect_url, code=302)
        else:
            flash("Couldn't find a category for given id", "warning")
            redirect_url = url_for('allObjects')
            return redirect(redirect_url, code=302)


# This method returns requested item if the http method is GET and updates
# information of the item if the http method is POST
@app.route('/categories/<int:category_id>/items/<int:item_id>/', methods=['GET', 'POST'])
def selectedItem(category_id, item_id):
    if request.method == 'GET':
        state = getState()
        user = None
        if login_session.get('user_id') is not None:
            user = getUserInfo(login_session['user_id'])

        item = session.query(Item).filter_by(id=item_id).one()

        return render_template('item.html', STATE=state, user=user, item=item)

    if request.method == 'POST':
        item = session.query(Item).filter_by(id=item_id).one_or_none()
        user = getUserInfo(login_session['user_id'])
        if item is not None:
            if (user is not None) and (user.id == item.owner_id):
                item.name = request.form['itemName']
                item.description = request.form['itemDesc']
                item.picture = request.form['itemPic']

                session.add(item)
                session.commit()
                return render_template('item.html', user=user, item=item)
            else:
                flash("You are not authorized to edit this item!", "danger")
                redirect_url = "/categories/%s/items/%s/" % (
                    category_id, item_id)
                return redirect(redirect_url, code=302)
        else:
            flash("Couldn't find a item for given id", "warning")
            redirect_url = "/categories/%s/" % category_id
            return redirect(redirect_url, code=302)


# This method add item with given information about the item to database
@app.route('/categories/<int:category_id>/addItem/', methods=['POST'])
def addItem(category_id):
    if request.method == 'POST':
        category = session.query(Category).filter_by(id=category_id).one()
        if category is not None:
            print "dsfsdfsd"
            name = request.form['itemName']
            desc = request.form['itemDesc']
            pic = request.form['itemPic']
            user = getUserInfo(login_session['user_id'])
            item = Item(name=name, category_id=category_id, description=desc, picture=pic,
                        category=category, owner_id=user.id, owner=user)
            session.add(item)
            session.commit()
        redirect_url = "/categories/%s" % category.id
        return redirect(redirect_url, code=302)


# This method deletes given item from database
@app.route('/categories/<int:category_id>/items/<int:item_id>/delete/', methods=['POST'])
def deleteSelectedItem(category_id, item_id):
    if request.method == 'POST':
        item = session.query(Item).filter_by(id=item_id).one_or_none()
        user = getUserInfo(login_session['user_id'])
        if item is not None:
            if (user is not None) and (user.id == item.owner_id):
                session.delete(item)
                session.commit()

                redirect_url = "/categories/%s/" % category_id
                return redirect(redirect_url, code=302)
            else:
                flash("You are not authorized to delete this item!", "danger")
                redirect_url = "/categories/%s/items/%s/" % (
                    category_id, item_id)
                return redirect(redirect_url, code=302)
        else:
            flash("Couldn't find a item for given id", "warning")
            redirect_url = "/categories/%s/" % category_id
            return redirect(redirect_url, code=302)


if __name__ == '__main__':
    app.secret_key = '[K\xb7C\x95\xaa\xdd\xfa\n\xf0\x8fz\xc4\x92\xf6=\xac\xd9\xec\xfeW\xb6):'
    app.debug = True
    app.jinja_env.globals['csrf_token'] = generate_csrf_token
    app.run(host='0.0.0.0', port=8000)
