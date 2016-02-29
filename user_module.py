import re
import os
import random
import hashlib
import hmac
import time
import datetime
from string import ascii_letters
import logging
from random import randint
from urllib import urlencode
from urllib import quote_plus
import urlparse

import oauth2 as oauth
from webapp2_extras import sessions
from google.appengine.api import memcache

from utils import *
from utils import PWHandlerPDKDF2
from handler import Handler
from user_database import User, ResetPasswordRequest, DeactAccounts
from article_database import Article, DeletdArticle

#IMPORTS SOCIAL LOGIN
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json


# --- USER SIGNUP - LOGNIN - LOGOUT ---

class SignupHandler(Handler):

    def get(self):
        if self.user:
            # Prompt user to log out.
            self.session.add_flash('message_signup_1', key='homepage_flashes')
            self.redirect("/")
        else:
            state = self.make_state()
            self.render('signup.html', state = state)

    def post(self):
        if self.user:
            # Prompt user to log out.
            self.session.add_flash('message_signup_1', key='homepage_flashes')
            self.redirect("/")
        else:
            if not self.check_state():
                self.redirect("/")
                return

            input_username = self.request.get('username')
            input_password = self.request.get('password')
            input_verify_password = self.request.get('verify_password')
            input_email = self.request.get('email').lower()
            input_verify_email = self.request.get('verify_email').lower()
            input_captcha = self.request.get('g-recaptcha-response')

            error_username=""
            error_password=""
            error_verify_password=""
            error_email=""
            error_verify_email=""
            error_username_exists=""
            error_user_exists=""
            error_captcha=""

            have_error = False

            if not valid_captcha(input_captcha):
                # Show the error-message: captcha not resolved.
                error_captcha = True
                have_error = True

            if not valid_username(input_username):
                # Show the error-message: not a valid username.
                error_username = True
                have_error = True
            if not valid_password(input_password):
                # Show the error-message: not a valid password.
                error_password = True
                have_error = True
            if not valid_verify(input_password, input_verify_password):
                # Show the error-message: passwords do not match.
                error_verify_password = True
                have_error = True
            if not valid_email(input_email):
                # Show the error-message: not a valid email.
                error_email = True
                have_error = True
            if not valid_verify(input_email, input_verify_email):
                # Show the error-message: emails do not match.
                error_verify_email = True
                have_error = True
            if have_error == False:
                u = User.by_name(input_username)
                if u:
                    # Show the error-message: username is already taken.
                    error_username_exists = True
                    have_error = True
                    
                u = User.by_email(input_email)
                if u:
                    # Show the error-message: email already used.
                    error_user_exists = True
                    have_error = True

            if have_error:
                state = self.make_state()
                # Render page with error-messages.
                self.render('signup.html',
                            error_username = error_username,
                            error_username_exists = error_username_exists,
                            error_password = error_password,
                            error_verify_password = error_verify_password,
                            error_email = error_email,
                            error_verify_email = error_verify_email,
                            error_user_exists = error_user_exists,
                            error_captcha = error_captcha,
                            username_form = input_username,
                            email_form = input_email,
                            verify_email_form = input_verify_email,
                            state = state)
            else:
                #Create new entry in the User-DB.
                u = User.register(input_username, input_password, input_email)

                #Send confirmation email
                self.send_email(u.email, 
                                'email_subject.html', 
                                'email_welcome.html', 
                                subject_type = 'welcome', 
                                username = u.name, 
                                user_email = u.email)
                
                # Start session and add welcome flash for homepage
                self.session['provider'] = 'blog'
                self.login(u)
                self.session.add_flash('message_signup_2', 
                                       key='homepage_flashes')
                self.redirect("/")


class LoginHandler(Handler):

    def get(self):
        if self.user:
            # Prompt user to log out.
            self.session.add_flash('message_login_1', key='homepage_flashes')
            self.redirect("/")
        else:
            state = self.make_state()
            self.render('login.html', 
                        state = state)

    def post(self):
        if self.user:
            # Prompt user to log out.
            self.session.add_flash('message_login_1', key='homepage_flashes')
            self.redirect("/")
        else:
            if not self.check_state():
                self.redirect("/")
                return

            input_email = self.request.get('email').lower()
            input_password = self.request.get('password')
            input_captcha = self.request.get('g-recaptcha-response')

            have_error = False

            if not valid_captcha(input_captcha):
                # Show generic login error-message.
                have_error = True

            if not valid_email(input_email):
                # Show generic login error-message.
                have_error = True
            if not valid_password(input_password):
                # Show generic login error-message.
                have_error = True

            if have_error == False:
                u = User.login_by_email(input_email, input_password)
                if not u:
                    # Show generic login error-message.
                    have_error = True

            if have_error == False:
                # Start session and add welcome flash for homepage
                self.session['provider'] = 'blog'
                self.login(u)
                self.session.add_flash('message_login_2', key='homepage_flashes')
                self.redirect('/')
            else:
                state = self.make_state()
                # Render page with error-messages.
                self.render('login.html', 
                            error = True, 
                            email_form = input_email,
                            state = state)


class GoogleConnectHandler(Handler):


    CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']

    def post(self):
        # Validate state token
        if not self.check_state():
            self.response.set_status(401)
            self.response.headers["Content-Type"] = 'text/html'
            self.response.out.write('Invalid state parameter.')
            return
        # Obtain authorization code
        code = self.request.body
        logging.error('Request data from Google (Authorization code):')
        logging.error(code)

        try:
            # Upgrade the authorization code into a credentials object
            oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
            oauth_flow.redirect_uri = 'postmessage'
            credentials = oauth_flow.step2_exchange(code)
            logging.error('User credentials recieved from Google (Access token, ...):')
            for attr in dir(credentials):
                logging.error("obj.%s = %s" % (attr, getattr(credentials, attr)))
           
        except FlowExchangeError:
            self.response.set_status(401)
            self.response.headers["Content-Type"] = 'text/html'
            self.response.out.write('Failed to upgrade the authorization code.')
            return

        # Check that the access token is valid.
        access_token = credentials.access_token
        logging.error('In gconnect access token is %s', access_token)
        url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
               % access_token)
        h = httplib2.Http()
        result = json.loads(h.request(url, 'GET')[1])
        logging.error('Check Access token. Result: ')
        logging.error(result)
        # If there was an error in the access token info, abort.
        if result.get('error') is not None:
            self.response.set_status(500)
            self.response.headers["Content-Type"] = 'text/html'
            self.response.out.write(result.get('error'))
            return

        # Verify that the access token is used for the intended user.
        gplus_id = credentials.id_token['sub']
        if result['user_id'] != gplus_id:
            self.response.set_status(401)
            self.response.headers["Content-Type"] = 'text/html'
            self.response.out.write("Token's user ID doesn't match given user ID.")
            return

        # Verify that the access token is valid for this app.
        if result['issued_to'] != self.CLIENT_ID:
            logging.error("Token's client ID does not match app's.")
            self.response.set_status(401)
            self.response.headers["Content-Type"] = 'text/html'
            self.response.out.write("Token's client ID does not match app's.")
            return

        # Store the access token in the session for later use.
        self.session['access_token'] = credentials.access_token
        self.session['gplus_id'] = gplus_id

        # Get user info
        url_userinfo = ('https://www.googleapis.com/oauth2/v1/userinfo?access_token=%s&alt=json'
               % access_token)
        h = httplib2.Http()
        data = json.loads(h.request(url_userinfo, 'GET')[1])
       

        # ADD PROVIDER TO LOGIN SESSION
        self.session['provider'] = 'google'

        # see if user exists, if it doesn't make a new one
        u = User.by_email(data['email'])
        if not u:
            # turn name from Google+ into a unique username
            # replace spaces with underscores
            u_name = str(data['name'].replace(" ","_"))
            # check if username exists
            # add a random number
            while User.by_name(u_name):
                u_name = u_name + str(randint(0,9))
                # SET FLASH MESSAGE THAT USERNAME CAN BE EDITED.
            
            u = User.register(u_name,
                              None,
                              data['email'])

            #Send confirmation email
            self.send_email(u.email, 
                            'email_subject.html', 
                            'email_welcome_gplus.html', 
                            subject_type = 'welcome', 
                            username = u.name, 
                            user_email = u.email)
            
            #Set session and add a flash welcome message
            self.login(u)
            self.session.add_flash('message_signup_2', 
                               key='homepage_flashes')
   
        else:
            self.login(u)
            self.session.add_flash('message_login_2', 
                               key='homepage_flashes')

        output = ''
        output += '<h1>Welcome, '
        output += data['name']
        output += '!</h1>'
        output += '<img src="'
        output += data['picture']
        output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
        self.response.set_status(200)
        self.response.headers["Content-Type"] = 'text/html'
        self.response.out.write(output)


class FacebookConnectHandler(Handler):

    def post(self):
        # Validate state token
        if not self.check_state():
            self.response.set_status(401)
            self.response.headers["Content-Type"] = 'text/html'
            self.response.out.write('Invalid state parameter.')
            return

        # Obtain fb_exchange_token
        fb_exchange_token = self.request.body
        logging.error('Request data from Facebook (fb_exchange_token):')
        logging.error(fb_exchange_token)

        # Upgrade the fb_exchange_token into an access_token to get user info from API
        app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
            'web']['app_id']
        app_secret = json.loads(
            open('fb_client_secrets.json', 'r').read())['web']['app_secret']
        url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
            app_id, app_secret, fb_exchange_token)
        h = httplib2.Http()
        result = h.request(url, 'GET')[1]

        # Use access_token to get user info from API
        # strip expire tag from access_token
        access_token = result.split("&")[0]

        url = 'https://graph.facebook.com/v2.4/me?%s&fields=name,id,email' % access_token
        h = httplib2.Http()
        result = h.request(url, 'GET')[1]
        data_profile = json.loads(result)
        self.session['facebook_id'] = data_profile["id"]
        self.session['provider'] = 'facebook'

        # The access_token must be stored in the login_session in order to properly logout, let's strip out the information before the equals sign in our access_token
        stored_access_token = access_token.split("=")[1]
        self.session['access_token'] = stored_access_token

        # Get user picture
        url = 'https://graph.facebook.com/v2.4/me/picture?%s&redirect=0&height=200&width=200' % access_token
        h = httplib2.Http()
        result = h.request(url, 'GET')[1]
        data_picture = json.loads(result)

        # see if user exists, if it doesn't make a new one
        u = User.by_email(data_profile['email'])
        if not u:
            # turn name from FB into a unique username
            # replace spaces with underscores
            u_name = str(data_profile['name'].replace(" ","_"))
            # check if username exists
            # add a random number
            while User.by_name(u_name):
                u_name = u_name + str(randint(0,9))
            
            u = User.register(u_name,
                              None,
                              data_profile['email'])

            #Send confirmation email
            self.send_email(u.email, 
                            'email_subject.html', 
                            'email_welcome_fb.html', 
                            subject_type = 'welcome', 
                            username = u.name, 
                            user_email = u.email)
            
            #Set session and add a flash welcome message
            self.login(u)
            self.session.add_flash('message_signup_2', 
                               key='homepage_flashes')
   
        else:
            self.login(u)
            self.session.add_flash('message_login_2', 
                               key='homepage_flashes')

        output = ''
        output += '<h1>Welcome, '
        output += data_profile["name"]

        output += '!</h1>'
        output += '<img src="'
        output += data_picture["data"]["url"]
        output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
        self.response.set_status(200)
        self.response.headers["Content-Type"] = 'text/html'
        self.response.out.write(output)


class TwitterConnectHandler(Handler):

    def get(self):

        # Validate state token
        if not self.check_state():
            self.response.set_status(401)
            self.response.headers["Content-Type"] = 'text/html'
            self.response.out.write('Invalid state parameter.')
            return


        consumer_key = json.loads(open('twitter_client_secrets.json', 'r').read())['web']['consumer_key']
        consumer_secret = json.loads(open('twitter_client_secrets.json', 'r').read())['web']['consumer_secret']
        consumer = oauth.Consumer(consumer_key, consumer_secret)

        # Step 1: Get a request token. This is a temporary token that is used for 
        # having the user authorize an access token and to sign the request to obtain 
        # said access token.
        # The only unique parameter in this request is oauth_callback, 
        # which must be a URL-encoded version of the URL you wish your user 
        # to be redirected to when they complete step 2.

        client = oauth.Client(consumer)

        #callback_url = 'http://localhost:13080/tlogin'
        callback_url = 'http://signupjupp.appspot.com/tlogin'

        request_token_url = 'https://api.twitter.com/oauth/request_token?oauth_callback=%s' % quote_plus(callback_url)

        resp, content = client.request(request_token_url, "POST")
        if resp['status'] != '200':
            raise Exception("Invalid response %s." % resp['status'])

        request_token = dict(urlparse.parse_qsl(content))

        if request_token['oauth_callback_confirmed'] != 'true':
            raise Exception("Invalid response: oauth_callback_confirmed not true")

        self.session['request_token'] = request_token

        logging.error('Request token from TWITTER:')
        logging.error(request_token)

        # Step 2: Redirect to the provider.
        # After the user has granted access to you, the consumer, the provider will
        # redirect you to whatever URL you have told them to redirect to. You can 
        # usually define this in the oauth_callback argument as well.

        authenticate_url = 'https://api.twitter.com/oauth/authenticate'
        redirect_url = "%s?oauth_token=%s" % (authenticate_url, request_token['oauth_token'])

        self.redirect(redirect_url)



class TwitterLogintHandler(Handler):

    def get(self):

        # Step 3: Once the consumer has redirected the user back to the oauth_callback
        # URL you can request the access token the user has approved. You use the 
        # request token to sign this request. After this is done you throw away the
        # request token and use the access token returned. You should store this 
        # access token somewhere safe, like a database, for future use.

        access_token_url = 'https://api.twitter.com/oauth/access_token'

        consumer_key = json.loads(open('twitter_client_secrets.json', 'r').read())['web']['consumer_key']
        consumer_secret = json.loads(open('twitter_client_secrets.json', 'r').read())['web']['consumer_secret']

        consumer = oauth.Consumer(consumer_key, consumer_secret)
 
        input_oauth_token = self.request.get('oauth_token')
        input_oauth_verifier = self.request.get('oauth_verifier')
        if not input_oauth_verifier:
            raise Exception("No oauth_verifier received.")

        request_token = self.session.get('request_token')
        logging.error(request_token['oauth_token'])
        if not input_oauth_token == request_token['oauth_token']:
            raise Exception("Invalid request_token.")

        token = oauth.Token(request_token['oauth_token'], request_token['oauth_token_secret'])
        token.set_verifier(input_oauth_verifier)
        client = oauth.Client(consumer, token)

        resp, content = client.request(access_token_url, "POST")
        if resp['status'] != '200':
            raise Exception("Invalid response %s." % resp['status'])

        access_token = dict(urlparse.parse_qsl(content))

        logging.error('TWITTER ACCESS TOKEN:')
        logging.error(access_token)

        # Set the API endpoint 
        url = "https://api.twitter.com/1.1/account/verify_credentials.json?include_email=true&skip_status=true&include_entities=false"

        token = oauth.Token(access_token['oauth_token'], access_token['oauth_token_secret'])

        client = oauth.Client(consumer, token)

        resp, content = client.request(url, "GET")
        if resp['status'] != '200':
            raise Exception("Invalid response %s." % resp['status'])

        user_credentials = json.loads(content)
        self.session['twitter_id'] = user_credentials["id"]
        self.session['provider'] = 'twitter'

        # The access_token must be stored in the login_session in order to properly logout
        self.session['access_token'] = access_token


        logging.error('TWITTER CREDENTIALS:')
        logging.error(content)
        logging.error(user_credentials['email'])

        # see if user exists, if it doesn't make a new one
        u = User.by_email(user_credentials['email'])
        if not u:
            # turn name from Twitter into a unique username
            # replace spaces with underscores
            u_name = str(user_credentials['name'].replace(" ","_"))
            # check if username exists
            # add a random number
            while User.by_name(u_name):
                u_name = u_name + str(randint(0,9))
            
            u = User.register(u_name,
                              None,
                              user_credentials['email'])

            #Send confirmation email
            self.send_email(u.email, 
                            'email_subject.html', 
                            'email_welcome_fb.html', 
                            subject_type = 'welcome', 
                            username = u.name, 
                            user_email = u.email)
            
            #Set session and add a flash welcome message
            self.login(u)
            self.session.add_flash('message_signup_2', 
                               key='homepage_flashes')
   
        else:
            self.login(u)
            self.session.add_flash('message_login_2', 
                               key='homepage_flashes')

        self.redirect('/')


class LogoutHandler(Handler):

    def gdisconnect(self):
        access_token = self.session.get('access_token')
        # Only disconnect a connected user.
        if access_token is None:
            logging.error('gdisconnect: access_token not found in session!')
            return
        url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
        h = httplib2.Http()
        result = h.request(url, 'GET')[0]
        if result['status'] == '200':
            logging.info('Successfully revoked token for given user.')
            return
        else:
            # For whatever reason, the given token was invalid.
            logging.error('Failed to revoke token for given user.')
            return

    def fbdisconnect(self):
        facebook_id = self.session.get('facebook_id')
        if facebook_id is None:
            logging.error('fbdisconnect: facebook_id not found in session!')
            return
        # The access token must me included to successfully logout
        access_token = self.session.get('access_token')
        if access_token is None:
            logging.error('fbdisconnect: access_token not found in session!')
            return
        url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
        h = httplib2.Http()
        result = h.request(url, 'DELETE')[1]
        return


    def get(self):
        if self.user:
            if self.session.get('provider') == 'google':
                self.gdisconnect()
            if self.session.get('provider') == 'facebook':
                self.fbdisconnect()
            self.logout()
            # Show message that user has been logged out.
            self.session.add_flash('message_logout_1', key='homepage_flashes')
            self.redirect("/")
        else:
            self.redirect("/")


# --- PASSWORD RESET ---

class ForgotPasswordHandler(Handler):

    def get(self):
        if self.user:
            # Prompt user to log out.
            self.session.add_flash('message_forgot_password_1', 
                                   key='homepage_flashes')
            self.redirect("/")
        else:
            state = self.make_state()
            self.render('forgot_password.html', state = state)

    def post(self):
        if self.user:
            # Prompt user to log out.
            self.session.add_flash('message_forgot_password_1', 
                                   key='homepage_flashes')
            self.redirect("/")
        else:
            if not self.check_state():
                self.redirect("/")
                return
            # Receive input from web-page: eamil
            input_email = self.request.get('email').lower()

            have_error = False
            if not valid_email(input_email):
                # Show the error-message: not a valid email.
                have_error = True

            if have_error:
                state = self.make_state()
                # Render page with error-message.
                self.render('forgot_password.html', 
                            form_email = input_email, 
                            error = True,
                            state = state)
                return

            self.user = User.by_email(input_email)
            if not self.user:
                logging.warning('Unknown email from forgot password page received!')
                # Redirect to "/". Flash message that email was sent.
                self.session.add_flash('message_forgot_password_2', 
                                       key='homepage_flashes')
                self.session.add_flash(input_email, key='input_email')
                self.redirect("/")

            else:
                # Generate new temporary random password
                length = 10
                temp_pw = ''.join(random.choice(ascii_letters)for x in xrange(length))

                # Create entry in ResetPasswordRequest DB
                r = ResetPasswordRequest.create(input_email, temp_pw)

                # Send email with a link to the ResetPassword page. 
                # The link includes email and temporary password to 
                # authenticate the user.
                # ADAPT LINK TO GAE URL
                resetToken = str(r.key().id())+"-"+temp_pw
                link = "http://YOUR_APP_ID.appspot.com/reset_pw/?token=%s" %(resetToken)

                self.send_email(self.user.email, 
                                'email_subject.html', 
                                'email_forgot_password.html', 
                                subject_type = 'forgot_password', 
                                username = self.user.name, 
                                link = link)

                # Redirect to "/". Flash message that email was sent.
                self.session.add_flash('message_forgot_password_2', 
                                       key='homepage_flashes')
                self.session.add_flash(input_email, key='input_email')
                self.redirect("/")


class ResetPasswordHandler(Handler):

    def get(self):
        if self.user:
            # Prompt user to logout
            self.session.add_flash('message_reset_password_1', 
                                   key='homepage_flashes')
            self.redirect("/")
        else:
            # Get token from URL
            input_token = self.request.get('token')

            # Check if format of token is valid 
            TOKEN_RE = re.compile(r"^([0-9]{1,30})\-.{3,20}$")
            if not TOKEN_RE.match(input_token):
                # Set invalid reset_id so that a normal error message is sent
                reset_id = 1
            else:
                # Split token to obtain reset_id and temp_pw.
                reset_id = int(input_token.split('-')[0])
                temp_pw = input_token.split('-')[1]

            # Use reset_id to find entry in ResetPasswordRequest DB.
            self.r = ResetPasswordRequest.by_id(reset_id)
            # Check if entry exists 
            if not self.r:
                # Show message that link is not valid.
                self.session.add_flash('message_reset_password_2', 
                                       key='homepage_flashes')
                self.redirect("/")

            # Check if entry is not older than one hour.
            elif datetime.datetime.now() - datetime.timedelta(hours = 1) > self.r.created:
                # Show message that too much time has passed.
                self.session.add_flash('message_reset_password_3', 
                                       key='homepage_flashes')
                self.redirect("/")

            # Check if temp_pw is valid
            elif not ResetPasswordRequest.check_for_valid_request(self.r.email, temp_pw):
                # Show message that the link is not valid.
                self.session.add_flash('message_reset_password_4', 
                                       key='homepage_flashes')
                self.redirect("/")

            # If no error, get user by_email, 
            # log in and render reset_password.html 
            else:
                email = self.r.email
                self.user = User.by_email(email)
                self.login(self.user)
                state = self.make_state()
                self.render('reset_password.html', 
                            user = self.user, 
                            token = input_token,
                            state = state) 
    
    def post(self):
        if self.user:
            if not self.check_state():
                self.redirect("/")
                return

            # Get user input: password and verify_password
            input_password = self.request.get('password')
            input_verify_password = self.request.get('verify_password')
            # Get token from web page
            input_token = self.request.get('token')

            # Check if token is valid
            TOKEN_RE = re.compile(r"^([0-9]{1,30})\-.{3,20}$")
            if not TOKEN_RE.match(input_token):
                # Set invalid reset_id so that a normal error message is sent
                reset_id = 1
            else:
                reset_id = int(input_token.split('-')[0])
                temp_pw = input_token.split('-')[1]

            # Use reset_id to find entry in ResetPasswordRequest DB.
            self.r = ResetPasswordRequest.by_id(reset_id)
            # Check if entry exists 
            if not self.r:
                # Show message to contact via email
                self.session.add_flash('message_reset_password_5', 
                                       key='homepage_flashes')
                self.redirect("/")

            #Check if entry is not older than one hour.
            elif datetime.datetime.now() - datetime.timedelta(hours = 1) > self.r.created:
                # Show message that too much time has passed.
                self.session.add_flash('message_reset_password_3', 
                                       key='homepage_flashes')
                self.redirect("/")

            #Check if temp_pw is valid
            elif not ResetPasswordRequest.check_for_valid_request(self.r.email, temp_pw):
                # Show message to contact via email
                self.session.add_flash('message_reset_password_5', 
                                       key='homepage_flashes')
                self.redirect("/")
            else:
                # Check if password and verify_password are valid. 
                # Set error-messages. 
                error_password=""
                error_verify_password=""

                have_error = False

                if not valid_password(input_password):
                    # Show the error-message: not a valid password.
                    error_password = True
                    have_error = True
                if not valid_verify(input_password, input_verify_password):
                    # Show the error-message: passwords do not match.
                    error_verify_password = True
                    have_error = True

                if have_error:
                    state = self.make_state()
                    # Render page with error-messages.
                    self.render('reset_password.html',
                                user = self.user,
                                token = input_token,
                                error_password = error_password,
                                error_verify_password = error_verify_password,
                                state = state)
                else:
                    # Update user object in DB and memcache
                    User.update(self.user, pw=input_password)

                    # Invalidate entity in ResetPasswordRequest db
                    ResetPasswordRequest.update(self.r, temp_pw_hash = "deactivated")

                    # Show message that the password has been changed.
                    self.session.add_flash('message_reset_password_7', 
                                           key='homepage_flashes')
                    self.redirect("/")


        else:
            # Show message to use the link in the email.
            self.session.add_flash('message_reset_password_6', 
                                   key='homepage_flashes')
            self.redirect("/")


# --- USER SETTINGS ---

class UserSettingsHandler(Handler):

    def get(self):
        if self.user:
            self.render('user_settings.html', user = self.user)
        else:
            # Prompt user to login.
            self.session.add_flash('message_user_settings_1', 
                                   key='homepage_flashes')
            self.redirect("/")


class ChangePasswordHandler(Handler):

    def get(self):
        if self.user:
            state = self.make_state()
            self.render('change_password.html', 
                        user = self.user,
                        state = state)
        else:
            # Prompt user to login.
            self.session.add_flash('message_user_settings_1', 
                                   key='homepage_flashes')
            self.redirect("/")

    def post(self):
        if self.user:
            if not self.check_state():
                self.redirect("/")
                return

            # Get user input
            input_password = self.request.get('password')
            input_verify_password = self.request.get('verify_password')

            # Check input and set error messages. 
            error_password=""
            error_verify_password=""

            have_error = False

            if not valid_password(input_password):
                # Set the error-message: not a valid password.
                error_password = True
                have_error = True
            if not valid_verify(input_password, input_verify_password):
                # Set the error-message: passwords do not match.
                error_verify_password = True
                have_error = True
 
            if have_error:
                state = self.make_state()
                # Render page with error-messages.
                self.render('change_password.html',
                            user = self.user,
                            error_password = error_password,
                            error_verify_password = error_verify_password,
                            state = state)
            else:
                # Update user object in DB and memcache
                User.update(self.user, pw=input_password)

                state = self.make_state()
                # Render page with success message.
                self.render('change_password.html', 
                            user = self.user, 
                            success_message = True,
                            state = state)
        else:
            # Prompt user to login.
            self.session.add_flash('message_user_settings_1', 
                                   key='homepage_flashes')
            self.redirect("/")


class ChangeEmailHandler(Handler):

    def get(self):
        if self.user:
            state = self.make_state()
            self.render('change_email.html', 
                        user = self.user,
                        state = state)
        else:
            # Prompt user to login.
            self.session.add_flash('message_user_settings_1', 
                                   key='homepage_flashes')
            self.redirect("/")

    def post(self):
        if self.user:
            if not self.check_state():
                self.redirect("/")
                return

            # Get user input
            input_email = self.request.get('email').lower()
            input_verify_email = self.request.get('verify_email').lower()

            # Check input and set error messages. 
            error_email=""
            error_verify_email=""
            error_user_exists=""

            have_error = False

            if not valid_email(input_email):
                # Set the error-message: not a valid email.
                error_email = True
                have_error = True
            if not valid_verify(input_email, input_verify_email):
                # Set the error-message: emails do not match.
                error_verify_email = True
                have_error = True

            if have_error == False:
                u = User.by_email(input_email)
                if u:
                    # Set the error-message: email already assigned.
                    error_user_exists = True
                    have_error = True
 
            if have_error:
                state = self.make_state()
                # Render page with error-messages.
                self.render('change_email.html',
                            user = self.user,
                            email = input_email,
                            error_email = error_email,
                            error_verify_email = error_verify_email,
                            error_user_exists = error_user_exists,
                            state = state)
            else:
                # Update user object in DB and memcache
                User.update(self.user, email=input_email)

                # Send email notification to new address
                self.send_email(self.user.email, 
                                'email_subject.html', 
                                'email_email_changed.html', 
                                subject_type = 'email_changed', 
                                username = self.user.name, 
                                user_email = self.user.email)
                
                # Render page with message that email was sent
                state = self.make_state()
                self.render('change_email.html', 
                            user = self.user, 
                            success_message = True,
                            state = state)
        else:
            # Prompt user to login.
            self.session.add_flash('message_user_settings_1', 
                                   key='homepage_flashes')
            self.redirect("/")


class ChangeUsernameHandler(Handler):

    def get(self):
        if self.user:
            state = self.make_state()
            self.render('change_username.html',
                        user = self.user,
                        state = state)
        else:
            # Prompt user to login.
            self.session.add_flash('message_user_settings_1', 
                                   key='homepage_flashes')
            self.redirect("/")

    def post(self):
        if self.user:
            if not self.check_state():
                self.redirect("/")
                return

            # Get user input
            input_username = self.request.get('username')

            # Check input and set error messages. 
            error_username=""
            error_username_exists=""

            have_error = False

            if not valid_username(input_username):
                # Set the error-message: not a valid username.
                error_username = True
                have_error = True

            if have_error == False:
                u = User.by_name(input_username)
                if u:
                    # Set the error-message: username already taken.
                    error_username_exists = True
                    have_error = True
 
            if have_error:
                state = self.make_state()
                # Render page with error-messages.
                self.render('change_username.html',
                            user = self.user,
                            username = input_username,
                            error_username = error_username,
                            error_username_exists = error_username_exists,
                            state = state)
            else:
                # Update user object in DB and memcache
                User.update(self.user, name=input_username)

                # Render page success message
                state = self.make_state()
                self.render('change_username.html', 
                            user = self.user, 
                            success_message = True,
                            state = state)

        else:
            # Prompt user to login.
            self.session.add_flash('message_user_settings_1', 
                                   key='homepage_flashes')
            self.redirect("/")


class DeleteAccountHandler(Handler):

    def get(self):
        if self.user:
            state = self.make_state()
            self.render('delete_account.html',
                        user = self.user,
                        state = state)
        else:
            # Prompt user to login.
            self.session.add_flash('message_user_settings_1', 
                                   key='homepage_flashes')
            self.redirect("/")

    def post(self):
        if self.user:
            if not self.check_state():
                self.redirect("/")
                return

            # Deactivate account by deleting from User database and 
            # adding to the DeactAccounts database.
            d = DeactAccounts.create(self.user.key().id(), 
                                     self.user.name,
                                     self.user.email)

            # Delete user
            User.remove(self.user.key().id())

            # Genrate list of article-keys for the deleted user.
            article_key_list = Article.keys_by_author(self.user.key().id())

            for key in article_key_list:
                # Store article in DeletdArticle DB
                article = Article.by_id(key.id())
                del_art = DeletdArticle.create(article.title,
                                               article.body, 
                                               article.author)
                del_art.put()
                # Delete article from Article DB
                Article.remove(key.id())
            
            # Logout (delete coockie)
            self.logout()

            # Send email notification
            self.send_email(d.email, 
                            'email_subject.html', 
                            'email_account_deleted.html', 
                            subject_type = 'account_deleted')


            # Render page with message that account was deleted
            self.session.add_flash('message_delete_account_1', 
                                   key='homepage_flashes')
            self.session.add_flash(d.email, key='deleted_email')
            self.redirect("/")

        else:
            # Prompt user to login.
            self.session.add_flash('message_user_settings_1', 
                                   key='homepage_flashes')
            self.redirect("/")


