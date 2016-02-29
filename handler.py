import webapp2
from webapp2_extras import sessions
import jinja2
import os
import logging

from utils import *
from user_database import User

from google.appengine.api import mail

# Create an instance of the Jinja2.environment class to
# load the templates from the filesystem.
# Use the Jinja2 builtin FileSystemLoader().
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_environment = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                                       autoescape = True)


# The following Handler-class will be inherited 
# by every request handler class.

class Handler(webapp2.RequestHandler):

# --- RENDERING ---

    def write(self, *a, **kw):
        '''Write to the body fo the response-object

        Arguments:
        *a, **kw -- here the response body created by render_str()
        '''
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        '''Render a template with the given parameters

        Load the template by calling the get_template() method
        Render the template by calling the render() method and passing
        the params to it.
        Arguments:
        template -- the name of the template-file
        **params -- the variables to be passed to the renderer
        Return value:
        the redered template
        '''
        template_params = params
        t = jinja_environment.get_template(template)
        return t.render(template_params)

    def render(self, template, **kw):
        '''Create a response-body 

        Render a given template and write the result to the 
        response body.
        Arguments:
        template -- name of the template-file
        **kw -- the variables to be passed to the renderer
        '''
        self.write(self.render_str(template, **kw))


# --- LOGIN, LOGOUT ---

    def login(self, user):
        self.session['user_id'] = str(user.key().id())

    def logout(self):
        self.session['access_token'] = ''
        self.session['provider'] = ''
        self.session['gplus_id'] = ''
        self.session['facebook_id'] = ''
        self.session['twitter_id'] = ''
        self.session['user_id'] = ''


# --- SECURITY AGAINST CSRF ---

    def make_state(self):
        ''' Make a random state-token, set a cookie and return the token.

        Return value:
        state -- state-token
        '''
        state = ''.join(random.choice(string.ascii_uppercase 
            + string.digits) for x in xrange(32))
        self.session['state'] = state
        return state

    def check_state(self):
        ''' Compare the state-values from cookie and form.
        
        Get the value of 'state' from the form. 
        Get the value of 'state' from the session.
        Conmpare the two values and return the result.
        Log a warning if the two values are not the same.
        Return values:
        True if the two values are the same. 
        False if the two values are not the same.
        '''
        input_state_form = self.request.get('state')
        input_state_session = self.session.get('state')
        self.session['state'] = ''
        if input_state_session and (input_state_session == input_state_form):
            return True
        else:
            logging.warning("Possible CSRF attack detected!")
            return False


# --- EMAIL HANDLING ---

    def send_email(self, to_address, subject_template, email_template, **kw):
        '''Send an email

        Check if the given email address is valid.
        If not valid, log warning.
        If valid, send email.
        Arguments:
        to_address -- receiver email address
        subject_template -- name of template file for the email subject
        email_template -- name of template file for the email body
        **kw -- vriables to be passed to the templates
        '''
        if not mail.is_email_valid(to_address):
            logging.warning('Invalid email address was given by user.')

        else:
            # Set the following sender_address to a valid GAE admin address 
            sender_address = "Blog <blog@gmail.com>"
            body = self.render_str(email_template, **kw)
            subject = self.render_str(subject_template, **kw)
            mail.send_mail(sender_address, to_address, subject, body)

#--- EXCEPTIONS ---

    def handle_exception(self, exception, debug_mode):
        if debug_mode:
            webapp2.RequestHandler.handle_exception(self, exception, debug_mode)
        else:
            logging.exception(exception)
            self.error(500)
            self.render('error.html')


#--- DISPATCH ---
# Happens after initialize
# Get session store and check login here.

    def dispatch(self):
        # Get a session store for this request.
        self.session_store = sessions.get_store(request=self.request)

        # Check if user is logged in
        uid = self.session.get('user_id')
        self.user = uid and User.by_id(int(uid))
        # self.user is either set to None (if there is no user_id-cookie)
        # or to the entity returned from the Datastore (possibly None)

        try:
            # Dispatch the request.
            webapp2.RequestHandler.dispatch(self)
        finally:
            # Save all sessions.
            self.session_store.save_sessions(self.response)

    @webapp2.cached_property
    def session(self):
        # Returns a session using the default cookie key.
        return self.session_store.get_session()
