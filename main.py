import webapp2

from homepage_handler import HomePageHandler, NewArticleHandler,\
                             EditArticleHandler, ContactHandler, AboutHandler,\
                             TermsHandler, PrivacyHandler, SendEmailHandler
from user_module import SignupHandler, LoginHandler, ForgotPasswordHandler,\
                        LogoutHandler, GoogleConnectHandler, \
                        FacebookConnectHandler, TwitterConnectHandler,\
                        TwitterLogintHandler, UserSettingsHandler,\
                        ChangePasswordHandler, ChangeEmailHandler,\
                        ChangeUsernameHandler, DeleteAccountHandler,\
                        ResetPasswordHandler


# config for sessions
config = {}
config['webapp2_extras.sessions'] = {
    'secret_key': 'SUPER_SECRET_SESSION_KEY',
}


app = webapp2.WSGIApplication([
    ('/', HomePageHandler),
    ('/new_article', NewArticleHandler),
    ('/edit_article/', EditArticleHandler),
    ('/contact', ContactHandler),
    ('/about', AboutHandler),
    ('/terms', TermsHandler),
    ('/privacy', PrivacyHandler),
    ('/share/send_email', SendEmailHandler),
    ('/signup', SignupHandler),
    ('/login', LoginHandler),
    ('/login/forgot_password', ForgotPasswordHandler),
    ('/reset_pw/', ResetPasswordHandler),
    ('/gconnect', GoogleConnectHandler),
    ('/fbconnect', FacebookConnectHandler),
    ('/tconnect', TwitterConnectHandler),
    ('/tlogin', TwitterLogintHandler),
    ('/logout', LogoutHandler),
    ('/user_settings', UserSettingsHandler),
    ('/user_settings/change_password', ChangePasswordHandler),
    ('/user_settings/change_email', ChangeEmailHandler),
    ('/user_settings/change_username', ChangeUsernameHandler),
    ('/user_settings/delete_account', DeleteAccountHandler),
    ], debug = True, config=config)


