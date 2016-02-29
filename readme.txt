Based on Basic Blog with a view additional features.

1 Social login with Google+, Facebook and Twitter.
2. Enhanced session management and flash messaging via webapp2 sessions module.
3. ReCaptcha for additional security.


To run this webapp locally you need to do the following:

1. Create a local clone of this repository on your computer.

2. Download and install Google App Engine SDK for Python.
    https://cloud.google.com/appengine/downloads

3. Open the Google App Engine Launcher and import the app.
    a. Click on "Add Existing Application..." in the "File" menu.
    b. Navigate to the folder where the "app.yaml" and the .py-files are located.
    c. Click on "Add" to import the the app.

4. Enable Google+ sign in:
    a. Create a Google account.
    b. Visit http://console.developers.google.com, create a new project and get the Project-ID.
    c. Add the Project-ID to the app.yaml file. First line: "application: ADD-YOUR-PROJECT-ID-HERE"
    d. Back at the Google Developers console go to: API Manager - Credentials - Create Credentials - OAuth client ID. Select Web Application and follow the instructions to create a client_ID.
    e. Download JSON file with your client ID and save it in the main app folder as client_secret.json. (Override the dummy-file)
    f. Open login.html and signup.html and add the Google Client ID at the indicated pace.

5. Enable Facebook sign in:
    a. Create Facebook account
    b. Visit https://developers.facebook.com, register your app and get App ID and App Secret.
    c. Open fb_client_secrets.json located in the main app folder and add App ID and App Secret at the indicated places.
    d. Open login.html and signup.html and add the App ID at the indicated pace.

6. Enable Twitter sign in:
    a. Create Twitter account.
    b. Visit https://apps.twitter.com, register your app and get Consumer Key and Consumer Secret.
    c. You have to apply for a permission to request a user’s email address. This is a manual process and may take a day or two.
    d. Open twitter_client_secrets.json located in the main app folder and add Consumer Key and Consumer Secret at the indicated places.

7. Enable ReCaptcha:
    a. Visit https://www.google.com/recaptcha, register your app and get Site Key and Secret key.
    b. Open utils.py located in the main app folder and add the secret key at the indicated place inside the valid_captcha method.
    c. Open the HTML files and add the site key at the indicated place.

8. Generate a random session key and replace the placeholder in main.py

9. Put Google App ID in the placeholder in the ForgotPasswordHandler in user-module.py

10. Run the app.
    a. Select the app in the list on the main screen and click on "Run".
    b. Open a web browser and go to localhost:8080.
        The port-number may vary, it is  given on the main screen of the Google App Engine Launcher.

If locally run, the email functionality will not work. (And also password recovery.)

To get the app online do the following:

1. Edit "sender_address" in the send_email method in the handler.py file.
    You can use the email address of your Google Account,
    or add other emails in the Permissions section of Google Developers Console.

2. Edit "sender" in the ContactHandler class in the homepage-handler.py file.
    You can use the email address of your Google Account,
    or add other emails in the Permissions section of Google Developers Console.

3. Deploy the app from Google App Engine Launcher (Click “Deploy” on the main screen.)


