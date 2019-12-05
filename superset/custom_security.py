from flask import redirect, g, flash, request
from flask_appbuilder.security.views import UserDBModelView,AuthDBView
from superset.security import SupersetSecurityManager
from flask_appbuilder.security.views import expose
from flask_appbuilder.security.manager import BaseSecurityManager
from flask_login import login_user, logout_user, LoginManager
import logging

from .iam import is_authorized


# class CustomAuthDBView(AuthDBView):
#     login_template = 'appbuilder/general/security/login_db.html'

#     @expose('/login/', methods=['GET', 'POST'])
#     def login(self):
#         redirect_url = self.appbuilder.get_url_for_index
#         if request.args.get('redirect') is not None:
#             redirect_url = request.args.get('redirect')
#         print('user====1')
#         if request.args.get('username') is not None:
#             user = self.appbuilder.sm.find_user(username=request.args.get('username'))
#             print('user====2')
#             print(user)
#             login_user(user, remember=False)
#             return redirect(redirect_url)
#         elif g.user is not None and g.user.is_authenticated:
#             print('user====3')
#             return redirect(redirect_url)
#         else:
#             print('user====4')
#             flash('Unable to auto login', 'warning')
#             return super(CustomAuthDBView,self).login()

class CustomSecurityManager(SupersetSecurityManager):
    # authdbview = CustomAuthDBView

    # def oauth_user_info(self, provider, response=None):
    #     print("Oauth2 provider: {0}.".format(provider))
    #     if provider == 'iamOauth':
    #         # As example, this line request a GET to base_url + '/' + userDetails with Bearer  Authentication,
    #         # and expects that authorization server checks the token, and response with user details
    #         me = self.appbuilder.sm.oauth_remotes[provider].get('identity/userinfo').data
    #         logging.debug("user_data: {0}".format(me))
    #         return { 'name' : me['name'], 'email' : me['email'], 'id' : me['iam_id'], 'username' : me['email'], 'first_name':me['given_name'], 'last_name': me['family_name']}

    def create_login_manager(self, app) -> LoginManager:
        """
            Override to implement your custom login manager instance
            :param app: Flask app
        """
        lm = LoginManager(app)
        lm.login_view = "login"
        lm.user_loader(self.load_user)
        lm.request_loader(self.load_user_from_request)
        return lm

    def load_user_from_request(self, request):
        isAuthorized = is_authorized(self, request)
        if (isAuthorized):
            # return the admin account
            return self.get_session.query(self.user_model).get(1)

        return None

    def load_user(self, pk):
        return self.get_user_by_id(int(pk))

    def __init__(self, appbuilder):
         super(CustomSecurityManager, self).__init__(appbuilder)
