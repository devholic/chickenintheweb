#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import webapp2
import logging
import random
import datetime
import hashlib
from webapp2_extras import sessions
from google.appengine.ext import db
from google.appengine.ext.webapp import template

class User(db.Model):
	email = db.StringProperty() # 이메일
	password = db.StringProperty() # 비밀번호
	name = db.StringProperty() # 이름
	address = db.StringProperty() # 주소
	number = db.StringProperty() # 전화번호
	salt = db.StringProperty() # Salt
	created_at = db.DateProperty(auto_now_add=True) # Created At
	isSeller = db.BooleanProperty() # 판매자인지 
	isAdmin = db.BooleanProperty() # 관리자인지

def Render(handler, path = "index.htm", values ={}):
	fpath = os.path.join(os.path.dirname(__file__), 'templates/' + path)
	if not os.path.isfile(fpath):
		return False
	d = dict(values)
	email = handler.session.get('email')
	if email:
		d['email'] = email

	d['path'] = handler.request.path
	outstr = template.render(fpath, d)
	handler.response.out.write(unicode(outstr))
	return True

class BaseHandler(webapp2.RequestHandler):
    def dispatch(self):
        # Get a session store for this request.
        self.session_store = sessions.get_store(request=self.request)
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

class RegisterHandler(webapp2.RequestHandler):
	def get(self):
		path = os.path.join(os.path.dirname(__file__), 'error.htm')
		self.response.write(template.render(path,{'errorcode':'400'}))

	def post(self):
		req_email = self.request.get('email')
		alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
		saltstring = ""
		for i in range(16):
			saltstring+=random.choice(alphabet)

		query = User.all()
		if query.filter("email ==",req_email).count() == 1:
			# 유저가 존재하는 경우
			# 유저를 삭제 
			req_pw = self.request.get('password')
		else:
			# 유저를 추가
			user = User()
			user.email = self.request.get('email')
			user.password = hashlib.sha256(self.request.get('password') + saltstring).hexdigest() # Hash 후 저장
			user.salt = saltstring # Salt
			user.isSeller = False # 판매자 False
			user.isAdmin = False # 관리자 False
			user.put()

class LoginHandler(BaseHandler):
	def get(self):
		Render(self, "index.htm")

	def post(self):
		email = self.request.get('email')
		password = self.request.get('password')
		query = db.Query(User)
		q = query.filter("email ==",email)
		if q.count() == 1:
			# 유저가 존재하는 경우
			u = q.get()
			if u.password == hashlib.sha256(password + u.salt).hexdigest():
				self.session['email'] = email
				Render(self, 'index.htm', {})
			else:
				Render(self, 'error.htm', {'errorcode':'401'})
		else:
			Render(self, 'error.htm', {'errorcode':'400'})

class LogoutHandler(BaseHandler):
	def get(self):
		self.session.clear()
		Render(self, "index.htm")

	def post(self):
		self.session.clear()
		Render(self, "index.htm")

class MainHandler(BaseHandler):
    def get(self):
		logging.info(self.request.path)
		if Render(self,self.request.path):
			return
		Render(self, 'index.htm', {})

config = {}

config['webapp2_extras.sessions'] = {
    'secret_key': 'dc458da48fa171a071a547a07d8e13f25dd2ed714a03f4d6fbae331e6b711139',
}

app = webapp2.WSGIApplication([('/login', LoginHandler), ('/register', RegisterHandler), ('/logout', LogoutHandler), ('/.*', MainHandler)], debug=True, config=config)

def main():
	app.run()

if __name__ == '__main__':
	main()