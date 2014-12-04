#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import webapp2
import logging
import random
import datetime
import time
import hashlib
import urllib2
from webapp2_extras import sessions
from google.appengine.api import mail
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

class UserRecovery(db.Model):
	email = db.StringProperty() # 이메일
	code = db.StringProperty() # 코드
	expire = db.IntegerProperty()

def Render(handler, path = "n_index.htm", values ={}):
	fpath = os.path.join(os.path.dirname(__file__), 'templates/' + path)
	if not os.path.isfile(fpath):
		return False
	d = dict(values)
	email = handler.session.get('email')
	if email:
		d['email'] = email
	d['path'] = handler.request.path
	outstr = template.render(fpath, d)
	handler.response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
	handler.response.headers["Pragma"] = "no-cache"
	handler.response.headers["Expires"] = "0"
	handler.response.out.write(unicode(outstr))
	return True

def Salt():
	alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	saltstring = ""
	for i in range(16):
		saltstring+=random.choice(alphabet)
	return saltstring

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

class RegisterHandler(BaseHandler):
	def get(self):
		Render(self, 'n_register.htm', {})

	def post(self):
		req_email = self.request.get('email')
		query = db.Query(User)
		q = query.filter("email ==",email)
		if q.count() == 1:
			# 유저가 존재하는 경우
			u = q.get()
			req_pw = self.request.get('password')
			# 로그인 시도
			if u.password == hashlib.sha256(req_pw + u.salt).hexdigest():
				self.session['email'] = email
				Render(self, 'n_index.htm', {})
			else:
			# 만약 아니라면 이미 있는 계정이라고 form update
				$.ajax({
				type: "POST",
				url: "https://myapp.appspot.com/service",
				contentType: "application/json; charset=utf-8",
				data: data,
				success: function(data) {
				alert("AJAX done");
				}
				}); 
		else:
			# 유저를 추가
			user = User()
			user.email = self.request.get('email')
			user.password = hashlib.sha256(self.request.get('password') + Salt()).hexdigest() # Hash 후 저장
			user.name = self.request.get('name')
			user.address = self.request.get('address')
			user.number = self.request.get('number')
			user.salt = saltstring # Salt
			user.isSeller = False # 판매자 False
			user.isAdmin = False # 관리자 False
			user.put()
			self.session['email'] = email
			self.session['name'] = name
			Render(self, 'n_index.htm', {})

class LoginHandler(BaseHandler):
	def get(self):
		Render(self, 'n_index.htm', {})

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
				Render(self, 'n_index.htm', {})
			else:
				Render(self, 'error.htm', {'errorcode':'401'})
		else:
			Render(self, 'error.htm', {'errorcode':'400'})

class LogoutHandler(BaseHandler):
	def get(self):
		if self.session.get('email'):
			self.session.pop('email')
			self.session.clear()
		Render(self, 'n_index.htm', {})

	def post(self):
		if self.session.get('email'):
			self.session.pop('email')
			self.session.clear()
		Render(self, 'n_index.htm', {})

class UserpwHandler(BaseHandler):
	def get(self):
		Render(self, 'n_index.htm', {})

	def post(self):
		email = self.request.get('email')
		query = db.Query(User)
		q = query.filter("email ==",email)
		if q.count() == 1:
			# 유저가 존재하는 경우
			user = UserRecovery()
			user.email = email
			code = Salt()
			user.code = code
			t = int(time.time()) + 1800
			user.expire = t
			user.put()
			message = mail.EmailMessage(sender="no-reply@chickenintheweb.appspotmail.com",
                            subject="치킨인더웹 비밀번호 재설정 코드입니다.")
			message.to = email
			message.body = """
			비밀번호 재설정 코드는 %s 입니다.
			""" % code
			message.send()
		else:
			Render(self, 'error.htm', {'errorcode':'400'})

class MainHandler(BaseHandler):
    def get(self):
		logging.info(self.request.path)
		if Render(self,self.request.path):
			return
		Render(self, 'n_index.htm', {})

config = {}

config['webapp2_extras.sessions'] = {
    'secret_key': 'dc458da48fa171a071a547a07d8e13f25dd2ed714a03f4d6fbae331e6b711139',
}

app = webapp2.WSGIApplication([('/login', LoginHandler), ('/register', RegisterHandler), ('/logout', LogoutHandler), ('/findpw', UserpwHandler), ('/.*', MainHandler)], debug=True, config=config)

def main():
	app.run()

if __name__ == '__main__':
	main()