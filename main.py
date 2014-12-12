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
import json
from webapp2_extras import sessions
from google.appengine.api import mail
from google.appengine.ext import db
from google.appengine.ext.webapp import template

class User(db.Model):
	email = db.StringProperty() # 이메일
	password = db.StringProperty() # 비밀번호
	name = db.StringProperty() # 이름
	storename = db.StringProperty() # 판매자 전용 속성 : 이름
	address = db.StringProperty() # 주소
	number = db.StringProperty() # 전화번호
	salt = db.StringProperty() # Salt
	created_at = db.DateProperty(auto_now_add=True) # Created At
	isSeller = db.BooleanProperty() # 판매자인지 
	isAdmin = db.BooleanProperty() # 관리자인지

class Chicken(db.Model): # 판매 치킨
	seller = db.ReferenceProperty() # 셀러정보
	name = db.StringProperty() # 이름
	quantity = db.IntegerProperty() # 수량
	price = db.IntegerProperty() # 가격
	isBrand = db.BooleanProperty() # 판매자구분

class ChickenOption(db.Model): # 치킨 옵션
	chicken = db.ReferenceProperty() # 셀러정보
	name = db.StringProperty() # 이름
	quantity = db.IntegerProperty() # 수량
	price = db.IntegerProperty() # 가격

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
	seller = handler.session.get('seller')
	if email:
		d['email'] = email
	if seller:
		d['seller'] = seller
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
		captcha = self.request.get('g-recaptcha-response')
		url = "https://www.google.com/recaptcha/api/siteverify?secret=6Ldi6f4SAAAAAJ5WXvkKk1cSzc7L9C1CALkCnITs&response="+captcha
		chk = urllib2.urlopen(url)
		data = json.load(chk)
		if data['success']:
			# Captcha 성공
			req_email = self.request.get('email')
			query = db.Query(User)
			q = query.filter("email ==", req_email)
			if q.count() == 1:
				# 유저가 존재하는 경우
				u = q.get()
				req_pw = self.request.get('password')
				# 로그인 시도
				if u.password == hashlib.sha256(req_pw + u.salt).hexdigest():
					self.session['email'] = req_email
					self.redirect("/")
				else:
				# 만약 아니라면 이미 있는 계정이라고 form update
					Render(self, 'n_register.htm', {'err': '이미 있는 계정입니다.'})
			else:
				# 유저를 추가
				saltstring = Salt()
				user = User()
				user.email = req_email
				user.password = hashlib.sha256(self.request.get('password') + saltstring).hexdigest() # Hash 후 저장
				user.name = self.request.get('name')
				user.address = self.request.get('address')
				user.number = self.request.get('number')
				user.salt = saltstring # Salt
				user.isSeller = False # 판매자 False
				user.isAdmin = False # 관리자 False
				user.put()
				self.session['email'] = user.email
				self.session['name'] = user.name
				self.redirect("/")
		else:
			if "response" in str(data['error-codes']):
				Render(self, 'n_register.htm', {'err': 'reCAPTCHA가 정상적으로 확인되지 않았습니다. 다시 시도해주세요.'})
			else:
				Render(self, 'n_register.htm', {'err': '시스템 에러입니다. 잠시후 다시 시도해주세요.'})

class SellerRegisterHandler(BaseHandler):
	def get(self):
		Render(self, 'n_register_seller.htm', {})

	def post(self):
		captcha = self.request.get('g-recaptcha-response')
		url = "https://www.google.com/recaptcha/api/siteverify?secret=6Ldi6f4SAAAAAJ5WXvkKk1cSzc7L9C1CALkCnITs&response="+captcha
		chk = urllib2.urlopen(url)
		data = json.load(chk)
		if data['success']:
			# Captcha 성공
			req_email = self.request.get('email')
			query = db.Query(User)
			q = query.filter("email ==", req_email)
			if q.count() == 1:
				# 유저가 존재하는 경우
				u = q.get()
				req_pw = self.request.get('password')
				# 로그인 시도
				if u.password == hashlib.sha256(req_pw + u.salt).hexdigest():
					self.session['email'] = req_email
					if u.isSeller:
						self.session['seller'] = 'true'
					self.redirect("/")
				else:
				# 만약 아니라면 이미 있는 계정이라고 form update
					Render(self, 'n_register_seller.htm', {'err': '이미 있는 계정입니다.'})
			else:
				# 유저를 추가
				saltstring = Salt()
				user = User()
				user.email = req_email
				user.password = hashlib.sha256(self.request.get('password') + saltstring).hexdigest() # Hash 후 저장
				user.name = self.request.get('name')
				user.address = self.request.get('address')
				user.number = self.request.get('number')
				user.salt = saltstring # Salt
				user.isSeller = True # 판매자 False
				user.isAdmin = False # 관리자 False
				user.put()
				self.session['email'] = user.email
				self.session['name'] = user.name
				self.redirect("/")
		else:
			if "response" in str(data['error-codes']):
				Render(self, 'n_register_seller.htm', {'err': 'reCAPTCHA가 정상적으로 확인되지 않았습니다. 다시 시도해주세요.'})
			else:
				Render(self, 'n_register_seller.htm', {'err': '시스템 에러입니다. 잠시후 다시 시도해주세요.'})

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
				if u.isSeller:
					self.session['seller'] = 'true'
				self.redirect("/")
			else:
				Render(self, 'n_index.htm', {'err':'없는 계정이거나 비밀번호가 맞지 않습니다.'})
		else:
			Render(self, 'n_index.htm', {'err':'없는 계정이거나 비밀번호가 맞지 않습니다.'})

class LogoutHandler(BaseHandler):
	def get(self):
		if self.session.get('email'):
			self.session.pop('email')
			self.session.clear()
		self.redirect("/")

	def post(self):
		if self.session.get('email'):
			self.session.pop('email')
			self.session.clear()
		self.redirect("/")

class UserpwHandler(BaseHandler):
	def get(self):
		Render(self, 'n_findpw.htm', {})

	def post(self):
		captcha = self.request.get('g-recaptcha-response')
		url = "https://www.google.com/recaptcha/api/siteverify?secret=6Ldi6f4SAAAAAJ5WXvkKk1cSzc7L9C1CALkCnITs&response="+captcha
		chk = urllib2.urlopen(url)
		data = json.load(chk)
		if data['success']:
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
				Render(self, 'n_findpw.htm', {'err':'입력하신 이메일에 해당되는 계정을 찾을 수 없습니다. 확인하신 다음 다시 시도해주세요.'})
		else:
			if "response" in str(data['error-codes']):
				Render(self, 'n_findpw.htm', {'err': 'Captcha가 정상적으로 확인되지 않았습니다. 다시 시도해주세요.'})
			else:
				Render(self, 'n_findpw.htm', {'err': '시스템 에러입니다. 잠시후 다시 시도해주세요.'})

class MypageHandler(BaseHandler):
    def get(self):
		if self.session.get('email'):
			Render(self, 'n_mypage.htm', {})
		else:
			Render(self, 'n_index.htm', {})

class MainHandler(BaseHandler):
    def get(self):
		Render(self, 'n_index.htm', {})

class BrandHandler(BaseHandler):
    def get(self):
		if self.session.get('email'):
			Render(self, 'n_brand.htm', {})
		else:
			Render(self, 'n_index.htm', {})

class LocalHandler(BaseHandler):
    def get(self):
		if self.session.get('email'):
			Render(self, 'n_local.htm', {})
		else:
			Render(self, 'n_index.htm', {})

class OrderBucketHandler(BaseHandler):
    def get(self):
		if self.session.get('email'):
			Render(self, 'n_order_bucket.htm', {})
		else:
			Render(self, 'n_index.htm', {})

class SellerNewChcieknHandler(BaseHandler):
    def get(self):
		if self.session.get('email') and self.session.get('seller'):
			Render(self, 'n_seller_add.htm', {})
		else:
			Render(self, 'n_index.htm', {})

class TermsHandler(BaseHandler):
    def get(self):
		Render(self, 'terms.htm', {})

class SecurityHandler(BaseHandler):
    def get(self):
		Render(self, 'security.htm', {})

config = {}

config['webapp2_extras.sessions'] = {
    'secret_key': 'dc458da48fa171a071a547a07d8e13f25dd2ed714a03f4d6fbae331e6b711139',
}

app = webapp2.WSGIApplication([('/login', LoginHandler), ('/register', RegisterHandler), ('/register/seller', SellerRegisterHandler), ('/logout', LogoutHandler), ('/findpw', UserpwHandler), ('/chicken/brand', BrandHandler), ('/chicken/local', LocalHandler), ('/order/bucket', OrderBucketHandler), ('/mypage', MypageHandler), ('/seller/add', SellerNewChcieknHandler), ('/terms', TermsHandler), ('/security', SecurityHandler), ('/.*', MainHandler)], debug=True, config=config)

def main():
	app.run()

if __name__ == '__main__':
	main()