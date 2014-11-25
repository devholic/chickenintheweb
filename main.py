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

class RegisterHandler(webapp2.RequestHandler):
	def get(self):
		path = os.path.join(os.path.dirname(__file__), 'templates/error.htm')
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

class LoginHandler(webapp2.RequestHandler):
	def get(self):
		path = os.path.join(os.path.dirname(__file__), 'templates/index.htm')
		self.response.write(template.render(path,''))

	def post(self):
		email = self.request.get('email')
		password = self.request.get('password')
		query = db.Query(User)
		path = os.path.join(os.path.dirname(__file__), 'templates/error.htm')
		q = query.filter("email ==",email)
		if q.count() == 1:
			# 유저가 존재하는 경우
			u = q.get()
			if u.password==hashlib.sha256(password + u.salt).hexdigest():
				self.response.write(template.render(path,{'errorcode':'200'}))
			else:
				self.response.write(template.render(path,{'errorcode':'401'}))
		else:
			self.response.write(template.render(path,{'errorcode':'400'}))

class MainHandler(webapp2.RequestHandler):
    def get(self):
    	path = os.path.join(os.path.dirname(__file__), 'templates/index.htm')
        self.response.write(template.render(path,''))

app = webapp2.WSGIApplication([('/login', LoginHandler), ('/register', RegisterHandler),
    ('/.*', MainHandler)
], debug=True)
