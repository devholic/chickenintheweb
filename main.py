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
from google.appengine.ext import db
from google.appengine.ext.webapp import template

class User(db.Model):
	email = db.StringProperty(required=True) # 이메일
	password = db.StringProperty(required=True) # 비밀번호
	name = db.StringProperty(required=False) # 이름
	address = db.StringProperty(required=False) # 주소
	number = db.StringProperty(required=False) # 전화번호
	isFacebookAccount = db.BooleanProperty(required=True) # 페이스북 계정인지 
	salt = db.StringProperty(required=True) # Salt
	created_at = db.DateProperty(required=True) # Created At
	isSeller = db.BooleanProperty(required=True)
	isAdmin = db.BooleanProperty(required=True)

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
		if len(query.filter("email ==",req_email).get()) == 1:
			# 유저가 존재하는 경우
			# 유저를 삭제 
			req_pw = self.request.get('password')
		else:
			# 유저를 추가
			req_pw = self.request.get('password')
			user = User(email=req_email,password=req_pw,isFacebookAccount=False,salt=saltstring)
			user.created_at = datetime.datetime.now().date()
			user.isSeller = False
			user.isAdmin = False
			user.put()
			#u = User(email=req_email,)

class LoginHandler(webapp2.RequestHandler):
	def get(self):
		path = os.path.join(os.path.dirname(__file__), 'templates/index.htm')
		self.response.write(template.render(path,''))

	def post(self):
		email = self.request.get('email')
		password = self.request.get('password')
		logging.info('Checking account='+email+' pw='+password)
		query = db.Query(User)
		path = os.path.join(os.path.dirname(__file__), 'templates/error.htm')
		if query.filter("email ==",email).count() == 1:
			# 유저가 존재하는 경우
			self.response.write(template.render(path,{'errorcode':'200'}))
		else:
			self.response.write(template.render(path,{'errorcode':'400'}))

class MainHandler(webapp2.RequestHandler):
    def get(self):
    	path = os.path.join(os.path.dirname(__file__), 'templates/index.htm')
        self.response.write(template.render(path,''))

app = webapp2.WSGIApplication([('/login', LoginHandler), ('/register', RegisterHandler),
    ('/.*', MainHandler)
], debug=True)
