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
from google.appengine.api import images
from google.appengine.ext import db
from google.appengine.ext.webapp import template

class User(db.Model): # 유저
	email = db.StringProperty() # 이메일
	password = db.StringProperty() # 비밀번호
	name = db.StringProperty() # 이름 / 업체명
	address = db.StringProperty() # 주소
	number = db.StringProperty() # 전화번호
	salt = db.StringProperty() # Salt
	created_at = db.DateTimeProperty(auto_now_add=True) # Entity 생성시간
	isSeller = db.BooleanProperty() # 판매자인지
	isBrandSeller = db.BooleanProperty() # 프랜차이즈 기업 회원인지
	isAdmin = db.BooleanProperty() # 관리자인지

class Store(db.Model): # 스토어
	seller = db.ReferenceProperty() # 판매자 (User)
	intro = db.StringProperty() # 한줄소개 
	thumb = db.BlobProperty() # 썸네일
	isBrand = db.BooleanProperty() # 브랜드 치킨인지
	created_at = db.DateTimeProperty(auto_now_add=True) # Entity 생성시간

class UserOrder(db.Model):
	buyer = db.ReferenceProperty(User)
	detail = db.StringProperty()
	price = db.IntegerProperty()
	created_at = db.DateTimeProperty(auto_now_add=True) # Entity 생성시간

class SellerOrder(db.Model):
	order = db.ReferenceProperty(UserOrder)
	seller = db.ReferenceProperty(User)
	status = db.IntegerProperty()
	created_at = db.DateTimeProperty()

class Chicken(db.Model): # 치킨
	seller = db.ReferenceProperty() # 판매자 (Store)
	name = db.StringProperty() # 치킨 이름
	quantity = db.IntegerProperty() # 수량
	price = db.IntegerProperty() # 가격
	intro = db.StringProperty() # 한줄소개
	thumb = db.BlobProperty() # 썸네일
	created_at = db.DateTimeProperty(auto_now_add=True) # Entity 생성시간

class ChickenOption(db.Model): # 치킨 옵션
	chicken = db.ReferenceProperty() # 치킨 
	name = db.StringProperty() # 옵션 이름
	quantity = db.IntegerProperty() # 수량
	price = db.IntegerProperty() # 가격

class ChickenImage(db.Model): # 치킨 이미지
	chicken = db.ReferenceProperty() # 치킨
	f = db.BlobProperty() # 치킨 파일 

class UserRecovery(db.Model): # 유저 비밀번호 찾기용 복구 코드 관리 Model
	email = db.StringProperty() # 이메일
	code = db.StringProperty() # 코드
	expire = db.IntegerProperty() # 만료시간 (ms)

class Wallet(db.Model): # 지갑 모델
	user = db.ReferenceProperty() # 유저
	money = db.IntegerProperty() # 월렛 잔고

def Render(handler, path = "n_index.htm", values ={}): # 템플릿 렌더링 
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

def OrderStatusString(s):
	if s == 0:
		return '[접수 대기]'
	elif s == 1:
		return '[접수 완료]'
	elif s == 2:
		return '[요리중]'
	elif s == 3:
		return '[배달중]'
	elif s == 4:
		return '[배달 완료]'
	else:
		return '[오류]'

def Salt(): # 비밀번호 암호화용 Salt 생성 메소드
	alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	saltstring = "" # 결과를 담을 스트링 
	for i in range(16): # Salt는 16자리
		saltstring+=random.choice(alphabet)
	return saltstring # 생성된 Salt를 return

class BaseHandler(webapp2.RequestHandler): # Webapp2에서 제공하는 Session을 사용하기 위한 
    def dispatch(self):
        # 요청에 대한 session_store 가져오기
        self.session_store = sessions.get_store(request=self.request)
        try:
            # Request dispatch
            webapp2.RequestHandler.dispatch(self)
        finally:
            # 세션 저장
            self.session_store.save_sessions(self.response)

    @webapp2.cached_property
    def session(self):
        # 기본 Cookie 키를 사용하는 세션 리턴
        return self.session_store.get_session()

class RegisterHandler(BaseHandler): # 회원가입 핸들러
	# get method 
	def get(self):
		# 회원가입 페이지 보여주기
		Render(self, 'n_register.htm', {})
	# post method
	def post(self):
		captcha = self.request.get('g-recaptcha-response') # recaptcha response 받기 
		url = "https://www.google.com/recaptcha/api/siteverify?secret=6Ldi6f4SAAAAAJ5WXvkKk1cSzc7L9C1CALkCnITs&response="+captcha # recaptcha response 검증 URL
		chk = urllib2.urlopen(url) # 검증 url open
		data = json.load(chk) # response를 json으로 파싱 
		if data['success']:
			# recaptcha 성공
			req_email = self.request.get('email') # 사용자 입력 이메일 가져오기
			query = db.Query(User) # 유저 쿼리
			q = query.filter("email ==", req_email) # 쿼리 필터링
			if q.count() == 1:
				# 유저가 존재하는 경우
				u = q.get() # 유저 가져오기
				req_pw = self.request.get('password') # 사용자 입력 비밀번호 가져오기 
				# 로그인 시도
				if u.password == hashlib.sha256(req_pw + u.salt).hexdigest(): # 입력된 비밀번호 hash값과 Datastore에 저장된 유저 비밀번호 해쉬값 비교
					self.session['email'] = req_email # 세션에 이메일 추가
					self.session['name'] = u.name # 세션에 이름 추가
					if u.isSeller: # 판매자인경우
						self.session['seller'] = 'true' # 판매자 속성 추가
					self.redirect("/") # Main으로 redirect (로그인 처리 완료)
				else:
				# 만약 아니라면 이미 있는 계정이라고 alert
					Render(self, 'n_register.htm', {'err': '이미 있는 계정입니다.'})
			else:
				# 유저가 없는 경우 유저를 추가
				saltstring = Salt() # salt 생성
				user = User() # User 생성 
				user.email = req_email # 이메일 가져오기
				user.password = hashlib.sha256(self.request.get('password') + saltstring).hexdigest() # 비밀번호 Hash 후 저장
				user.name = self.request.get('name') # 사용자 입력 이름 가져오기 
				user.address = self.request.get('address') # 사용자 입력 주소 가져오기 
				user.number = self.request.get('number') # 사용자 입력 번호 가져오기 
				user.salt = saltstring # salt
				user.isSeller = False # 판매자 False
				user.isBrandSeller = False # 프랜차이즈 판매자 False
				user.isAdmin = False # 관리자 False
				k = user.put() # User 저장
				w = Wallet() # 월렛 생성
				w.user = k # Return 받은 User key 지정
				w.money = 10000 # 기본 적립금 만원
				w.put() # 월렛 저장
				self.session['email'] = user.email # 세션에 이메일 추가
				self.session['name'] = user.name # 세션에 이름 추가
				self.redirect("/") # Main으로 redirect (로그인 처리 완료)
		else:
			# recaptcha 실패
			if "response" in str(data['error-codes']): # 에러코드 체크
				# recaptcha 에러인 경우
				Render(self, 'n_register.htm', {'err': 'reCAPTCHA가 정상적으로 확인되지 않았습니다. 다시 시도해주세요.'}) 
			else:
				# 그 외의 에러인 경우
				Render(self, 'n_register.htm', {'err': '시스템 에러입니다. 잠시후 다시 시도해주세요.'})

class SellerRegisterHandler(BaseHandler): # 판매자 회원가입 핸들러
	# get method 
	def get(self):
		# 판매자 회원가입 페이지 보여주기
		Render(self, 'n_register_seller.htm', {})
	# post method 
	def post(self):
		captcha = self.request.get('g-recaptcha-response') # recaptcha response 받기
		url = "https://www.google.com/recaptcha/api/siteverify?secret=6Ldi6f4SAAAAAJ5WXvkKk1cSzc7L9C1CALkCnITs&response="+captcha # recaptcha response 검증 URL
		chk = urllib2.urlopen(url) # 검증 url open
		data = json.load(chk) # response를 json으로 파싱 
		if data['success']:
			# Captcha 성공
			req_email = self.request.get('email') # 사용자 입력 이메일 가져오기
			query = db.Query(User) # 유저 쿼리
			q = query.filter("email ==", req_email) # 쿼리 필터링
			if q.count() == 1:
				# 유저가 존재하는 경우
				u = q.get() # 유저 가져오기
				req_pw = self.request.get('password') # 사용자 입력 비밀번호 가져오기 
				# 로그인 시도
				if u.password == hashlib.sha256(req_pw + u.salt).hexdigest(): # 입력된 비밀번호 hash값과 Datastore에 저장된 유저 비밀번호 해쉬값 비교
					self.session['email'] = req_email # 세션에 이메일 추가
					self.session['name'] = u.name # 세션에 이름 추가
					if u.isSeller: # 판매자인경우
						self.session['seller'] = 'true' # 판매자 속성 추가
					self.redirect("/") # Main으로 redirect (로그인 처리 완료)
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
				if self.request.get('brand'):
					user.isBrandSeller = True # 판매자 False
				else:
					user.isBrandSeller = False # 판매자 False
				uk = user.put()
				s = Store()
				s.seller = uk
				s.isBrand = user.isBrandSeller
				s.intro = unicode("치킨인더웹 페이지",'utf-8')
				s.put()
				w = Wallet()
				w.user = uk # Return 받은 User key 지정
				w.money = 0 # 기본 판매액 0원 
				w.put() # 월렛 저장 
				self.session['email'] = user.email # 세션에 이메일 추가
				self.session['name'] = user.name # 세션에 이름 추가
				self.session['seller'] = 'true' # 세션에 판매자 속성 추가
				self.redirect("/") # Main으로 redirect (로그인 처리 완료)
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
				self.session['name'] = u.name
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
		if self.session.get('name'):
			self.session.pop('name')
		if self.session.get('seller'):
			self.session.pop('seller')
		if self.session.get('bucket'):
			self.session.pop('bucket')
		self.session.clear()
		self.redirect("/")

	def post(self):
		if self.session.get('email'):
			self.session.pop('email')
		if self.session.get('name'):
			self.session.pop('name')
		if self.session.get('seller'):
			self.session.pop('seller')
		if self.session.get('bucket'):
			self.session.pop('bucket')
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
		if self.session.get('email') and not self.session.get('seller'):
			if self.request.get('orderid'):
				o = UserOrder.get_by_id(int(self.request.get("orderid")))
				sq = db.Query(SellerOrder)
				sq.filter('order', o.key())
				so = sq.fetch(limit=(sq.count()))
				seller_email_list = []
				seller_status_list = []
				for sindex in range(len(so)):
					seller_email_list.append(so[sindex].seller.email)
					seller_status_list.append(int(so[sindex].status))
				bucketlist = json.loads(o.detail)
				renderlist = []
				finalprice = 0
				for bucket in bucketlist:
					isSeller = 0
					for index in range(len(bucket)):
						if index == 0:
							chicken = Chicken.get_by_id(int(bucket[index]['chicken']))
							if chicken.seller.email in seller_email_list:
								oidx = seller_email_list.index(chicken.seller.email)
								logging.info(OrderStatusString(seller_status_list[oidx]))
								chicken.orderstatus = OrderStatusString(seller_status_list[oidx])
							chicken.uquantity = bucket[index]['chicken_quantity']
							chicken.pricestr = '₩'+format(chicken.price,',d')
							if not chicken.uquantity == 0:
								finalprice += (chicken.price * int(chicken.uquantity))
							renderlist.append(chicken)
						else:
							option = ChickenOption.get_by_id(int(bucket[index]['option']))
							option.uquantity = bucket[index]['option_quantity']
							option.pricestr = '₩'+format(option.price,',d')
							if not option.uquantity == 0:
								finalprice += (option.price * int(option.uquantity))	
							renderlist.append(option)
				finalpricestr = '₩'+format(finalprice,',d')
				Render(self, 'n_mypage_order_detail.htm', {'bucketlist':renderlist,'bucketprice':finalpricestr, 'user':o.buyer})
			else:
				uq = db.Query(User)
				uq.filter("email =", self.session.get('email'))
				u = uq.get()
				wq = db.Query(Wallet)
				wq.filter("user =", u.key())
				w = wq.get()
				oq = db.Query(UserOrder)
				oq.filter("buyer =", u.key())
				oq.order("-created_at")
				o = oq.fetch(limit=(oq.count()))
				w.moneystr = '₩'+format(w.money,',d')
				Render(self, 'n_mypage.htm', {'wallet':w,'orderlist':o})
		else:
			if self.session.get('seller'):
				uq = db.Query(User)
				uq.filter("email =", self.session.get('email'))
				u = uq.get()
				wq = db.Query(Wallet)
				wq.filter("user =", u.key())
				w = wq.get()
				w.moneystr = '₩'+format(w.money,',d')
				sq = db.Query(Store)
				sq.filter("seller =",u.key())
				s = sq.get()
				Render(self, 'n_mypage.htm', {'wallet':w, 'store':s})
			else:
				self.redirect('/')

	def post(self):
		if self.session.get('email') and not self.session.get('seller'):
			if self.request.get('money'):
				captcha = self.request.get('g-recaptcha-response')
				url = "https://www.google.com/recaptcha/api/siteverify?secret=6Ldi6f4SAAAAAJ5WXvkKk1cSzc7L9C1CALkCnITs&response="+captcha
				chk = urllib2.urlopen(url)
				data = json.load(chk)
				if data['success']:
					uq = db.Query(User)
					uq.filter("email =", self.session.get('email'))
					u = uq.get()
					wq = db.Query(Wallet)
					wq.filter("user =", u.key())
					w = wq.get()
					w.money += int(self.request.get('money'))
					w.put()
					w.moneystr = '₩'+format(w.money,',d')
					self.get()
				else:
					self.redirect('/error')
			else:
				self.get()
		else:
			if self.session.get('email') and self.session.get('seller'):
				if self.request.get('update'):
					uq = db.Query(User)
					uq.filter("email =", self.session.get('email'))
					u = uq.get()
					sq = db.Query(Store)
					sq.filter("seller =", u.key())
					s = sq.get()
					if self.request.get('intro'):
						s.intro = self.request.get('intro')
					if self.request.get('thumbimage'):
						s.thumb = db.Blob(self.request.get('thumbimage'))
					s.put()
					self.get()
				else:
					self.get()
			else:
				self.get()


class MainHandler(BaseHandler):
	def get(self):
		if self.session.get('email') and not self.session.get('seller'):
			query = db.Query(Chicken)
			query.order("-created_at")
			result = query.fetch(limit=12)
			for c in result:
				# https://www.python.org/dev/peps/pep-0378/
				c.pricestr = '₩'+format(c.price,',d')
			Render(self, 'n_index.htm', {'chicken_list':result})
		else:
			Render(self, 'n_index.htm', {})

class BrandHandler(BaseHandler):
	def get(self):
		if self.session.get('email') and not self.session.get('seller'):
			if self.request.get("cid"):
				q = Chicken.get_by_id(int(self.request.get("cid")))
				if q:
					q.pricestr = '₩'+format(q.price,',d')
					oq = db.Query(ChickenOption)
					oq.filter("chicken =", q.key())
					o = oq.fetch(limit=(oq.count()))
					for op in o:
						# https://www.python.org/dev/peps/pep-0378/
						op.pricestr = '₩'+format(op.price,',d')
					iq = db.Query(ChickenImage)
					iq.filter("chicken =", q.key())
					i = iq.fetch(limit=5)
					if len(o) != 0:
						if len(i) != 0:
							Render(self, 'n_chicken.htm',{'chicken':q,'option_list':o,'image_list':i})
						else:
							Render(self, 'n_chicken.htm',{'chicken':q,'option_list':o})
					elif len(i) != 0:
						Render(self, 'n_chicken.htm',{'chicken':q,'image_list':i})
					else:
						Render(self, 'n_chicken.htm',{'chicken':q})
				else:
					query = db.Query(Store)
					query.filter("isBrand =", True)
					result = query.fetch(limit=(query.count()))
					Render(self, 'n_store.htm', {'request':'storelist','store_list':result, 'type':'brand'})
			elif self.request.get("id"):
				q = Store.get_by_id(int(self.request.get("id")))
				if q:
					cquery = db.Query(Chicken)
					cquery.filter("seller =", q.seller)
					result = cquery.fetch(limit=(cquery.count()))
					for c in result:
						# https://www.python.org/dev/peps/pep-0378/
						c.pricestr = '₩'+format(c.price,',d')
					Render(self, 'n_store.htm', {'request':'store','store':q, 'chicken_list':result})
				else:
					query = db.Query(Store)
					query.filter("isBrand =", True)
					result = query.fetch(limit=(query.count()))
					Render(self, 'n_store.htm', {'request':'storelist','store_list':result, 'type':'brand'})
			else:
				query = db.Query(Store)
				query.filter("isBrand =", True)
				result = query.fetch(limit=(query.count()))
				Render(self, 'n_store.htm', {'request':'storelist','store_list':result, 'type':'brand'})
		else:
			Render(self, 'n_index.htm', {})

class LocalHandler(BaseHandler):
	def get(self):
		if self.session.get('email') and not self.session.get('seller'):
			if self.request.get("cid"):
				q = Chicken.get_by_id(int(self.request.get("cid")))
				if q:
					q.pricestr = '₩'+format(q.price,',d')
					oq = db.Query(ChickenOption)
					oq.filter("chicken =", q.key())
					o = oq.fetch(limit=(oq.count()))
					for op in o:
						# https://www.python.org/dev/peps/pep-0378/
						op.pricestr = '₩'+format(op.price,',d')
					iq = db.Query(ChickenImage)
					iq.filter("chicken =", q.key())
					i = iq.fetch(limit=5)
					if len(o) != 0:
						if len(i) != 0:
							Render(self, 'n_chicken.htm',{'chicken':q,'option_list':o,'image_list':i})
						else:
							Render(self, 'n_chicken.htm',{'chicken':q,'option_list':o})
					elif len(i) != 0:
						Render(self, 'n_chicken.htm',{'chicken':q,'image_list':i})
					else:
						Render(self, 'n_chicken.htm',{'chicken':q})
				else:
					query = db.Query(Store)
					query.filter("isBrand =", False)
					result = query.fetch(limit=(query.count()))
					Render(self, 'n_store.htm', {'request':'storelist','store_list':result, 'type':'local'})
			elif self.request.get("id"):
				q = Store.get_by_id(int(self.request.get("id")))
				if q:
					cquery = db.Query(Chicken)
					cquery.filter("seller =", q.seller)
					result = cquery.fetch(limit=(cquery.count()))
					for c in result:
						# https://www.python.org/dev/peps/pep-0378/
						c.pricestr = '₩'+format(c.price,',d')
					Render(self, 'n_store.htm', {'request':'store','store':q, 'chicken_list':result})
				else:
					query = db.Query(Store)
					query.filter("isBrand =", False)
					result = query.fetch(limit=(query.count()))
					Render(self, 'n_store.htm', {'request':'storelist','store_list':result, 'type':'local'})
			else:
				query = db.Query(Store)
				query.filter("isBrand =", False)
				result = query.fetch(limit=(query.count()))
				Render(self, 'n_store.htm', {'request':'storelist','store_list':result, 'type':'local'})
		else:
			Render(self, 'n_index.htm', {})

class OrderBucketHandler(BaseHandler):
	def get(self):
		if self.session.get('email') and not self.session.get('seller'):
			if self.request.get('clear'):
				if self.session.get('bucket'):
					self.session.pop('bucket')
				self.redirect('/order/bucket')

			if self.request.get('remove'):
				target = int(self.request.get('remove'))
				jstr = self.session.get('bucket')
				bucketlist = json.loads(jstr)
				parentlist = []
				finalprice = 0
				item = 0
				isChicken = False
				for bucket in bucketlist:
					childlist = []
					for index in range(len(bucket)):
						if index == 0:
							if item == target:
								isChicken = True
								item+=1
							else:
								isChicken = False
								chicken = {'chicken':bucket[index]['chicken'],'chicken_quantity':bucket[index]['chicken_quantity']}
								item+=1
								childlist.append(chicken)
						else:
							if isChicken == True:
								item+=1
							elif item == target:
								item+=1
							else:
								option = {'option':bucket[index]['option'],'option_quantity':bucket[index]['option_quantity']}
								item+=1
								childlist.append(option)
					parentlist.append(childlist)
				j = json.dumps(parentlist)
				self.session['bucket'] = j
				self.redirect('/order/bucket')

			if self.request.get('change'):
				if self.request.get('value'):
					v = self.request.get('value')
					target = int(self.request.get('change'))
					jstr = self.session.get('bucket')
					bucketlist = json.loads(jstr)
					parentlist = []
					finalprice = 0
					item = 0
					isChicken = False
					for bucket in bucketlist:
						childlist = []
						for index in range(len(bucket)):
							if index == 0:
								if item == target:
									chicken = {'chicken':bucket[index]['chicken'],'chicken_quantity':v}
									item+=1
								else:
									chicken = {'chicken':bucket[index]['chicken'],'chicken_quantity':bucket[index]['chicken_quantity']}
									item+=1
								childlist.append(chicken)
							else:
								if item == target:
									option = {'option':bucket[index]['option'],'option_quantity':v}
									item+=1
								else:
									option = {'option':bucket[index]['option'],'option_quantity':bucket[index]['option_quantity']}
									item+=1
								childlist.append(option)
						parentlist.append(childlist)
					j = json.dumps(parentlist)
					self.session['bucket'] = j
					self.redirect('/order/bucket')

			if self.session.get('bucket'):
				jstr = self.session.get('bucket')
				bucketlist = json.loads(jstr)
				renderlist = []
				finalprice = 0
				item = 0
				soldout = 0
				for bucket in bucketlist:
					for index in range(len(bucket)):
						if index == 0:
							chicken = Chicken.get_by_id(int(bucket[index]['chicken']))
							chicken.uquantity = bucket[index]['chicken_quantity']
							chicken.pricestr = '₩'+format(chicken.price,',d')
							chicken.index = item
							item+=1
							if not chicken.quantity == 0:
								finalprice += (chicken.price * int(chicken.uquantity))
							else:
								soldout = 1
							renderlist.append(chicken)
						else:
							option = ChickenOption.get_by_id(int(bucket[index]['option']))
							option.uquantity = bucket[index]['option_quantity']
							option.pricestr = '₩'+format(option.price,',d')
							option.index = item
							item+=1
							if not option.quantity == 0:
								finalprice += (option.price * int(option.uquantity))
							else:
								soldout = 1
							renderlist.append(option)
				finalpricestr = '₩'+format(finalprice,',d')
				if finalprice == 0:
					Render(self, 'n_order_bucket.htm', {'bucketlist':renderlist,'bucketprice':finalpricestr,'empty':'true', 'soldout':soldout})
				else:
					Render(self, 'n_order_bucket.htm', {'bucketlist':renderlist,'bucketprice':finalpricestr, 'soldout':soldout})
			else:
				finalpricestr = '₩'+format(0,',d')
				Render(self, 'n_order_bucket.htm', {'bucketprice':finalpricestr,'empty':'true'})
		else:
			self.redirect('/')

	def post(self):
		if self.session.get('email') and not self.session.get('seller'):
			if self.session.get('bucket'):
				jstr = self.session.get('bucket')
				bucket = json.loads(jstr)
				olist = []
				c = self.request.get("chicken")
				cq = self.request.get("chicken_quantity")
				chicken = {'chicken':c,'chicken_quantity':cq}
				olist.append(chicken)
				i = self.request.get_all('item')
				q = self.request.get_all('quantity')
				if i:
					for index in range(len(i)):
						option = {'option':i[index],'option_quantity':q[index]}
						olist.append(option)
				bucket.append(olist)
				j = json.dumps(bucket)
				self.session['bucket'] = j
				self.get()
			else:
				olist = []
				c = self.request.get("chicken")
				cq = self.request.get("chicken_quantity")
				chicken = {'chicken':c,'chicken_quantity':cq}
				olist.append(chicken)
				i = self.request.get_all('item')
				q = self.request.get_all('quantity')
				if i:
					for index in range(len(i)):
						option = {'option':i[index],'option_quantity':q[index]}
						olist.append(option)
				bucket = []
				bucket.append(olist)
				j = json.dumps(bucket)
				self.session['bucket'] = j
				self.get()
		else:
			self.redirect('/')

class PurchaseHandler(BaseHandler):
	def get(self):
		if self.session.get('email') and not self.session.get('seller'):
			if self.session.get('bucket'):
				jstr = self.session.get('bucket')
				bucketlist = json.loads(jstr)
				renderlist = []
				finalprice = 0
				item = 0
				for bucket in bucketlist:
					for index in range(len(bucket)):
						if index == 0:
							chicken = Chicken.get_by_id(int(bucket[index]['chicken']))
							chicken.uquantity = bucket[index]['chicken_quantity']
							chicken.pricestr = '₩'+format(chicken.price,',d')
							chicken.index = item
							item+=1
							if not chicken.quantity == 0:
								finalprice += (chicken.price * int(chicken.uquantity))
							renderlist.append(chicken)
						else:
							option = ChickenOption.get_by_id(int(bucket[index]['option']))
							option.uquantity = bucket[index]['option_quantity']
							option.pricestr = '₩'+format(option.price,',d')
							option.index = item
							item+=1
							if not option.quantity == 0:
								finalprice += (option.price * int(option.uquantity))
							renderlist.append(option)
				pricestr = '₩'+format(finalprice,',d')
				uq = db.Query(User)
				uq.filter("email =", self.session.get('email'))
				u = uq.get()
				wq = db.Query(Wallet)
				wq.filter("user =", u.key())
				w = wq.get()
				w.afterpay = w.money - finalprice
				w.afterpaystr = '₩'+format(w.afterpay,',d')
				w.moneystr = '₩'+format(w.money,',d')
				Render(self, 'n_purchase.htm', {'request':'bucket','bucketlist':renderlist, 'finalprice':pricestr, 'user':u, 'wallet':w})
			else:
				self.redirect('/order/bucket')
		else:
			self.redirect('/')

	def post(self):
		if self.session.get('email') and not self.session.get('seller'):
			if self.request.get('checkout'):
				checkout_type = self.request.get('checkout')
				# 유저 가져오기
				uq = db.Query(User)
				uq.filter("email =", self.session.get('email'))
				u = uq.get()
				wq = db.Query(Wallet)
				wq.filter("user =", u.key())
				w = wq.get() 
				if checkout_type == 'direct':
					logging.info('direct')
					parentlist = []
					childlist = []
					optionlist_check = []
					chicken = Chicken.get_by_id(int(self.request.get("chicken")))
					cq = int(self.request.get("chicken_quantity"))
					if cq>chicken.quantity:
						self.redirect('/error')
					else:
						price = chicken.price * cq
						co = {'chicken': int(self.request.get("chicken")),'chicken_quantity':cq}
						childlist.append(co)
						i = self.request.get_all('option')
						q = self.request.get_all('option_quantity')
						if i:
							for index in range(len(i)): # 입력된 id int형으로 바꿔주기
								i[index] = int(i[index])
							optionlist = ChickenOption.get_by_id(i) # 해당되는 모든 옵션 리스트 가져오기
							optionlist_check = optionlist
							index = 0
							for option in optionlist:
								if int(q[index])>option.quantity:
									logging.info('error_oquantity')
									self.redirect('/error')
								else:
									option.uquantity = int(q[index])
									option.finalprice = option.uquantity * option.price
									oo = {'option': int(i[index]),'option_quantity': int(q[index])}
									childlist.append(oo)
									price += option.finalprice
									index += 1
						if w.money - price >= 0:
							# 결제 처리
							chicken.quantity = chicken.quantity - cq
							chicken.put()
							wsq = db.Query(Wallet)
							wsq.filter("user =", chicken.seller)
							sw = wsq.get()
							sw.money = sw.money + price
							sw.put()
							if i:
								index = 0
								for option in optionlist:
									option.quantity = option.quantity - int(q[index])
									option.put()
							parentlist.append(childlist)
							j = json.dumps(parentlist)
							order = UserOrder()
							order.buyer = u.key()
							order.detail = j
							order.price = price
							ok = order.put()
							so = SellerOrder()
							so.seller = chicken.seller
							so.order = ok
							so.status = 0
							so.created_at = order.created_at
							so.put()
							w.money = w.money - price
							w.put()
							self.redirect('/mypage')
						else:
							self.redirect('/mypage')
				else:
					# 장바구니 결제
					jstr = self.session.get('bucket')
					bucketlist = json.loads(jstr)
					renderlist = []
					sellerlist = []
					moneylist = []
					seller_email = []
					itemlist = []
					finalprice = 0
					for bucket in bucketlist:
						for index in range(len(bucket)):
							if index == 0:
								chicken = Chicken.get_by_id(int(bucket[index]['chicken']))
								itemlist.append(chicken)
								chicken.uquantity = bucket[index]['chicken_quantity']
								if not chicken.seller.email in seller_email:
									sellerlist.append(chicken.seller)
									seller_email.append(chicken.seller.email)
									moneylist.append((chicken.price * int(chicken.uquantity)))
								else:
									idx = seller_email.index(chicken.seller.email)	
									moneylist[idx] += (chicken.price * int(chicken.uquantity))
								finalprice += (chicken.price * int(chicken.uquantity))
							else:
								option = ChickenOption.get_by_id(int(bucket[index]['option']))
								itemlist.append(option)
								option.uquantity = bucket[index]['option_quantity']
								option.pricestr = '₩'+format(option.price,',d')
								if option.chicken.seller.email in seller_email:
									idx = seller_email.index(option.chicken.seller.email)	
									moneylist[idx] += (option.price * int(option.uquantity))
								finalprice += (option.price * int(option.uquantity))
					if w.money - finalprice >= 0:
						for bucket in bucketlist:
							for index in range(len(bucket)):
								if index == 0:
									itemlist[index].quantity = itemlist[index].quantity - int(bucket[index]['chicken_quantity'])
									itemlist[index].put()
								else:
									itemlist[index].quantity = itemlist[index].quantity - int(bucket[index]['option_quantity'])
									itemlist[index].put()
						order = UserOrder()
						order.buyer = u.key()
						order.detail = jstr
						order.price = finalprice
						ok = order.put()
						for i in sellerlist:
							so = SellerOrder()
							so.seller = i
							so.order = ok
							so.status = 0
							so.created_at = order.created_at
							so.put()
							if i.email in seller_email:
								idx = seller_email.index(i.email)
								swq = db.Query(Wallet)
								swq.filter('user =', i)
								sw = swq.get()
								sw.money += moneylist[idx]
								sw.put()
						w.money = w.money - finalprice
						w.put()
						if self.session.get('bucket'):
							self.session.pop('bucket')
						self.redirect('/order/bucket')
					else:
						self.redirect('/error')
			else:
				i = self.request.get_all('item')
				q = self.request.get_all('quantity')
				chicken = Chicken.get_by_id(int(self.request.get("chicken")))
				chicken.uquantity = self.request.get("chicken_quantity")
				chicken.finalprice = int(chicken.uquantity) * chicken.price
				chicken.pricestr = '₩'+format(chicken.finalprice,',d')
				price = chicken.finalprice
				if i:
					for index in range(len(i)): # 입력된 id int형으로 바꿔주기
						i[index] = int(i[index])
					optionlist = ChickenOption.get_by_id(i) # 해당되는 모든 옵션 리스트 가져오기
					index = 0
					for option in optionlist:
						option.uquantity = int(q[index])
						index += 1
						option.finalprice = option.uquantity * int(option.price)
						price += option.finalprice
						option.pricestr = '₩'+format(option.finalprice,',d')
					pricestr = '₩'+format(price,',d')
					uq = db.Query(User)
					uq.filter("email =", self.session.get('email'))
					u = uq.get()
					wq = db.Query(Wallet)
					wq.filter("user =", u.key())
					w = wq.get()
					w.afterpay = w.money - price
					w.afterpaystr = '₩'+format((w.money - price),',d')
					w.moneystr = '₩'+format(w.money,',d')
					Render(self, 'n_purchase.htm', {'request':'direct','chicken':chicken, 'optionlist':optionlist, 'finalprice':pricestr, 'user':u, 'wallet':w})
				else:
					pricestr = '₩'+format(price,',d')
					uq = db.Query(User)
					uq.filter("email =", self.session.get('email'))
					u = uq.get()
					wq = db.Query(Wallet)
					wq.filter("user =", u.key())
					w = wq.get()
					w.afterpay = w.money - price
					w.afterpaystr = '₩'+format((w.money - price),',d')
					w.moneystr = '₩'+format(w.money,',d')
					Render(self, 'n_purchase.htm', {'request':'direct','chicken':chicken, 'finalprice':pricestr, 'user':u, 'wallet':w})
		else:
			self.redirect('/')

class SellerOrderHandler(BaseHandler):
	def get(self):
		if self.session.get('email') and self.session.get('seller'):
			if self.request.get('id'):
				if self.request.get('status'):
					so = SellerOrder.get_by_id(int(self.request.get("id")))
					if so.seller.email == self.session.get('email'):
						so.status = int(self.request.get("status"))
						so.put()
						self.redirect('/seller/order?id='+self.request.get('id'))
					else:
						self.redirect('/')
				else:
					so = SellerOrder.get_by_id(int(self.request.get("id")))
					bucketlist = json.loads(so.order.detail)
					renderlist = []
					finalprice = 0
					soldout = 0
					for bucket in bucketlist:
						isSeller = 0
						for index in range(len(bucket)):
							if index == 0:
								chicken = Chicken.get_by_id(int(bucket[index]['chicken']))
								chicken.uquantity = bucket[index]['chicken_quantity']
								chicken.pricestr = '₩'+format(chicken.price,',d')
								if chicken.seller.email == so.seller.email:
									if not chicken.uquantity == 0:
										finalprice += (chicken.price * int(chicken.uquantity))
									isSeller = 1
									renderlist.append(chicken)
							else:
								option = ChickenOption.get_by_id(int(bucket[index]['option']))
								option.uquantity = bucket[index]['option_quantity']
								option.pricestr = '₩'+format(option.price,',d')
								if isSeller == 1:
									if not option.uquantity == 0:
										finalprice += (option.price * int(option.uquantity))
									renderlist.append(option)
					finalpricestr = '₩'+format(finalprice,',d')
					Render(self, 'n_seller_order_detail.htm', {'status':so.status, 'oid':self.request.get("id"),'bucketlist':renderlist,'bucketprice':finalpricestr, 'user':so.order.buyer})
			else:
				query = db.Query(User)
				query.filter("email =",self.session.get('email'))
				u = query.get()
				oq = db.Query(SellerOrder)
				oq.filter("seller =",u.key())
				oq.order("-created_at")
				result = oq.fetch(limit=(oq.count()))
				Render(self, 'n_seller_order.htm', {'orderlist':result})
		else:
			self.redirect('/')

class SellerChickenHandler(BaseHandler):
	def get(self):
		if self.session.get('email') and self.session.get('seller'):
			if self.request.get('cid'):
				chicken = Chicken.get_by_id(int(self.request.get('cid')))
				chicken.pricestr = '₩'+format(chicken.price,',d')
				oq = db.Query(ChickenOption)
				oq.filter('chicken =', chicken.key())
				ol = oq.fetch(limit=(oq.count()))
				for option in ol:
					option.pricestr = '₩'+format(option.price,',d')
				iq = db.Query(ChickenImage)
				iq.filter('chicken =', chicken.key())
				il = iq.fetch(limit=(iq.count()))
				if il:
					Render(self, 'n_seller_edit.htm', {'chicken':chicken, 'optionlist':ol, 'imagelist':il})
				else:
					Render(self, 'n_seller_edit.htm', {'chicken':chicken, 'optionlist':ol})
			else:
				query = db.Query(User)
				query.filter("email =",self.session.get('email'))
				u = query.get()
				cq = db.Query(Chicken)
				cq.filter('seller =',u.key())
				Render(self, 'n_seller_product.htm', {'chicken_list':cq})
		else:
			self.redirect('/')

class SellerNewChickenHandler(BaseHandler):
	def get(self):
		if self.session.get('email') and self.session.get('seller'):
			Render(self, 'n_seller_add.htm', {})
		else:
			self.redirect('/')

	def post(self):
		if self.session.get('email') and self.session.get('seller'):
			query = db.Query(User)
			q = query.filter("email =",self.session.get('email'))
			u = q.get()
			c = Chicken()
			c.seller = u
			c.name = self.request.get("name")
			c.quantity = int(self.request.get("quantity"))
			c.price = int(self.request.get("price"))
			c.intro = self.request.get("intro")
			ti = self.request.get("thumbimage")
			if ti:
				c.thumb = db.Blob(ti)
			ck = c.put()
			i = self.request.get_all("fimage")
			if i:
				for ic in range(len(i)):
					ci = ChickenImage()
					ci.chicken = ck
					ci.f = db.Blob(i[ic])
					ci.put()
					ci = None
					logging.info("done")
			on = self.request.get_all("oname")
			if on:
				op = self.request.get_all("oprice")
				oq = self.request.get_all("oquantity")
				for oc in range(len(on)):
					o = ChickenOption()
					o.chicken = ck
					o.name = on[oc]
					o.quantity = int(oq[oc])
					o.price = int(op[oc])
					o.put()
			self.redirect('/seller/chicken')
		else:
			self.redirect('/')

class ErrorHandler(BaseHandler):
	def get(self):
		Render(self, 'error.htm', {})

class TermsHandler(BaseHandler):
	def get(self):
		Render(self, 'terms.htm', {})

class SecurityHandler(BaseHandler):
	def get(self):
		Render(self, 'security.htm', {})

class ImageHandler(webapp2.RequestHandler):
	def get(self):
		if self.request.get("id"):
			k = self.request.get("id")
			r = db.get(k)
			if r.thumb:
				self.response.headers['Content-Type'] = 'image/jpg'
				self.response.out.write(r.thumb)
			else:
				self.response.headers['Content-Type'] = 'image/jpg'
				self.redirect('/resources/holder.jpg')
		elif self.request.get("oid"):
			k = self.request.get("oid")
			r = db.get(k)
			if r.f:
				self.response.headers['Content-Type'] = 'image/jpg'
				self.response.out.write(r.f)
			else:
				self.response.headers['Content-Type'] = 'image/jpg'
				self.redirect('/resources/holder.jpg')
		else:
			self.response.headers['Content-Type'] = 'image/jpg'
			self.redirect('/resources/holder.jpg')

config = {}

config['webapp2_extras.sessions'] = {
    'secret_key': 'dc458da48fa171a071a547a07d8e13f25dd2ed714a03f4d6fbae331e6b711139',
}

app = webapp2.WSGIApplication([('/login', LoginHandler), ('/register', RegisterHandler), 
	('/register/seller', SellerRegisterHandler), ('/logout', LogoutHandler), ('/findpw', UserpwHandler), 
	('/chicken/brand', BrandHandler), ('/chicken/local', LocalHandler), ('/order/bucket', OrderBucketHandler), 
	('/purchase', PurchaseHandler),('/mypage', MypageHandler), ('/seller/order', SellerOrderHandler), 
	('/seller/chicken', SellerChickenHandler), ('/seller/add', SellerNewChickenHandler), 
	('/terms', TermsHandler), ('/security', SecurityHandler), ('/blob/image', ImageHandler),
	('/error', ErrorHandler), ('/.*', MainHandler)], debug=True, config=config)

def main():
	app.run()

if __name__ == '__main__':
	main()