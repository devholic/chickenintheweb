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

class UserOrder(db.Model): # 유저 주문 내역
	buyer = db.ReferenceProperty(User) # 구매자
	detail = db.StringProperty() # 주문 내역 (JSON)
	price = db.IntegerProperty() # 가격
	created_at = db.DateTimeProperty(auto_now_add=True) # Entity 생성시간

class SellerOrder(db.Model):
	order = db.ReferenceProperty(UserOrder) # Order
	seller = db.ReferenceProperty(User) # 판매자
	status = db.IntegerProperty() # 배송 상태
	created_at = db.DateTimeProperty() # Entity 생성시간 (UserOrder와 같음)

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

def OrderStatusString(s): # 배송 상태 리턴해주는 함수
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
		saltstring+=random.choice(alphabet) # 알파벳 한글자씩 계속 더함
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
		captcha = self.request.get('g-recaptcha-response') # recaptcha 입력값 받기 
		url = "https://www.google.com/recaptcha/api/siteverify?secret=6Ldi6f4SAAAAAJ5WXvkKk1cSzc7L9C1CALkCnITs&response="+captcha # recaptcha 입력값 검증 URL
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
				# 구매자 추가
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
		captcha = self.request.get('g-recaptcha-response') # recaptcha 입력값 받기
		url = "https://www.google.com/recaptcha/api/siteverify?secret=6Ldi6f4SAAAAAJ5WXvkKk1cSzc7L9C1CALkCnITs&response="+captcha # recaptcha 입력값 검증 URL
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
				# 판매자를 추가
				saltstring = Salt() # Salt 생성
				user = User() # 유저 인스턴스 만들기
				user.email = req_email # 유저 이메일
				user.password = hashlib.sha256(self.request.get('password') + saltstring).hexdigest() # Hash 후 저장
				user.name = self.request.get('name') # 유저 이름
				user.address = self.request.get('address') # 유저 주소
				user.number = self.request.get('number') # 유저 전화번호 
				user.salt = saltstring # Salt
				user.isSeller = True # 판매자 True
				user.isAdmin = False # 관리자 False
				if self.request.get('brand'): # 프랜차이즈 회원인 경우
					user.isBrandSeller = True # 프랜차이즈 판매자 True
				else:
					user.isBrandSeller = False # 프랜차이즈 판매자 False
				uk = user.put() # 유저 추가하고 키 리턴받기
				s = Store() # 스토어 인스턴스 생성
				s.seller = uk # 셀러 = 방금 추가한 유저
				s.isBrand = user.isBrandSeller # 브랜드 스토어 여부 확인
				s.intro = unicode("치킨인더웹 페이지",'utf-8') # 기본 값 집어넣기
				s.put() # 데이터스토어에 추가 
				w = Wallet() # 월렛 인스턴스 생성
				w.user = uk # Return 받은 User key 지정
				w.money = 0 # 기본 판매액 0원 
				w.put() # 월렛 저장 
				self.session['email'] = user.email # 세션에 이메일 추가
				self.session['name'] = user.name # 세션에 이름 추가
				self.session['seller'] = 'true' # 세션에 판매자 속성 추가
				self.redirect("/") # Main으로 redirect (로그인 처리 완료)
		else:
			if "response" in str(data['error-codes']): # reCAPTCHA 에러 판별
				Render(self, 'n_register_seller.htm', {'err': 'reCAPTCHA가 정상적으로 확인되지 않았습니다. 다시 시도해주세요.'})
			else: # 요청 에러 
				Render(self, 'n_register_seller.htm', {'err': '시스템 에러입니다. 잠시후 다시 시도해주세요.'})

class LoginHandler(BaseHandler): # 로그인 핸들러
	def get(self):
		Render(self, 'n_index.htm', {})

	def post(self):
		email = self.request.get('email') # 이메일 
		password = self.request.get('password') # 비밀번호
		query = db.Query(User) # 유저 쿼리
		q = query.filter("email ==",email) # 사용자가 보낸 값을 가지고 필터링 
		if q.count() == 1:
			# 유저가 존재하는 경우
			u = q.get() # 유저 가져오기 
			if u.password == hashlib.sha256(password + u.salt).hexdigest(): # 사용자가 입력한 비밀번호 값을 계정에 저장된 Salt 값을 가져와 Hash해서 저장되어있는 Hash 값과 같은지 확인
				# 만약 맞다면
				self.session['email'] = email # 세션에 이메일 추가
				self.session['name'] = u.name # 세션에 이름 추가
				if u.isSeller: # 판매자인 경우
					self.session['seller'] = 'true' # 판매자 true 값 넣어줌
				self.redirect("/") # 메인 페이지로 redirect 
			else:
				Render(self, 'n_index.htm', {'err':'없는 계정이거나 비밀번호가 맞지 않습니다.'}) # 이메일이 틀렸는지 비밀번호가 틀렸는지 알려주지 않음
		else:
			Render(self, 'n_index.htm', {'err':'없는 계정이거나 비밀번호가 맞지 않습니다.'}) # 이메일이 틀렸는지 비밀번호가 틀렸는지 알려주지 않

class LogoutHandler(BaseHandler): # 로그아웃
	def get(self):
		if self.session.get('email'): # 이메일이 세션에 있는 경우 
			self.session.pop('email') # 저장된 이메일 지우기 
		if self.session.get('name'): # 이름이 세션에 있는 경우 
			self.session.pop('name') # 이름 지우기
		if self.session.get('seller'): # 판매자 정보가 세션에 있는 경우 
			self.session.pop('seller') # 판매자 정보 지우기
		if self.session.get('bucket'): # 장바구니 정보가 세션에 있는 경우
			self.session.pop('bucket') # 장바구니 정보 지우기
		self.session.clear() # 세션 클리어
		self.redirect("/") # 메인화면으로 이동 

	def post(self):
		if self.session.get('email'): # 이메일이 세션에 있는 경우 
			self.session.pop('email') # 저장된 이메일 지우기 
		if self.session.get('name'): # 이름이 세션에 있는 경우 
			self.session.pop('name') # 이름 지우기
		if self.session.get('seller'): # 판매자 정보가 세션에 있는 경우 
			self.session.pop('seller') # 판매자 정보 지우기
		if self.session.get('bucket'): # 장바구니 정보가 세션에 있는 경우
			self.session.pop('bucket') # 장바구니 정보 지우기
		self.session.clear() # 세션 클리어
		self.redirect("/") # 메인화면으로 이동 

class UserpwHandler(BaseHandler): # 비밀번호 찾기 핸들러
	def get(self):
		Render(self, 'n_findpw.htm', {}) # 비밀번호 찾기 페이지 보여주기

	def post(self):
		captcha = self.request.get('g-recaptcha-response') # reCAPTCHA 입력값 
		url = "https://www.google.com/recaptcha/api/siteverify?secret=6Ldi6f4SAAAAAJ5WXvkKk1cSzc7L9C1CALkCnITs&response="+captcha # Google에 
		chk = urllib2.urlopen(url) # 검증 url open
		data = json.load(chk) # response를 json으로 파싱
		if data['success']: # recaptcha 성공
			email = self.request.get('email') # email 요청된거 가져오기
			query = db.Query(User) # 유저 쿼리
			q = query.filter("email ==",email) # 유저 이메일로 필터링
			if q.count() == 1:
				# 유저가 존재하는 경우
				user = UserRecovery() # 유저 리커버리 인스턴스 생성
				user.email = email # 이메일
				code = Salt() # Salt (인증키 용도) 생성 
				user.code = code # 생선한 Salt 저장
				t = int(time.time()) + 1800 # 30분 뒤 키 만료
				user.expire = t # 키 만료시간 저장
				user.put() # 유저 리커버리 저장
				message = mail.EmailMessage(sender="no-reply@chickenintheweb.appspotmail.com",
                            subject="치킨인더웹 비밀번호 재설정 코드입니다.") # 보낼 메시지
				message.to = email # 보낼 이메일 주소
				message.body = """
				비밀번호 재설정 코드는 %s 입니다.
				""" % code # 보낼 본문
				message.send() # 메시지 전송
			else:
				# 이메일이 없는 경우
				Render(self, 'n_findpw.htm', {'err':'입력하신 이메일에 해당되는 계정을 찾을 수 없습니다. 확인하신 다음 다시 시도해주세요.'})
		else:
			if "response" in str(data['error-codes']):
				# reCAPTCHA가 정상적으로 확인되지 않은 경우
				Render(self, 'n_findpw.htm', {'err': 'Captcha가 정상적으로 확인되지 않았습니다. 다시 시도해주세요.'})
			else:
				# 요청 오류
				Render(self, 'n_findpw.htm', {'err': '시스템 에러입니다. 잠시후 다시 시도해주세요.'})

class MypageHandler(BaseHandler):
	def get(self):
		if self.session.get('email') and not self.session.get('seller'):
			# 일반 회원이 로그인 한 경우
			if self.request.get('orderid'):
				# orderid가 주어진 경우 
				o = UserOrder.get_by_id(int(self.request.get("orderid"))) # 해당하는 UserOrder 가져오기
				sq = db.Query(SellerOrder) # SellerOrder 가져오기 (배송 상태 체크용)
				sq.filter('order =', o.key()) # UserOrder로 필터링
				so = sq.fetch(limit=(sq.count())) # 검색된 개수 만큼 가져오기
				seller_email_list = [] # 이메일을 담을 리스트 생성 (밑의 list와 index 같게)
				seller_status_list = [] # 배송 상태를 담을 리스트 생성 (위의 list와 index 같게)
				for sindex in range(len(so)): # SellerOrder 개수만큼
					seller_email_list.append(so[sindex].seller.email) # email 가져와서 넣고
					seller_status_list.append(int(so[sindex].status)) # 배송 상태 가져와서 넣기
				bucketlist = json.loads(o.detail) # json 파싱
				renderlist = [] # 화면에 렌더링할 리스트
				finalprice = 0 # 최종 가격
				for bucket in bucketlist: # 전체 결제된 리스트 가져오기
					for index in range(len(bucket)): # bucket 개수 만큼 index for문으로 
						if index == 0: #index가 0인경우 : 무조건 치킨임 
							chicken = Chicken.get_by_id(int(bucket[index]['chicken'])) # 치킨 가져오기
							if chicken.seller.email in seller_email_list: # 이메일리스트에 그 치킨 셀러의 이메일이 있는경우
								oidx = seller_email_list.index(chicken.seller.email) # 인덱스를 가져와서
								chicken.orderstatus = OrderStatusString(seller_status_list[oidx]) # 해당하는 배송상태를 OrderStatusString을 이용하여 문장으로 가져옴
							chicken.uquantity = bucket[index]['chicken_quantity'] # 유저가 주문한 개수
							chicken.pricestr = '₩'+format(chicken.price,',d') # 가격 표시용
							if not chicken.uquantity == 0: # 유저가 주문한 개수가 0개가 아니라면 
								finalprice += (chicken.price * int(chicken.uquantity)) # 최종 가격 업데이트
							renderlist.append(chicken) # 치킨을 렌더링할 리스트에 추가
						else:
							# index가 0이 아닌경우 무조건 옵션임
							option = ChickenOption.get_by_id(int(bucket[index]['option'])) # 옵션 가져오기
							option.uquantity = bucket[index]['option_quantity'] # 유저가 주문한 옵션 수량 가져오기
							option.pricestr = '₩'+format(option.price,',d') # 옵션 가격 표시용
							if not option.uquantity == 0: # 유저가 주문한 개수가 0개가 아니라면
								finalprice += (option.price * int(option.uquantity)) # 최종 가격 업데이트
							renderlist.append(option) # 옵션을 렌더링할 리스트에 추가
				finalpricestr = '₩'+format(finalprice,',d') # 최종 가격 표시용 String
				Render(self, 'n_mypage_order_detail.htm', {'bucketlist':renderlist,'bucketprice':finalpricestr, 'user':o.buyer}) # 화면 렌더링 
			else:
				# orderid가 없는 경우 : 일반 mypage 띄우기
				uq = db.Query(User) # 유저 쿼리
				uq.filter("email =", self.session.get('email')) # 이메일로 필터링
				u = uq.get() # 유저 가져오기
				wq = db.Query(Wallet) # 월렛 쿼리
				wq.filter("user =", u.key()) # 월렛 필터링 
				w = wq.get() # 해당하는 월렛 가져오기
				oq = db.Query(UserOrder) # 주문 쿼리
				oq.filter("buyer =", u.key()) # 구매자로 필터링 
				oq.order("-created_at") # 최근 주문한 순서대로 정렬
				o = oq.fetch(limit=(oq.count())) # 주문 가져오기 
				w.moneystr = '₩'+format(w.money,',d') # 월렛 잔고 표시용 String
				Render(self, 'n_mypage.htm', {'wallet':w,'orderlist':o}) # 화면 렌더링
		else:
			# 일반 회원이 아닌경우
			if self.session.get('seller'):
				# 판매자인 경우 
				uq = db.Query(User) # 유저 쿼리
				uq.filter("email =", self.session.get('email')) # 이메일로 필터링
				u = uq.get() # 유저 가져오기 
				wq = db.Query(Wallet) # 월렛 쿼리
				wq.filter("user =", u.key()) # 월렛 유저로 필터링 
				w = wq.get() # 월렛 가져오기
				w.moneystr = '₩'+format(w.money,',d') # 월렛 잔고 표시
				sq = db.Query(Store) # Store 쿼리
				sq.filter("seller =",u.key()) # 셀러로 필터링
				s = sq.get() # 스토어 데이터 가져오기
				Render(self, 'n_mypage.htm', {'wallet':w, 'store':s})
			else:
				# 로그인이 안된 경우 
				self.redirect('/') # 메인 페이지로 이동 

	def post(self):
		if self.session.get('email') and not self.session.get('seller'):
			# 일반 유저인 경우
			if self.request.get('money'):
				# money 데이터가 있는 경우
				captcha = self.request.get('g-recaptcha-response') # reCAPTCHA 판별값 가져오기 
				url = "https://www.google.com/recaptcha/api/siteverify?secret=6Ldi6f4SAAAAAJ5WXvkKk1cSzc7L9C1CALkCnITs&response="+captcha # captcha 검증
				chk = urllib2.urlopen(url) # url open
				data = json.load(chk) # reCAPTCHA Response 파싱
				if data['success']: # reCAPTCHA 성공한 경우 
					uq = db.Query(User) # User 쿼리
					uq.filter("email =", self.session.get('email')) # 이메일로 필터링
					u = uq.get() # 유저 가져오기 
					wq = db.Query(Wallet) # 월렛 쿼리
					wq.filter("user =", u.key()) # 월렛 필터링 
					w = wq.get() # 월렛 가져오기 
					w.money += int(self.request.get('money')) # 월렛 잔고에 입력받은만큼 추가 
					w.put() # 월렛 업데이트
					self.get() # get request
				else: # reCAPTCHA 실패한 경우 
					self.redirect('/error') # 에러 페이지로 이동 
			else: # money 데이터가 없는 경우 
				self.get() # get request
		else: # 일반 유저가 아닌 경우 
			if self.session.get('email') and self.session.get('seller'): # 판매자인 경우 
				if self.request.get('update'): # 업데이트할 내용이 있는 경우 
					uq = db.Query(User) # User 쿼리
					uq.filter("email =", self.session.get('email')) # 이메일로 필터링
					u = uq.get() # 유저 가져오기 
					sq = db.Query(Store) # 스토어 쿼리 
					sq.filter("seller =", u.key()) # 스토어 필터링
					s = sq.get() # 스토어 가져오기 
					if self.request.get('intro'): # 스토어 소개 내용이 있는 경우 
						s.intro = self.request.get('intro') # 스토어 소개 내용을 업데이트 
					if self.request.get('thumbimage'): # 썸네일이 있는 경우 
						s.thumb = db.Blob(self.request.get('thumbimage')) # 썸네일 업데이트
					s.put() # 스토어 데이터 업데이트 
					self.get() # get request 
				else: # 업데이트할 내용이 없는 경우 
					self.get() # get request
			else: # 일반회원도 아니고 판매자도 아닌경우 
				self.get() # get request

class MainHandler(BaseHandler):
	def get(self):
		if self.session.get('email') and not self.session.get('seller'):
			# 판매자가 아닌경우 최근 추가된 치킨 12개 가져오기
			query = db.Query(Chicken)
			query.order("-created_at")
			result = query.fetch(limit=12)
			for c in result:
				# https://www.python.org/dev/peps/pep-0378/
				c.pricestr = '₩'+format(c.price,',d') # 가격 포맷 설정
			Render(self, 'n_index.htm', {'chicken_list':result})
		else:
			Render(self, 'n_index.htm', {})

class BrandHandler(BaseHandler): # 프랜차이즈 치킨 핸들러 
	def get(self):
		if self.session.get('email') and not self.session.get('seller'): # 일반 회원인 경우 
			if self.request.get("cid"): # cid가 요청에 포함되어 있는 경우 
				# 치킨을 찾고 해당 치킨의 이미지와 옵션을 가져와서 판매 페이지를 렌더링 한다
				q = Chicken.get_by_id(int(self.request.get("cid")))
				if q:
					q.pricestr = '₩'+format(q.price,',d')
					oq = db.Query(ChickenOption)
					oq.filter("chicken =", q.key())
					o = oq.fetch(limit=(oq.count()))
					for op in o:
						# https://www.python.org/dev/peps/pep-0378/
						op.pricestr = '₩'+format(op.price,',d') # 가격 포맷 설정
					iq = db.Query(ChickenImage)
					iq.filter("chicken =", q.key())
					i = iq.fetch(limit=5)
					if len(o) != 0: # 옵션이 있는 경우
						if len(i) != 0: # 이미지가 있는 경우 
							Render(self, 'n_chicken.htm',{'chicken':q,'option_list':o,'image_list':i, 'type':'brand'})
						else: # 이미지가 없는 경우
							Render(self, 'n_chicken.htm',{'chicken':q,'option_list':o, 'type':'brand'})
					elif len(i) != 0: # 이미지가 있는 경우
						Render(self, 'n_chicken.htm',{'chicken':q,'image_list':i, 'type':'brand'})
					else: # 그 외의 경우 
						Render(self, 'n_chicken.htm',{'chicken':q, 'type':'brand'})
				else: # 치킨이 없는 경우 프랜차이즈 스토어 리스트 렌더링
					query = db.Query(Store)
					query.filter("isBrand =", True)
					result = query.fetch(limit=(query.count()))
					Render(self, 'n_store.htm', {'request':'storelist','store_list':result, 'type':'brand'})
			elif self.request.get("id"): # id가 있는 경우 해당 store를 보여준다
				q = Store.get_by_id(int(self.request.get("id")))
				if q:
					cquery = db.Query(Chicken)
					cquery.filter("seller =", q.seller)
					result = cquery.fetch(limit=(cquery.count()))
					for c in result:
						# https://www.python.org/dev/peps/pep-0378/
						c.pricestr = '₩'+format(c.price,',d') # 가격 포맷 설정
					Render(self, 'n_store.htm', {'request':'store','store':q, 'chicken_list':result, 'type':'brand'})
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
			self.redirect('/')

class LocalHandler(BaseHandler): # 동네 치킨 핸들러
	def get(self):
		if self.session.get('email') and not self.session.get('seller'): #일반 회원인 경우 
			if self.request.get("cid"): # 요청에 cid가 있으면
			# 치킨을 찾고 해당 치킨의 이미지와 옵션을 가져와서 판매 페이지를 렌더링 한다
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
					# 치킨이 없는경우 동네 치킨 스토어 리스트를 렌더링해준다
					query = db.Query(Store)
					query.filter("isBrand =", False)
					result = query.fetch(limit=(query.count()))
					Render(self, 'n_store.htm', {'request':'storelist','store_list':result, 'type':'local'})
			elif self.request.get("id"):
				# 요청에 id가 있는 경우 해당 치킨 스토어에서 판매중인 리스트를 렌더링해준다 
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
			self.redirect('/')

class OrderBucketHandler(BaseHandler): # 장바구니 핸들러 
	def get(self):
		if self.session.get('email') and not self.session.get('seller'):
			# 일반 회원인 경우
			if self.request.get('clear'):
				# 요청에 clear 가 있다면 장바구니를 삭제한다 
				if self.session.get('bucket'):
					self.session.pop('bucket')
				self.redirect('/order/bucket')

			if self.request.get('remove'):
				# 요청에 remove가 있다면 해당 위치의 데이터를 제외하고 다시 JSON 파일을 구성해 세션에 집어넣는다
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
				# 요청에 change가 있다면 해당 위치의 데이터를 value로 교체한다. (양 교체)
				if self.request.get('value'):
					v = self.request.get('value')
					target = int(self.request.get('change'))
					jstr = self.session.get('bucket')
					bucketlist = json.loads(jstr)
					parentlist = []
					finalprice = 0
					item = 0
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
				# 장바구니가 존재하는 경우 장바구니 정보를 표시해준다
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
				if finalprice == 0: # 최종 가격이 0원인 경우 결제가 되지 않게 empty:true를 Render 함수에 집어넣어준다
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
			# 일반 회원인 경우
			if self.session.get('bucket'):
				# 장바구니가 존재하는 경우 기존의 데이터에 전송받은 데이터를 더 추가해준뒤 세션에 저장된 장바구니 항목을 업데이트해준다.
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
				# 장바구니가 존재하지 않는 경우 전송받은 데이터를 추가해준뒤 세션에 저장된 장바구니 항목을 업데이트해준다.
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
			# 일반 회원이 아닌경우 메인핸들러로
			self.redirect('/')

class PurchaseHandler(BaseHandler): # 치킨 구매 핸들러
	def get(self):
		if self.session.get('email') and not self.session.get('seller'):
			if self.session.get('bucket'): # 장바구니가 있는 경우 장바구니에 있는 항목 결제창을 렌더링해준다 (배송정보도)
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
			else: # 그렇지 않은 경우 장바구니로 이동
				self.redirect('/order/bucket')
		else: # 일반 회원이 아닌경우 메인핸들러로 이동 
			self.redirect('/')

	def post(self): # 결제 요청인 경우 
		if self.session.get('email') and not self.session.get('seller'):
			if self.request.get('checkout'): # 결제 요청인 경우
				checkout_type = self.request.get('checkout')
				# 유저 가져오기
				uq = db.Query(User)
				uq.filter("email =", self.session.get('email'))
				u = uq.get()
				wq = db.Query(Wallet)
				wq.filter("user =", u.key())
				w = wq.get() 
				if checkout_type == 'direct': # 바로 결제인 경우 (장바구니 사용 x) 주어진 치킨과 옵션의 수량을 확인하고, 결제후 잔고가 0원 이상인 경우 주문을 추가
				# 주문은 JSON 형태로 detail에 저장
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
					# 장바구니 결제인 경우 세션에서 장바구니 데이터를 불러온다
					# 각각 판매자가 다를 수 있으므로 각각의 판매자에게 적립될 월렛 잔고를 관리해주고, 마찬가지로 주문 내역은 JSON 형태로 저장한다 .
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
						itemindex = 0
						for bucket in bucketlist:
							for index in range(len(bucket)):
								if index == 0:
									itemlist[itemindex].quantity = itemlist[itemindex].quantity - int(bucket[index]['chicken_quantity'])
									itemlist[itemindex].put()
								else:
									itemlist[itemindex].quantity = itemlist[itemindex].quantity - int(bucket[index]['option_quantity'])
									itemlist[itemindex].put()
								itemindex += 1
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
			else: # 결제 화면을 요청받은 경우 (직접 결제) 해당하는 상품의 요약 내용과 배송정보를 렌더링해준다.
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

class SellerOrderHandler(BaseHandler): # 판매자 주문관리 핸들러
	def get(self):
		if self.session.get('email') and self.session.get('seller'):
			# 판매자인 경우
			if self.request.get('id'):
				# 요청에 id가 있는 경우 
				if self.request.get('status'):
					# 요청에 status가 있는 경우 
					so = SellerOrder.get_by_id(int(self.request.get("id")))
					if so.seller.email == self.session.get('email'):
						so.status = int(self.request.get("status"))
						so.put() # 해당 판매자의 상품이 맞는 경우 status를 업데이트 해준다
						self.redirect('/seller/order?id='+self.request.get('id'))
					else:
						self.redirect('/') # 아니면 메인 핸들러로 보내버린다 
				else: # 요청에 id만 있는 경우 배송 정보와 주문한 상품 내역을 렌더링해준다
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
			else: #id가 없는 경우 현재 모든 주문 내역을 렌더링해준다 
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

class SellerChickenHandler(BaseHandler): # 판매자 상품 관리 핸들러
	def get(self):
		if self.session.get('email') and self.session.get('seller'):
			if self.request.get('cid'):
				# cid가 있는 경우 해당 치킨에 관련된 정보를 렌더링해준다
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
			else: # 현재 판매하고 있는 모든 제품을 렌더링해준다
				query = db.Query(User)
				query.filter("email =",self.session.get('email'))
				u = query.get()
				cq = db.Query(Chicken)
				cq.filter('seller =',u.key())
				Render(self, 'n_seller_product.htm', {'chicken_list':cq})
		else:
			self.redirect('/')

class SellerNewChickenHandler(BaseHandler): # 판매자 상품 추가 핸들러
	def get(self):
		if self.session.get('email') and self.session.get('seller'):
			Render(self, 'n_seller_add.htm', {})
		else:
			self.redirect('/')

	def post(self):
		if self.session.get('email') and self.session.get('seller'):
			# 판매자인 경우 치킨 추가
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
			if ti: # 썸네일이 존재하는 경우 
				c.thumb = db.Blob(ti)
			ck = c.put()
			i = self.request.get_all("fimage")
			if i: # 이미지가 존재하는 경우 
				for ic in range(len(i)):
					ci = ChickenImage()
					ci.chicken = ck
					ci.f = db.Blob(i[ic])
					ci.put()
					ci = None
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

class ErrorHandler(BaseHandler): # 임시 에러 페이지
	def get(self):
		Render(self, 'error.htm', {})

class TermsHandler(BaseHandler): # 약관
	def get(self):
		Render(self, 'terms.htm', {})

class SecurityHandler(BaseHandler): # 개인정보 취급방침
	def get(self):
		Render(self, 'security.htm', {})

class ImageHandler(webapp2.RequestHandler): # DB에 Blob 형태로 저장된 Image를 띄워주기 위한 핸들러
	def get(self):
		if self.request.get("id"): # id가 요청에 있으면 
			k = self.request.get("id")
			r = db.get(k)
			if r.thumb: # 썸네일을 가져오고 (치킨 이미지를 제외한 모든 이미지)
				self.response.headers['Content-Type'] = 'image/jpg'
				self.response.out.write(r.thumb)
			else:
				self.response.headers['Content-Type'] = 'image/jpg'
				self.redirect('/resources/holder.jpg') # 이미지가 없는경우 default 이미지 표시 
		elif self.request.get("oid"): # oid가 요청에 있으면 (치킨이미지)
			k = self.request.get("oid")
			r = db.get(k)
			if r.f: # 이미지를 가져온다
				self.response.headers['Content-Type'] = 'image/jpg'
				self.response.out.write(r.f)
			else:
				self.response.headers['Content-Type'] = 'image/jpg'
				self.redirect('/resources/holder.jpg') # 이미지가 없는경우 default 이미지 표시
		else:
			self.response.headers['Content-Type'] = 'image/jpg'
			self.redirect('/resources/holder.jpg') # id나 oid가 없는경우 default 이미지 표시

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