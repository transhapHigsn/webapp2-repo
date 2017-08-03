# Copyright 2016 Google Inc.
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

import webapp2
import os
import jinja2
from google.appengine.ext import db
import hashlib
import hmac
import re

SECRET = '1$%&%$0'
template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
								autoescape=True)

def hash_string(s):
	return hmac.new(SECRET,s).hexdigest()

def make_secure_val(s):
	return '%s|%s' % (s, hash_string(s))
	
def check_secure_val(s):
	val, hash = s.split('|')
	if hash_string(val)==hash:
		return val

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PW_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
		
def valid_username(username):
	return USER_RE.match(username)		
	
def valid_password(password):
	return PW_RE.match(password)		

def valid_email(email):
	return EMAIL_RE.match(email)		

class Blogs(db.Model):
	subject = db.StringProperty(required=True)
	content = db.TextProperty(required=True)
	created = db.DateTimeProperty(auto_now_add=True)
	
	def render(self):
		self._render_str = self.content.replace("\n", "<br>")
		return render_str('entry.html', p = self )
'''
class Results(db.Model):
	name = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
'''
	
class Relts(db.Model):
	name = db.StringProperty(required = True)
	content = db.TextProperty(required = True)


class Handler(webapp2.RequestHandler):
	def write(self,*a,**kw):
		self.response.out.write(*a,**kw)
		
	def render_str(self,template,**params):
		t = jinja_env.get_template(template)
		return t.render(params)
		
	def render(self, template, **kw):
		self.write(self.render_str(template,**kw))					

class BlogHomeHandler(Handler):
	def get(self):
		entries = db.GqlQuery('Select * From Blogs Order by created desc limit 10')
		
		self.render('home.html', entries = entries)

class BlogPostHandler(Handler):
	def get(self):
		self.render_front()
		
	def post(self):
		subject = self.request.get("subject")
		content = self.request.get("content")
		
		if subject and content:
			entry = Blogs(subject = subject, content = content)
			entry_key = entry.put()
			#self.redirect('/blog/%s' %str(entry_key.id()))
			self.render('permalink.html',subject = subject, content = content, message='Is this your blog? ;)')
		else:
			error = 'Both subject and content are required.'
			self.render_front(subject,content,error)
	
	def render_front(self,subject='',content='',error=''):
		#print 'It should work in case of incomplete fields.'
		self.render('entry.html',subject = subject,content = content,error = error)
		
class NewHandler(Handler):
	def get(self,post_id):
		k = db.Key.from_path('Blogs',int(post_id))
		p = db.get(k)
		
		if p:
			self.render('permalink.html',subject=p.subject,content=p.content,message='This is permalink for selected entry.')
		else:
			self.error(404)
			return
		

class PermalinkHandler(Handler):
	def get(self):
		name = ''
		content = ''
		self.render('check.html',name = name, content = content)
		
	def post(self):
		name = self.request.get('name')
		content = self.request.get('content')
		print 'Content: ',content
		
		print 'Storing Data..'
		res = Relts(name=name,content = content)
		res.put()
		print 'Data submission successful'
		
		results = db.GqlQuery('Select * From Relts Order By name Desc')
		print('Tried querying data...')
		for res in results:
			print res.content
		self.render('check.html',name = name, content = content, results = results)

class MainPageHandler(Handler):
	def get(self):
		self.response.headers['Content-Type'] = 'text/plain'
		visits = 0
		username='user'
		
		
		cookie_val_str = self.request.cookies.get('visi')
		print cookie_val_str
		
		if cookie_val_str:
			if check_secure_val(cookie_val_str):
				visits = int(check_secure_val(cookie_val_str))
		
		visits += 1
		s = make_secure_val(str(visits))
		self.response.headers.add_header('Set-Cookie','visi=%s' %s)
		
		print 'Vists by the user ',visits

		self.redirect('/blog')

class User(db.Model):
	username = db.StringProperty(required=True)
	pw = db.StringProperty(required=True)
	email = db.StringProperty()
	created = db.DateTimeProperty(auto_now_add=True)
		
class SignupHandler(Handler):
	def get(self):
		self.render('signup.html')

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')
		v_password = self.request.get('v_password')
		email = self.request.get('email')
		
		if username and valid_username(username):
			
			query = "Select * from User where username = '%s' "
			print query %username
			users = db.GqlQuery(query %username)
			if not users:
				print 'Condition is true'
				error = 'Username already present'
				self.render_form(error)
			
			else:
				if password and valid_password(password):
					if v_password:
						if v_password == password:
							if not email or (email and valid_email(email)):
								pw = make_secure_val(password)
								user = User(username=username,pw = pw,email=email)
								user.put()
								self.response.headers['Content-Type'] = 'text/plain'			
								self.response.headers.add_header('Set-Cookie','username=%s; Path=/' %str(username))
								self.redirect('/welcome')
							else:
								error='Invalid Email id'
								self.render_form(error)
							
						else:
							error = 'Unmatched passwords'
							self.render_form(error)
					else:
						error = 'Empty verify password field'
						self.render_form(error)
				else:
					error = 'Empty password field'
					self.render_form(error)
		else:
			error = 'Empty username field or Invalid username'
			self.render_form(error)

		
	def render_form(self,error = ''):
		self.render('signup.html',error = error)
	
		
class WelcomePageHandler(Handler):
	def get(self):
		user = self.request.cookies.get('username')
		query = "Select * from User where username = '"+user+"'"
		print query
		q = db.GqlQuery(query)
		u = q.get()
		print u.email, u.username, u.created
		print u	
		if user:
			self.response.write('Welcome!, %s mails via %s' %(user,u.email))
		
		else:
			self.response.write('Welcome! User.')
			
app = webapp2.WSGIApplication([
	('/',MainPageHandler),
    ('/blog',BlogHomeHandler),
    ('/blog/newpost',BlogPostHandler),
    ('/blog/perma',PermalinkHandler),
    ('/blog/([0-9]+)',NewHandler),
    ('/signup',SignupHandler),
    ('/welcome',WelcomePageHandler),
], debug=True)
