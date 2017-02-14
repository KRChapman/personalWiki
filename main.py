import os.path
import webapp2
import cgi
import re
import jinja2
import Cookie
import hmac


from itertools import izip_longest

import json
import logging
import hashlib
import string
import random
import datetime
import calendar
import time
import email.mime.text
from google.appengine.api import memcache
from google.appengine.ext import db
##import pdb; pdb.set_trace()

seceret = 'ifyouhavetoaskyouwillneverknow'

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def blog_key(user, page):
    return db.Key.from_path(user, page)

def make_secure_val(session_id, seceret=seceret):
    return hmac.new(seceret, session_id).hexdigest()




def content_cache(user, pagename, update = False, delete = False):
    key = blog_key(user, pagename)
    memcache_key = '{}'.format(str(key))
    posts = memcache.get(memcache_key)

    if (posts is None or update) and not delete:
        page_content = Content.all()
        page = page_content.ancestor(key)
        posts = list(page)
        brainbug('content')
     
        memcache.set(memcache_key, posts)

    if delete:
  
        memcache.delete(memcache_key)   
    return posts





def page_cache(username, update = False):
    pages = memcache.get(username)

    if pages is None or update:
        name = "SELECT * FROM Pages WHERE username = '%s'"
        v = name % (username)
        pages = db.GqlQuery(v)
        logging.debug('querypage')
##        pages = list(page)
        memcache.set(username, pages)
    return pages

def grouper(iterable, n, fillvalue=None):
    args = [iter(iterable)] * n
    return izip_longest(*args, fillvalue=fillvalue)



class MainHandler(webapp2.RequestHandler):
 
    def write_form(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write_form(self.render_str(template, **kw))
        
    def check_username(self, username):
        username_query = "SELECT * FROM UserData WHERE username = '{}'"
        return db.GqlQuery(username_query.format(username)).get()   
    
    def id_generator(self, chars=string.ascii_uppercase + string.digits, size=15):
         return ''.join(random.SystemRandom().choice(chars) for _ in range(size))      

    def make_pw_hash(self, pw, salt=None):
        if not salt:
            salt = self.id_generator()
        h = hashlib.sha256(pw + salt).hexdigest()
        return '%s,%s' % (h, salt)
    
    def valid_pw(self, pw, hash_and_salt):
        salt = hash_and_salt.split(',')[1]
        a = self.make_pw_hash(pw,salt)
        return a == hash_and_salt    
  
        
    def valid_field(self, inp):
        if inp:
            USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
            return USER_RE.match(inp)

    def find_user_data(self, update = False, password = False):
        cookie_id = self.request.cookies.get('id')
        cookie = make_secure_val(cookie_id) 
        user = memcache.get(str(cookie))
        
        if user is None or update:
            value = str(cookie)
            query  = "SELECT * FROM UserData WHERE cookie = '{}'".format(value)  
            user = db.GqlQuery(query).get()
            
            if not password:
                user.password_hash_salt = None
                memcache.set(str(cookie), user) 
        return user
    

        
    def set_cookies(self, name='id',value=None, path= '/', expires_days=1):
##        self.response.headers.add_header('Set-Cookie', "%s=%s; %s, %s" % (name, value, path, expires_days))
        c = Cookie.SimpleCookie()
        c[name] = value
        expires = datetime.datetime.utcnow() + datetime.timedelta(days=expires_days)
        timestamp = calendar.timegm(expires.utctimetuple())
        c[name]["expires"] = email.utils.formatdate(timestamp,localtime=False,usegmt=True)
        c[name]["path"] = path

        for m in c.values():
            self.response.headers.add_header('Set-Cookie',m.OutputString(None))
        return c[name].value        


class SignUp(MainHandler):
    def get(self):
        self.render("sign_form.html")
        
    def post(self):
        # Info from user validated and if valid error is blank by default otherwise error message displayed
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        
        valid_name = self.valid_field(username)
        valid_pass = self.valid_field(password)
        valid_verify = self.valid_field(verify) 
        
        user_error=""
        pass_error=""
        verify_error=""

        if (not valid_verify) or (password != verify):
            verify_error = "passwords do not match or invalid"
             
        if not valid_pass:
            pass_error = "invalid or blank password"

        elif not valid_name:
            user_error = "invalid or blank user name"

        #check if username already in database
        elif self.check_username(username):
            user_error = "username is already taken"
        
        if (valid_verify and valid_name and valid_pass and not self.check_username(username)):
            
         
                session_id = self.id_generator()
                user_session_id_hash = make_secure_val(session_id)
                self.set_cookies(value=session_id)
                password_hash = self.make_pw_hash(password)
                d = UserData(username=username, password_hash_salt=password_hash, cookie=user_session_id_hash)
                d.put()
                time.sleep(0.1)
                self.redirect("/home")
        else:    
            errors = {"user_error": user_error,
                  "pass_error": pass_error,
                  "verify_error": verify_error,
                  "username": cgi.escape(username, quote=True),
                  "password": cgi.escape(password, quote=True),
                  "verify": cgi.escape(verify, quote=True)}

            self.render("sign_form.html", **errors)      
        
    def set_cookies(self, name='id',value=None, path= '/', expires_days=1):
##        self.response.headers.add_header('Set-Cookie', "%s=%s; %s, %s" % (name, value, path, expires_days))
        c = Cookie.SimpleCookie()
        c[name] = value
    
                    # date time method need module and name of class then method TIMEDELTA is a class that creates object just need module and class name timedelta
        expires = datetime.datetime.utcnow() + datetime.timedelta(days=expires_days)
        timestamp = calendar.timegm(expires.utctimetuple())
       
        c[name]["expires"] = email.utils.formatdate(timestamp,localtime=False,usegmt=True)
        c[name]["path"] = path


        for m in c.values():
            self.response.headers.add_header('Set-Cookie',m.OutputString(None))
        return c[name].value
        

class LogIn(MainHandler):
    def get(self):
        user_data = self.find_user_data(False, True)
        if user_data:
           self.redirect('/home') 
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        
        correct_name = self.valid_field(username)
        correct_pass = self.valid_field(password)
        user = self.check_username(username)
        valid_pass = None

        if user:
            valid_pass = self.valid_pw(password, user.password_hash_salt)
        
        user_error=""
        pass_error=""
        
        
        if not correct_pass:
            pass_error = "blank password"

        elif not correct_name:
            user_error = "invalid or blank user name"
            
        elif not user:
            user_error = "username not found"

        elif not valid_pass:
            pass_error = 'invalid password'
            
        if (correct_pass and correct_name and valid_pass and user ):
            session_id = self.id_generator()
            self.set_cookies(value=session_id)    
            user_session_id_hash = make_secure_val(session_id)
            user.cookie = user_session_id_hash

            user.put()
            time.sleep(0.1)
            self.redirect("/home")
        else:    
            errors = {"user_error": user_error,
                  "pass_error": pass_error,
                  "username": cgi.escape(username, quote=True),
                  "password": cgi.escape(password, quote=True)}
                

            self.render("login.html", **errors)


 
class UserData(db.Model):
    username = db.StringProperty()
    password_hash_salt = db.StringProperty()
    cookie = db.StringProperty()

class Pages(db.Model):
    pagename = db.StringProperty()
    username = db.StringProperty()

class Content(db.Model):
    title = db.StringProperty()
    description = db.StringProperty()
    links  = db.StringListProperty() ############################
    
    
      
class HomeHandler(MainHandler):
    def get(self):
        user = self.find_user_data()
        pages = page_cache(user.username)
        posts = content_cache(user.username, 'home')

##        if posts is not None and pages is not None:
        self.render("display.html", pages = pages, page_link = 'home',  recent_posts = posts, content = 'home') 
                       
##        else:
##            self.render("home.html")

class NewPost(MainHandler):
    def get(self, pagename):
      
        self.render('newpost.html', pagename = pagename)
        
    def post(self, pagename):    
        title = self.request.get("title")
        description_data = self.request.get("description")
        links_data = self.request.get("links") 
        description = description_data.replace('\n', '<br>')
        links = links_data.split('\n') ######################################################
##        links = links_data.replace('\n', '<br>')

        if (title and description_data or links):
            user = self.find_user_data()
            c = str(user.username)
            key = blog_key(c, pagename)

            post = Content(parent = key, title = title, description = description, links = links)  
            post.put()
            content_cache(user.username, pagename, True)
            self.redirect('/home/{}'.format(pagename))

        else:
            error = "Enter title and at least one description or link"
            self.render('newpost.html', title = title, text = blog_text, error = error, link = links)

class NewPage(MainHandler):
    def get(self):
        self.render("newpage.html")

    def post(self):
        input_pagename = self.request.get('pagename')
        title = self.request.get('title')
        description_data = self.request.get('description')
        links_data = self.request.get('links') 
        brainbug('LinkFirstData{}O'.format(links_data))

        pagename = self.valid_field(input_pagename)

        if not pagename:
            error = "No symbols and must be longer than 3 words and shorter than 20"
            self.render("newpage.html", pagename = input_pagename, error = error)
        else:
            description = description_data.replace('\n', '<br>')
            
            links = links_data.split('\n') ######################################################
 ##               brainbug('SecondLinks{}P'.format(links))
##            links = links_data.replace('\n', '<br>')


            user = self.find_user_data()
            content = Content(parent = blog_key(user.username, input_pagename), title = title, description = description, links = links)
            content.put()
            page = Pages(pagename = input_pagename, username = user.username)
            content_cache(user.username, input_pagename, True)
            page.put()
            time.sleep(0.1)
            page_cache(user.username, True)        
            self.redirect('/home/{}'.format(input_pagename))

class Page(MainHandler):
    def get(self, pagename):
        user = self.find_user_data()
        c = str(user.username)
        posts = content_cache(user.username, pagename)
        pages = page_cache(user.username)
       
        if posts is not None and pages is not None: 
            self.render("display.html", pages = pages, page_link = pagename,  recent_posts = posts, content = pagename) 
                     
        else:
            self.render("display.html")

  

class Edit(MainHandler):
    
    def get(self, pagename):
        user = self.find_user_data()
        posts = content_cache(user.username, pagename)

##        posts = []

##        for p in post:
##            p.replace('<br>','\n')
            

##        posts = post.replace('\n', '<br>')
##        brainbug(post)

        if posts is not None:
            self.render("edit.html", recent_posts = posts) 
            
        else:
            self.render("display.html")

    def post(self, pagename):
        user = self.find_user_data()
        c = str(user.username)
        entry = self.request.get_all('edit')
        key = blog_key(c, pagename)
        content = Content.all()

        posts = content.ancestor(key).fetch(limit=None)
        grouped_entry = grouper(entry, 3)
        to_delete = None
        i = 0
        for k in grouped_entry:
##                 description = description_data.replace('\n', '<br>')
##        links = links_data.replace('\n', '<br>')
            posts[i].title = k[0].replace('\n', '<br>')
            posts[i].description = k[1].replace('\n', '<br>')
            posts[i].links = k[2].split('\n') ########################################################
##            posts[i].links = k[2].replace('\n', '<br>') 

            if posts[i].title == "" and posts[i].description == "" and posts[i].links.count("") == len(posts[i].links):
                to_delete = posts[i]      
            i+= 1

        db.put(posts)
        time.sleep(0.1)

        if to_delete is not None:
            db.delete(to_delete)
        
        content_cache(user.username, pagename, True)
        self.redirect('/home/{}'.format(pagename))

        
class Delete(MainHandler):

    def get(self, pagename):
        user = self.find_user_data()
        content = content_cache(user.username,pagename, False, True)
        db.delete(content)

        p =  "SELECT * FROM Pages WHERE username = '{}' and pagename = '{}'".format(user.username, pagename)
        page = db.GqlQuery(p)
        db.delete(page)
        time.sleep(0.1)
        page_cache(user.username, True)

        self.redirect('/home')

    
class LogoutHandler(MainHandler):
    def get(self):
        cookie_id = self.request.cookies.get('id')
        
        if cookie_id:
            user = self.find_user_data(True, True)
            pages = page_cache(user.username)
            home_key = blog_key(user.username, 'home')
            key_list = []
            
            for page in pages:
                memcache_key = blog_key(user.username, page.pagename)
                brainbug(memcache_key)
                a = str(memcache_key)
     
                key_list.append(a)
             
            key_list.append(str(home_key))    
            brainbug(key_list)      
            memcache.delete(str(user.username))
            memcache.delete(str(user.cookie))
            memcache.delete_multi(key_list)
            memcache.delete('home')
            user.cookie = None
            user.put()    
            self.set_cookies(value=None,expires_days=0)
            self.redirect('/')

        else:
            self.redirect('/')
            
##        aA-zZ
def brainbug(thing):
    return logging.debug('THE MORE YOU KNOW {}'.format(thing))      

app = webapp2.WSGIApplication([('/',LogIn ), ('/home', HomeHandler),('/newpost/([a-zA-Z0-9_-]+)', NewPost),
                               ('/newpage', NewPage), ('/home/([a-zA-Z0-9_-]+)', Page), ('/signup', SignUp), ('/edit/([a-zA-Z0-9_-]+)', Edit), ('/delete/([a-zA-Z0-9_-]+)', Delete), ('/logout', LogoutHandler)], debug=True)
