"""
This source file (nevowopenid.py) is available under the MIT License.

Copyright (c) 2009 Drew Perttula

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

"""
import string
from openid.cryptutil import randomString
import openid.consumer.consumer
import openid.store.filestore
from nevow import inevow, rend, tags as T, loaders
from twisted.web import http

store = openid.store.filestore.FileOpenIDStore('/tmp/openid')
sess = {} # sessionid : {}

def makeCookie():
    return randomString(32, string.letters + string.digits)

def getOrCreateCookie(request):
    sessionid = request.getCookie('s')
    if sessionid is None:
        sessionid = makeCookie()
        request.addCookie('s', sessionid, expires=None,
                          domain=None, path='/', max_age=None,
                          comment=None, secure=False)
    return sessionid

class OpenidLogin(rend.Page):
    form = lambda: T.form(method="post", action="")    
    docFactory = loaders.stan([
        form()["openid: ", T.input(name="openid"),
               T.input(type='submit', value='login')],
        form()[T.input(type='hidden', name='openid',
                       value='https://www.google.com/accounts/o8/id'),
               T.input(type='submit', value='Use google account')],
        form()[T.input(type='hidden', name='openid', value='yahoo.com'),
               T.input(type='submit', value='Use yahoo account')],
            ])

def userGaveOpenid(request, sessionDict, userOpenidUrl, here, realm):
    # stash the user's requested openid in another cookie, so future
    # logins can try that one first? Good for server restarts, but I'm
    # not sure if it's appropriate UX for openid.
    
    c = openid.consumer.consumer.Consumer(sessionDict, store)
    info = c.begin(userOpenidUrl)
    redir = info.redirectURL(realm=realm, return_to=here)
    request.redirect(redir)
    return ""
    
def returnedFromProvider(request, sessionDict, here):
    argsSingle = dict((k, v[0]) for k,v in request.args.items())
    c = openid.consumer.consumer.Consumer(sessionDict, store)
    resp = c.complete(argsSingle, here)
    if resp.status != 'success':
        request.setResponseCode(http.UNAUTHORIZED)
        return "login failed: %s" % resp.message
    sessionDict['identity'] = resp.identity_url
    # clear query params
    request.redirect(here)
    return ""

def getSessionDict(ctx):    
    request = inevow.IRequest(ctx)
    sessionid = getOrCreateCookie(request)
    sessionDict = sess.setdefault(sessionid, {}) # grows forever
    return sessionDict

def openidStep(ctx, here, needOpenidUrl):
    """When getIdentity returns None, keep returning the result of
    this function. It will be a login page or some url redirect.

    After enough forms and trips to the openid provider (normally 3
    times), getIdentity will stop returning None and you can use the
    openid identity url."""

    request = inevow.IRequest(ctx)
    sessionDict = getSessionDict(ctx)
    if ctx.arg('openid.identity') is not None:
        return returnedFromProvider(request, sessionDict, here)
    elif ctx.arg('openid') is not None:
        return userGaveOpenid(request, sessionDict, ctx.arg('openid'),
                              here, realm="http://bigasterisk.com/")
    else:
        return needOpenidUrl()

class WithOpenid(object):
    """
    Mixin class for replacing locateChild with a version that requires
    a verified openid before it shows any children.
    """
    def locateChild(self, ctx, segments):
        """this may display alternate challenge and redirect pages if
        the user is not yet logged in. But once it does call super's
        locateChild, self.identity will be set to the openid url that
        we verified."""
        self.identity = self.getOpenidIdentity(ctx)
        if self.identity is None:
            request = inevow.IRequest(ctx)
            return openidStep(ctx, self.fullUrl(ctx), self.needOpenidUrl), []

        self.verifyIdentity()
        # todo: if this raises, we should forget this user's cookie so
        # he can try again with a different id.
        
        return super(WithOpenid, self).locateChild(ctx, segments)

    def fullUrl(self, ctx):
        """
        make sure this returns a working URL to the current resource
        """
        request = inevow.IRequest(ctx)
        return 'http://bigasterisk.com/exchangeMeeting' + request.path

    def verifyIdentity(self):
        """raise if self.identity is not allowed to access the
        resource. You don't have to ever raise here; you can always
        use the id in self.identity in the rest of your page processing."""
        pass

        # example:
        # if self.identity not in ['http://example.com/id1', 'http://example.com/id2']:
        #    raise ValueError("unknown user")

    def getOpenidIdentity(self, ctx):
        """
        Either an openid identity url that has been verified, or None. If
        you get None, use openidStep to start the openid consumer sequence.
        """
        return getSessionDict(ctx).get('identity', None)

    def needOpenidUrl(self):
        """return a form to get a parameter named 'openid' with the
        user's requested openid url"""
        return OpenidLogin()
