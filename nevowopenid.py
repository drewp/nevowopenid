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
import string, os
# google logins work better with python_openid==2.2.4
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
        request.addCookie('s', sessionid,
                          expires="Wed, 01-Jan-2020 00:00:00 GMT",
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

def expandOpenidProviderAbbreviation(url):
    """user can give some shorthand words instead of openid provider
    URLs. This helps fit certain links on one line of email"""
    d = {
        'google' : 'https://www.google.com/accounts/o8/id',
        'yahoo' : 'yahoo.com',
        }
    return d.get(url, url)

def userGaveOpenid(request, sessionDict, userOpenidUrl, here, realm):
    """
    userOpenidUrl can be an abbreviation known to
    expandOpenidProviderAbbreviation
    """
    # stash the user's requested openid in another cookie, so future
    # logins can try that one first? Good for server restarts, but I'm
    # not sure if it's appropriate UX for openid.
    
    c = openid.consumer.consumer.Consumer(sessionDict, store)
    info = c.begin(expandOpenidProviderAbbreviation(userOpenidUrl))
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

def syncSessionStore(sess, key=None):
    if key is not None:
        sess[key] = sess[key]
    if hasattr(sess, 'sync'):
        sess.sync()

def getSessionDict(ctx):
    """this is returning this session's key in the sessions dict too,
    so you can pass it to syncSessionStore"""
    request = inevow.IRequest(ctx)
    sessionid = getOrCreateCookie(request)
    if sessionid not in sess:
        sess[sessionid] = {}  # grows forever
        syncSessionStore(sess)
    sessionDict = sess[sessionid]
    return sessionDict, sessionid

def forgetSession(ctx):
    request = inevow.IRequest(ctx)
    sessionid = getOrCreateCookie(request)
    del sess[sessionid]
    syncSessionStore(sess)

def openidStep(ctx, here, needOpenidUrl, realm):
    """When getIdentity returns None, keep returning the result of
    this function. It will be a login page or some url redirect.

    After enough forms and trips to the openid provider (normally 3
    times), getIdentity will stop returning None and you can use the
    openid identity url."""

    request = inevow.IRequest(ctx)
    sessionDict, key = getSessionDict(ctx)
    if ctx.arg('openid.identity') is not None:
        ret = returnedFromProvider(request, sessionDict, here)
    elif ctx.arg('openid') is not None or ctx.arg('openid_aol') is not None:

        if ctx.arg('openid_aol') is not None:
            openid = 'http://openid.aol.com/' + ctx.arg('openid_aol')
        else:
            openid = ctx.arg('openid')
        
        # todo: if the user's url doesn't actually do openid, this
        # will fail, and should make a better error message
        ret = userGaveOpenid(request, sessionDict, openid,
                              here, realm=realm)
    else:
        ret = needOpenidUrl()
    syncSessionStore(sess, key)
    return ret

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
            if (not self.anonymousAllowed(ctx) or
                # you can always use /login to start the login sequence
                # (useful if this resource is allowing anonymous
                # users). This could be a problem if your real resource
                # has a /login child

                # wrong- this needs to check after the site root,
                # somehow. I don't mean to be matching -any- login
                # segment, but it should be ok in practice
                segments[-1] == 'login'):
                request = inevow.IRequest(ctx)
                return openidStep(ctx, self.fullUrl(ctx), self.needOpenidUrl,
                                  self.getRealm(ctx)), []


        if segments[-1] == 'login':
            # we don't want to come back to this login page once we're
            # logged in; so I just go to the root. Someday we might
            # want a return-to-this-page variable to get used. A
            # better redirect would be to use this resource without
            # the /login component, but that's hard to get right
            # (vhosts, etc). Or, this could switch to ?openidLogin,
            # which would probably be harmless and not need a
            # redirect.
            request = inevow.IRequest(ctx)
            request.redirect('/')
            return "", []

        if segments[-1] == 'logout':
            forgetSession(ctx)
            return self.logoutPage(), []
        
        try:
            self.verifyIdentity(ctx)
        except ValueError:
            forgetSession(ctx)
            raise
        
        return super(WithOpenid, self).locateChild(ctx, segments)


    def logoutPage(self):
        return "Logged out."

    def anonymousAllowed(self, ctx):
        """should we intercept requests and prompt for openid?

        Note that either way, verifyIdentity will be called, so if you
        return True here you also need to allow a self.identity of
        None in the verifyIdentity method
        """
        return False

    def fullUrl(self, ctx):
        """
        make sure this returns a working URL to the current resource
        """
        request = inevow.IRequest(ctx)
        return 'http://bigasterisk.com/exchangeMeeting' + request.path

    def getRealm(self, ctx):
        return "http://bigasterisk.com/"

    def verifyIdentity(self, ctx):
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
        d, key = getSessionDict(ctx)
        return d.get('identity', None)

    def needOpenidUrl(self):
        """return a form to get a parameter named 'openid' with the
        user's requested openid url"""
        return OpenidLogin()
