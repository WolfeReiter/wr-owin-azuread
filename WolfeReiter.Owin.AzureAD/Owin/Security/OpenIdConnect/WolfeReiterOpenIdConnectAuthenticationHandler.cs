using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using System.Text;

namespace WolfeReiter.Owin.Security.OpenIdConnect
{
    public class WolfeReiterOpenIdConnectAuthenticationHandler : OpenIdConnectAuthenticationHandler
    {
        private const string NonceProperty = "N";

        public WolfeReiterOpenIdConnectAuthenticationHandler(ILogger logger) : base(logger) { }

        /*
         *  Option A: Shorten TTL on cookies to 15 mintues
         *  based on: https://github.com/aspnet/Security/pull/432/files
         *  add exlicit expiration to nonce cookies
         */
        protected override void RememberNonce(OpenIdConnectMessage message, string nonce)
        {
            if (message == null)
            {
                throw new ArgumentNullException("message");
            }

            if (nonce == null)
            {
                throw new ArgumentNullException("nonce");
            }

            // remove any existing nonce cookies
            var nonceCookies = Request.Cookies.Where(x => x.Key.StartsWith(OpenIdConnectAuthenticationDefaults.CookiePrefix + "nonce"));
            var cookieOptions = new CookieOptions()
            {
                HttpOnly = true,
                Secure = Request.IsSecure
            };
            
            // cleanup if cookie count is getting out of hand
            if(nonceCookies.Count() > 3)
            {
                foreach (var nonceCookie in nonceCookies)
                {
                    Response.Cookies.Delete(nonceCookie.Key, cookieOptions);
                }
            }

            AuthenticationProperties properties = new AuthenticationProperties();
            properties.Dictionary.Add(NonceProperty, nonce);
            Response.Cookies.Append(
                GetNonceKey(nonce),
                Convert.ToBase64String(Encoding.UTF8.GetBytes(Options.StateDataFormat.Protect(properties))),
                new CookieOptions
                {
                    HttpOnly = true,
                    Secure = Request.IsSecure,
                    Expires = DateTime.UtcNow + Options.ProtocolValidator.NonceLifetime
                });
        }

        /*
         *  Option B: Brutal delete cookies every time
         *  this option does not require the WolfeReiterOpenIdConnectAuthenicationOptions.cs class
         *  just delete any existing nonce cookies and create a new one
         */
        //protected override void RememberNonce(OpenIdConnectMessage message, string nonce)
        //{
        //    var nonceCookies = Request.Cookies.Where(x => x.Key.StartsWith(OpenIdConnectAuthenticationDefaults.CookiePrefix + "nonce"));
        //    if(nonceCookies.Any())
        //    {
        //        var cookieOptions = new CookieOptions()
        //        {
        //            HttpOnly = true,
        //            Secure   = Request.IsSecure
        //        };
        //        foreach(var nonceCookie in nonceCookies)
        //        {
        //            Response.Cookies.Delete(nonceCookie.Key, cookieOptions);
        //        }
        //    }
        //    base.RememberNonce(message, nonce);
        //}
    }
}