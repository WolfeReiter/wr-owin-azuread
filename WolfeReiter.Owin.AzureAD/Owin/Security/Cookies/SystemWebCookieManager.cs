using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using WolfeReiter.Owin;

namespace WolfeReiter.Owin.Security.Cookies
{
    /// <summary>
    /// Cookie manager to replace the default implementation in Microsoft.Owin.Security.Cookies to use the same storage
    /// as System.Web.SessionStateModule to prevent race condition which can lead to Owin authentication cookies being
    /// lost and user trapped in an external authentication loop. This is Microsoft implementation problem that is fixed in 
    /// ASP.NET Core 1.0.
    /// </summary>
    /// <remarks>
    /// &lt;p&gt;There seems to be a problem with cookies implementation in SystemWeb hosting when mixing usage of
    /// HttpContext.GetOwinContext().Response.Cookies and HttpContext.Response.Cookies (for example default SessionStateModule). 
    /// In some cases OWIN cookies are "lost" and not send to the browser.&lt;/p&gt;
    /// 
    /// &lt;p&gt;In case of SessionStateModule this can be quite fatal. If you use session (store some values) but after the user 
    /// authenticated, it is impossible for other users to login through OWIN anymore. OWIN authentication response cookies are 
    /// "lost" during response processing.&lt;/p&gt;
    /// </remarks>
    /// <seealso cref="http://stackoverflow.com/questions/20737578/asp-net-sessionid-owin-cookies-do-not-send-to-browser"/>
    /// <seealso cref="http://katanaproject.codeplex.com/wikipage?title=System.Web%20response%20cookie%20integration%20issues"/>
    public class SystemWebCookieManager : ICookieManager
    {
        public void AppendResponseCookie(IOwinContext context, string key, string value, CookieOptions options)
        {
            if (context == null) throw new ArgumentNullException("context");
            if (options == null) throw new ArgumentNullException("options");

            var httpContext      = context.GetHttpContext();
            bool domainHasValue  = !string.IsNullOrEmpty(options.Domain);
            bool pathHasValue    = !string.IsNullOrEmpty(options.Path);
            bool expiresHasValue = options.Expires.HasValue;

            var cookie = new HttpCookie(key, value);
            if (domainHasValue)
            {
                cookie.Domain = options.Domain;
            }
            if (pathHasValue)
            {
                cookie.Path = options.Path;
            }
            if (expiresHasValue)
            {
                cookie.Expires = options.Expires.Value;
            }
            if (options.Secure)
            {
                cookie.Secure = true;
            }
            if (options.HttpOnly)
            {
                cookie.HttpOnly = true;
            }

            httpContext.Response.AppendCookie(cookie);
        }

        public void DeleteCookie(IOwinContext context, string key, CookieOptions options)
        {
            if (context == null) throw new ArgumentNullException("context");
            if (options == null) throw new ArgumentNullException("options");

            AppendResponseCookie(
                context,
                key,
                string.Empty,
                new CookieOptions
                {
                    Path    = options.Path,
                    Domain  = options.Domain,
                    Expires = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)
                });
        }

        public string GetRequestCookie(IOwinContext context, string key)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            var webContext = context.GetHttpContext();
            var cookie     = webContext.Request.Cookies[key];

            return cookie == null ? null : cookie.Value;
        }
    }
}
