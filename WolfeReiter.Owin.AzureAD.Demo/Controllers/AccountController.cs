using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Security.Claims;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using WolfeReiter.Owin.AzureAD.Utils;
using System.Threading.Tasks;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Diagnostics;

namespace WolfeReiter.Owin.AzureAD.Demo.Controllers
{
    [HandleError]
    public class AccountController : Controller
    {
        /// <summary>
        /// Sends an OpenIDConnect Sign-In Request.
        /// </summary>
        public void SignIn(string redirectUri)
        {
            if(string.IsNullOrEmpty(redirectUri)) redirectUri = "/";

            HttpContext.GetOwinContext()
                .Authentication.Challenge(new AuthenticationProperties { RedirectUri = redirectUri },
                    OpenIdConnectAuthenticationDefaults.AuthenticationType);
        }

        /// <summary>
        /// Signs the user out and clears the cache of access tokens.
        /// </summary>
        public void SignOut()
        {
            // Remove all cache entries for this user and send an OpenID Connect sign-out request.
            if (Request.IsAuthenticated)
            {
                string userObjectID = ClaimsPrincipal.Current.FindFirst(AzureClaimTypes.ObjectIdentifier).Value;
                var authContext = new AuthenticationContext(ConfigHelper.AzureAuthority);
                var cacheitem = authContext.TokenCache.ReadItems().Where(x => x.UniqueId == userObjectID).SingleOrDefault();
                if(cacheitem != null) authContext.TokenCache.DeleteItem(cacheitem);

                HttpContext.GetOwinContext().Authentication.SignOut(
                    OpenIdConnectAuthenticationDefaults.AuthenticationType, CookieAuthenticationDefaults.AuthenticationType);
            }
        }
    }
}