using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using System;
using System.IdentityModel.Services;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using WolfeReiter.Owin.AzureAD.Utils;
using WolfeReiter.Owin.Security.Cookies;
using WolfeReiter.Owin.Security.OpenIdConnect;

namespace WolfeReiter.Owin.AzureAD
{
    public static class AzureAuthStartup
    {
        /// To be called by Owin Startup class Configuration(IAppBuilder) method.
        /// </summary>
        /// <param name="app"></param>
        public static void ConfigureAuth(IAppBuilder app)
        {
            /**
            * OWIN by default uses HttpContext.Response.Headers for storing its response cookies. All legacy .NET System.Web classes
            * prior to .NET Core (including .NET 4.0, 4.5.x, 4.6.x, 4.7, etc.) all use System.Web.HttpResponse.Cookies which
            * can overwrite the cookies in HttpResponse.Headers at the end of request processing. Use of System.Web.Response.Cookeis, 
            * such as using SessionState including MVC TempData[] can cause Owin authentication cookies to dissapear randomly. 
            * Once that occurs, nobody can log in.
            **/
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);
            app.UseCookieAuthentication(new CookieAuthenticationOptions()
            {
                CookieManager     = new SystemWebCookieManager(), //forces OWIN to use Response.Cookies for storage compatibility
                ExpireTimeSpan    = TimeSpan.FromHours(18),
                SlidingExpiration = true,
                CookieName        = ConfigHelper.CookieName,
                CookieSecure      = ConfigHelper.CookieSecureOption
            });
            app.UseWolfeReiterOpenIdConnectAuthentication(
                 new WolfeReiterOpenIdConnectAuthenticationOptions()
                 {
                     ClientId = ConfigHelper.AzureClientId,
                     Authority = ConfigHelper.AzureAuthority,
                     PostLogoutRedirectUri = ConfigHelper.PostLogoutRedirectUri,
                     Notifications = new OpenIdConnectAuthenticationNotifications()
                     {
                         AuthorizationCodeReceived = context =>
                         {
                             var authContext = new AuthenticationContext(ConfigHelper.AzureAuthority);
                             //manual cache invalidation
                             var userObjectID = context.AuthenticationTicket.Identity.FindFirst(AzureClaimTypes.ObjectIdentifier).Value;
                             var cacheitem = authContext.TokenCache.ReadItems().Where(x => x.UniqueId == userObjectID).SingleOrDefault();
                             if (cacheitem != null) authContext.TokenCache.DeleteItem(cacheitem);
                             //get target redirect
                             string path = ConfigHelper.FallbackRedirectUri;
                             var builder = new UriBuilder(path);
                             if (!string.IsNullOrEmpty(ConfigHelper.OpenIdConnectRedirectScheme)) builder.Scheme = ConfigHelper.OpenIdConnectRedirectScheme;
                             if (ConfigHelper.OpenIdConnectRedirectPort.HasValue) builder.Port = ConfigHelper.OpenIdConnectRedirectPort.Value;
                             var redirectUri = builder.Uri;
                             //azure credential
                             var credential = new ClientCredential(ConfigHelper.AzureClientId, ConfigHelper.AzureAppKey);
                             //request authentication service
                             var result = authContext.AcquireTokenByAuthorizationCode(
                                 context.Code, redirectUri, credential, ConfigHelper.AzureGraphResourceId);
                             return Task.FromResult(0);
                         },

                         AuthenticationFailed = context =>
                         {
                             context.HandleResponse();
                             LogUtility.WriteEventLogEntry(LogUtility.FormatException(context.Exception, "AzureAD Authentication Handshake Failed"), EventType.Warning);
                             var message = context.Exception.Message;
							 if (message.StartsWith("IDX10311:", StringComparison.InvariantCulture))
							 {
                                 message = "Your Azure authentication token is expired or has been invalidated.";
							 }
                             context.Response.Redirect(String.Format(ConfigHelper.AzureAuthenticationFailedHandlerUrlTemplate, message));
                             return Task.FromResult(0);
                         }
                     }
                 });
        }
    }
}
