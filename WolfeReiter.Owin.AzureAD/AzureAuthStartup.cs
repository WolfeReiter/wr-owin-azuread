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
using WolfeReiter.Owin.Security.OpenIdConnect;

namespace WolfeReiter.Owin.AzureAD
{
    public static class AzureAuthStartup
    {
        /// <summary>
        /// To be called by Owin Startup class Configuration(IAppBuilder) method.
        /// </summary>
        /// <param name="app"></param>
        public static void ConfigureAuth(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);
            app.UseCookieAuthentication(new CookieAuthenticationOptions() { ExpireTimeSpan = TimeSpan.FromHours(18), SlidingExpiration = true });
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
                             string path = null;
                             try
                             {
                                 //empirically this is sometimes throwing a NullReferenceException on IIS 8.5 on Windows Server 2012 R2.
                                 path = HttpContext.Current.Request.Url.GetLeftPart(UriPartial.Path);
                             }
                             catch(NullReferenceException)
                             {
                                 path = ConfigHelper.FallbackRedirectUri;
                             }
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

        /// <summary>
        /// To be called by Global.asax.cs Application_PostAuthenticateRequest() handler.
        /// </summary>
        public static void PostAuthenticateRequest()
        {
            var context = HttpContext.Current;
            if (ClaimsPrincipal.Current.Identity.IsAuthenticated)
            {
                var transformer = FederatedAuthentication.FederationConfiguration.IdentityConfiguration.ClaimsAuthenticationManager;
                var newPrincipal = transformer.Authenticate(string.Empty, ClaimsPrincipal.Current);
                Thread.CurrentPrincipal = newPrincipal;
                context.User = newPrincipal;
            }
        }
    }
}
