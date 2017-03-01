﻿using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using System;
using System.IdentityModel.Services;
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
                             var builder = new UriBuilder(HttpContext.Current.Request.Url.GetLeftPart(UriPartial.Path));
                             if (!string.IsNullOrEmpty(ConfigHelper.OpenIdConnectRedirectScheme)) builder.Scheme = ConfigHelper.OpenIdConnectRedirectScheme;
                             if (ConfigHelper.OpenIdConnectRedirectPort.HasValue) builder.Port = ConfigHelper.OpenIdConnectRedirectPort.Value;
                             var redirectUri = builder.Uri;
                             var credential = new ClientCredential(ConfigHelper.AzureClientId, ConfigHelper.AzureAppKey);
                             var userObjectID = context.AuthenticationTicket.Identity.FindFirst(AzureClaimTypes.ObjectIdentifier).Value;
                             var authContext = new AuthenticationContext(ConfigHelper.AzureAuthority);
                             var result = authContext.AcquireTokenByAuthorizationCode(
                                 context.Code, redirectUri, credential, ConfigHelper.AzureGraphResourceId);
                             return Task.FromResult(0);
                         },

                         AuthenticationFailed = context =>
                         {
                             context.HandleResponse();
                             context.Response.Redirect(String.Format(ConfigHelper.AzureAuthenticationFailedHandlerUrlTemplate, context.Exception.Message));
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
            if (ClaimsPrincipal.Current.Identity.IsAuthenticated)
            {
                var transformer = FederatedAuthentication.FederationConfiguration.IdentityConfiguration.ClaimsAuthenticationManager;
                try
                {
                    var newPrincipal = transformer.Authenticate(string.Empty, ClaimsPrincipal.Current);
                    Thread.CurrentPrincipal  = newPrincipal;
                    HttpContext.Current.User = newPrincipal;
                }
                catch(Exception ex)
                {
                    HttpContext.Current.Response.Redirect(String.Format(ConfigHelper.AzureAuthenticationFailedHandlerUrlTemplate, ex.Message));
                }
            }
        }
    }
}
