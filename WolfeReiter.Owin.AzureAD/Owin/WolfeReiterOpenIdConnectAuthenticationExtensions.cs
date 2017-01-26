using WolfeReiter.Owin.Security.OpenIdConnect;
using Microsoft.Owin.Security.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Owin
{
    public static class WolfeReiterOpenIdConnectAuthenticationExtensions
    {
        public static IAppBuilder UseWolfeReiterOpenIdConnectAuthentication(this IAppBuilder app, WolfeReiterOpenIdConnectAuthenticationOptions openIdConnectOptions)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }

            if (openIdConnectOptions == null)
            {
                throw new ArgumentNullException("openIdConnectOptions");
            }

            return app.Use(typeof(WolfeReiterOpenIdConnectAuthenticationMiddleware), app, openIdConnectOptions);
        }
    }
}