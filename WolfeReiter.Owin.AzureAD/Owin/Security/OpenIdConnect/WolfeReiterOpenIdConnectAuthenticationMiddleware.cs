using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace WolfeReiter.Owin.Security.OpenIdConnect
{
    public class WolfeReiterOpenIdConnectAuthenticationMiddleware : OpenIdConnectAuthenticationMiddleware
    {
        readonly ILogger _logger;

        public WolfeReiterOpenIdConnectAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, OpenIdConnectAuthenticationOptions options) 
            : base(next, app, options)
        {
            _logger = app.CreateLogger<WolfeReiterOpenIdConnectAuthenticationMiddleware>();
        }

        protected override AuthenticationHandler<OpenIdConnectAuthenticationOptions> CreateHandler()
        {
            return new WolfeReiterOpenIdConnectAuthenticationHandler(_logger);
        }
    }
}