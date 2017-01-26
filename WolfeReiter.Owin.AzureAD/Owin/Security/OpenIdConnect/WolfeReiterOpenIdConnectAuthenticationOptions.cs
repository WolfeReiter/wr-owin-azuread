using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Security.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace WolfeReiter.Owin.Security.OpenIdConnect
{
    public class WolfeReiterOpenIdConnectAuthenticationOptions : OpenIdConnectAuthenticationOptions
    {
        public WolfeReiterOpenIdConnectAuthenticationOptions() : this(OpenIdConnectAuthenticationDefaults.AuthenticationType) { }
        public WolfeReiterOpenIdConnectAuthenticationOptions(string authenticationType) : base(authenticationType)
        {
            ProtocolValidator = new OpenIdConnectProtocolValidator()
            {
                NonceLifetime = TimeSpan.FromMinutes(15)
            };
        }
    }
}