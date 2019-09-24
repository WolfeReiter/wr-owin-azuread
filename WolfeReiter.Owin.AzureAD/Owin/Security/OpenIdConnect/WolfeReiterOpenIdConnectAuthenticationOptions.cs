using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Security.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using WolfeReiter.Owin.AzureAD.Utils;

namespace WolfeReiter.Owin.Security.OpenIdConnect
{
    public class WolfeReiterOpenIdConnectAuthenticationOptions : OpenIdConnectAuthenticationOptions
    {
        public WolfeReiterOpenIdConnectAuthenticationOptions() : this(OpenIdConnectAuthenticationDefaults.AuthenticationType) { }
        public WolfeReiterOpenIdConnectAuthenticationOptions(string authenticationType) : base(authenticationType)
        {
            ProtocolValidator = new OpenIdConnectProtocolValidator()
            {
                NonceLifetime = TimeSpan.FromMinutes(15),
                /*****************************************
                 * Rare event, but blocks authentication *
                 *****************************************/
                //Event Message: [Microsoft.IdentityModel.Protocols.OpenIdConnectProtocolInvalidNonceException] 
                //IDX10311: RequireNonce is 'true' (default) but validationContext.Nonce is null. A nonce cannot be validated. 
                //If you don't need to check the nonce, set OpenIdConnectProtocolValidator.RequireNonce to 'false'.
                //
                // Possible Scenarios:
                // 
                // 1. This browser is configured to block cookies.
                // 2. Application is embedded in an iframe in another website and the user has disabled 3rd party cookies.
                // 3. The browser has an adblocker extension installed that is preventing the nonce cookie from being returned.

                RequireNonce = ConfigHelper.RequireNonce
            };
        }
    }
}