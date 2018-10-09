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
                NonceLifetime = TimeSpan.FromMinutes(15),
                /*****************************************
                 * Rare event, but blocks authentication *
                 *****************************************/
                //Event Message: [Microsoft.IdentityModel.Protocols.OpenIdConnectProtocolInvalidNonceException] 
                //IDX10311: RequireNonce is 'true' (default) but validationContext.Nonce is null. A nonce cannot be validated. 
                //If you don't need to check the nonce, set OpenIdConnectProtocolValidator.RequireNonce to 'false'.
                RequireNonce = false
            };
        }
    }
}