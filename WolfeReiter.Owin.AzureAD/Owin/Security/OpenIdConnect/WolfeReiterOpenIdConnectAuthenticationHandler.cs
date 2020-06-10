using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using System.Text;
using WolfeReiter.Owin.AzureAD.Utils;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Notifications;
using System.IdentityModel.Tokens;
using System.Threading.Tasks;
using System.IO;
using System.Runtime.ExceptionServices;
using System.Globalization;
using System.Security.Claims;
using Microsoft.IdentityModel.Extensions;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace WolfeReiter.Owin.Security.OpenIdConnect
{
    public class WolfeReiterOpenIdConnectAuthenticationHandler : OpenIdConnectAuthenticationHandler
    {
        private const string HandledResponse = "HandledResponse";
        private const string NonceProperty = "N";

        private readonly ILogger _logger;
        private OpenIdConnectConfiguration _configuration;

        public WolfeReiterOpenIdConnectAuthenticationHandler(ILogger logger) : base(logger)
        {
            _logger = logger;
        }


        bool CookieSecure
        {
            get
            {
                switch (ConfigHelper.CookieSecureOption)
                {
                    case CookieSecureOption.Never:
                        return false;
                    case CookieSecureOption.Always:
                        return true;
                    case CookieSecureOption.SameAsRequest:
                        return Request.IsSecure;
                    default:
                        return Request.IsSecure;
                }
            }
        }

        /*
         *  Option A: Shorten TTL on cookies to 15 mintues
         *  based on: https://github.com/aspnet/Security/pull/432/files
         *  add exlicit expiration to nonce cookies
         */
        protected override void RememberNonce(OpenIdConnectMessage message, string nonce)
        {
            if (message == null)
            {
                throw new ArgumentNullException("message");
            }

            if (nonce == null)
            {
                throw new ArgumentNullException("nonce");
            }

            // remove any existing nonce cookies
            var nonceCookies = Request.Cookies.Where(x => x.Key.StartsWith(OpenIdConnectAuthenticationDefaults.CookiePrefix + "nonce"));
            var cookieOptions = new CookieOptions()
            {
                HttpOnly = true,
                Secure = CookieSecure
            };


            // cleanup if cookie count is getting out of hand
            if (nonceCookies.Count() > 3)
            {
                foreach (var nonceCookie in nonceCookies)
                {
                    Options.CookieManager.DeleteCookie(Context, nonceCookie.Key, cookieOptions);
                }
            }

            AuthenticationProperties properties = new AuthenticationProperties();
            properties.Dictionary.Add(NonceProperty, nonce);
            Options.CookieManager.AppendResponseCookie(
                Context,
                GetNonceKey(nonce),
                Convert.ToBase64String(Encoding.UTF8.GetBytes(Options.StateDataFormat.Protect(properties))),
                new CookieOptions
                {
                    HttpOnly = true,
                    Secure = CookieSecure,
                    Expires = DateTime.UtcNow + Options.ProtocolValidator.NonceLifetime
                });
        }

        /*
         *  Option B: Brutal delete cookies every time
         *  this option does not require the WolfeReiterOpenIdConnectAuthenicationOptions.cs class
         *  just delete any existing nonce cookies and create a new one
         */
        //protected override void RememberNonce(OpenIdConnectMessage message, string nonce)
        //{
        //    var nonceCookies = Request.Cookies.Where(x => x.Key.StartsWith(OpenIdConnectAuthenticationDefaults.CookiePrefix + "nonce"));
        //    if(nonceCookies.Any())
        //    {
        //        var cookieOptions = new CookieOptions()
        //        {
        //            HttpOnly = true,
        //            Secure   = CookieSecure
        //        };
        //        foreach(var nonceCookie in nonceCookies)
        //        {
        //            Response.Cookies.Delete(nonceCookie.Key, cookieOptions);
        //        }
        //    }
        //    base.RememberNonce(message, nonce);
        //}

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            // Allow login to be constrained to a specific path. Need to make this runtime configurable.
            if (Options.CallbackPath.HasValue && Options.CallbackPath != (Request.PathBase + Request.Path))
            {
                return null;
            }

            OpenIdConnectMessage openIdConnectMessage = null;

            // assumption: if the ContentType is "application/x-www-form-urlencoded" it should be safe to read as it is small.
            if (string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase)
              && !string.IsNullOrWhiteSpace(Request.ContentType)
              // May have media/type; charset=utf-8, allow partial match.
              && Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)
              && Request.Body.CanRead)
            {
                if (!Request.Body.CanSeek)
                {
                    _logger.WriteVerbose("Buffering request body");
                    // Buffer in case this body was not meant for us.
                    MemoryStream memoryStream = new MemoryStream();
                    await Request.Body.CopyToAsync(memoryStream);
                    memoryStream.Seek(0, SeekOrigin.Begin);
                    Request.Body = memoryStream;
                }

                IFormCollection form = await Request.ReadFormAsync();
                Request.Body.Seek(0, SeekOrigin.Begin);

                // TODO: a delegate on OpenIdConnectAuthenticationOptions would allow for users to hook their own custom message.
                openIdConnectMessage = new OpenIdConnectMessage(form);
            }

            if (openIdConnectMessage == null)
            {
                return null;
            }

            ExceptionDispatchInfo authFailedEx = null;
            try
            {
                var messageReceivedNotification = new MessageReceivedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions>(Context, Options)
                {
                    ProtocolMessage = openIdConnectMessage
                };
                await Options.Notifications.MessageReceived(messageReceivedNotification);
                if (messageReceivedNotification.HandledResponse)
                {
                    return GetHandledResponseTicket();
                }
                if (messageReceivedNotification.Skipped)
                {
                    return null;
                }

                // runtime always adds state, if we don't find it OR we failed to 'unprotect' it this is not a message we
                // should process.
                AuthenticationProperties properties = GetPropertiesFromState(openIdConnectMessage.State);
                if (properties == null)
                {
                    _logger.WriteWarning("The state field is missing or invalid.");
                    return null;
                }

                // devs will need to hook AuthenticationFailedNotification to avoid having 'raw' runtime errors displayed to users.
                if (!string.IsNullOrWhiteSpace(openIdConnectMessage.Error))
                {
                    throw new OpenIdConnectProtocolException(
                        string.Format(CultureInfo.InvariantCulture,
                                      openIdConnectMessage.Error,
                                      /*Resources.*/Exception_OpenIdConnectMessageError, openIdConnectMessage.ErrorDescription ?? string.Empty, openIdConnectMessage.ErrorUri ?? string.Empty));
                }

                // code is only accepted with id_token, in this version, hence check for code is inside this if
                // OpenIdConnect protocol allows a Code to be received without the id_token
                if (string.IsNullOrWhiteSpace(openIdConnectMessage.IdToken))
                {
                    _logger.WriteWarning("The id_token is missing.");
                    return null;
                }

                var securityTokenReceivedNotification = new SecurityTokenReceivedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions>(Context, Options)
                {
                    ProtocolMessage = openIdConnectMessage,
                };
                await Options.Notifications.SecurityTokenReceived(securityTokenReceivedNotification);
                if (securityTokenReceivedNotification.HandledResponse)
                {
                    return GetHandledResponseTicket();
                }
                if (securityTokenReceivedNotification.Skipped)
                {
                    return null;
                }

                if (_configuration == null)
                {
                    _configuration = await Options.ConfigurationManager.GetConfigurationAsync(Context.Request.CallCancelled);
                }

                // Copy and augment to avoid cross request race conditions for updated configurations.
                TokenValidationParameters tvp = Options.TokenValidationParameters.Clone();
                IEnumerable<string> issuers = new[] { _configuration.Issuer };
                tvp.ValidIssuers = (tvp.ValidIssuers == null ? issuers : tvp.ValidIssuers.Concat(issuers));
                tvp.IssuerSigningTokens = (tvp.IssuerSigningTokens == null ? _configuration.SigningTokens : tvp.IssuerSigningTokens.Concat(_configuration.SigningTokens));

                SecurityToken validatedToken;
                ClaimsPrincipal principal = Options.SecurityTokenHandlers.ValidateToken(openIdConnectMessage.IdToken, tvp, out validatedToken);
                ClaimsIdentity claimsIdentity = principal.Identity as ClaimsIdentity;

                Regex roleFilter = null;
                if (!String.IsNullOrWhiteSpace(ConfigHelper.RoleFilterPattern)) roleFilter = new Regex(ConfigHelper.RoleFilterPattern);

                //convert Azure "groups" claim of Guids to Role claims by looking up the Group DisplayName in Microsoft Graph
                var groups = (await AzureGraphHelper.AzureGroups(principal)).Select(x => x.DisplayName);
                foreach (var group in groups)
                {
                    //the filter regex will only add matched roled names that are used by the application in order to limit the cookie size
                    if (roleFilter == null || roleFilter.IsMatch(group))
                    {
                        claimsIdentity.AddClaim(new Claim(ClaimTypes.Role, group, ClaimValueTypes.String, "AzureAD"));
                    }

                }

                //remove groups cliams -- which are simply GUIDs -- in order to reduce cookie size
                if (ConfigHelper.RemoveAzureGroupClaims)
                {
                    //remove Azure "groups" claims to save space
                    var groupClaims = claimsIdentity.Claims.Where(x => x.Type == "groups").ToList();
                    foreach (var claim in groupClaims)
                    {
                        claimsIdentity.TryRemoveClaim(claim);
                    }
                }

                // claims principal could have changed claim values, use bits received on wire for validation.
                JwtSecurityToken jwt = validatedToken as JwtSecurityToken;
                AuthenticationTicket ticket = new AuthenticationTicket(claimsIdentity, properties);

                string nonce = null;
                if (Options.ProtocolValidator.RequireNonce)
                {
                    if (String.IsNullOrWhiteSpace(openIdConnectMessage.Nonce))
                    {
                        openIdConnectMessage.Nonce = jwt.Payload.Nonce;
                    }

                    // deletes the nonce cookie
                    nonce = RetrieveNonce(openIdConnectMessage);
                }

                // remember 'session_state' and 'check_session_iframe'
                if (!string.IsNullOrWhiteSpace(openIdConnectMessage.SessionState))
                {
                    ticket.Properties.Dictionary[OpenIdConnectSessionProperties.SessionState] = openIdConnectMessage.SessionState;
                }

                if (!string.IsNullOrWhiteSpace(_configuration.CheckSessionIframe))
                {
                    ticket.Properties.Dictionary[OpenIdConnectSessionProperties.CheckSessionIFrame] = _configuration.CheckSessionIframe;
                }

                if (Options.UseTokenLifetime)
                {
                    // Override any session persistence to match the token lifetime.
                    DateTime issued = jwt.ValidFrom;
                    if (issued != DateTime.MinValue)
                    {
                        ticket.Properties.IssuedUtc = issued.ToUniversalTime();
                    }
                    DateTime expires = jwt.ValidTo;
                    if (expires != DateTime.MinValue)
                    {
                        ticket.Properties.ExpiresUtc = expires.ToUniversalTime();
                    }
                    ticket.Properties.AllowRefresh = false;
                }

                var securityTokenValidatedNotification = new SecurityTokenValidatedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions>(Context, Options)
                {
                    AuthenticationTicket = ticket,
                    ProtocolMessage = openIdConnectMessage,
                };
                await Options.Notifications.SecurityTokenValidated(securityTokenValidatedNotification);
                if (securityTokenValidatedNotification.HandledResponse)
                {
                    return GetHandledResponseTicket();
                }
                if (securityTokenValidatedNotification.Skipped)
                {
                    return null;
                }
                // Flow possible changes
                ticket = securityTokenValidatedNotification.AuthenticationTicket;

                var protocolValidationContext = new OpenIdConnectProtocolValidationContext
                {
                    AuthorizationCode = openIdConnectMessage.Code,
                    Nonce = nonce,
                };

                Options.ProtocolValidator.Validate(jwt, protocolValidationContext);

                if (openIdConnectMessage.Code != null)
                {
                    var authorizationCodeReceivedNotification = new AuthorizationCodeReceivedNotification(Context, Options)
                    {
                        AuthenticationTicket = ticket,
                        Code = openIdConnectMessage.Code,
                        JwtSecurityToken = jwt,
                        ProtocolMessage = openIdConnectMessage,
                        RedirectUri = ticket.Properties.Dictionary.ContainsKey(OpenIdConnectAuthenticationDefaults.RedirectUriUsedForCodeKey) ?
                            ticket.Properties.Dictionary[OpenIdConnectAuthenticationDefaults.RedirectUriUsedForCodeKey] : string.Empty,
                    };
                    await Options.Notifications.AuthorizationCodeReceived(authorizationCodeReceivedNotification);
                    if (authorizationCodeReceivedNotification.HandledResponse)
                    {
                        return GetHandledResponseTicket();
                    }
                    if (authorizationCodeReceivedNotification.Skipped)
                    {
                        return null;
                    }
                    // Flow possible changes
                    ticket = authorizationCodeReceivedNotification.AuthenticationTicket;
                }

                return ticket;
            }
            catch (Exception exception)
            {
                // We can't await inside a catch block, capture and handle outside.
                authFailedEx = ExceptionDispatchInfo.Capture(exception);
            }

            if (authFailedEx != null)
            {
                _logger.WriteError("Exception occurred while processing message: ", authFailedEx.SourceException);

                // Refresh the configuration for exceptions that may be caused by key rollovers. The user can also request a refresh in the notification.
                if (Options.RefreshOnIssuerKeyNotFound && authFailedEx.SourceException.GetType().Equals(typeof(SecurityTokenSignatureKeyNotFoundException)))
                {
                    Options.ConfigurationManager.RequestRefresh();
                }

                var authenticationFailedNotification = new AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions>(Context, Options)
                {
                    ProtocolMessage = openIdConnectMessage,
                    Exception = authFailedEx.SourceException
                };
                await Options.Notifications.AuthenticationFailed(authenticationFailedNotification);
                if (authenticationFailedNotification.HandledResponse)
                {
                    return GetHandledResponseTicket();
                }
                if (authenticationFailedNotification.Skipped)
                {
                    return null;
                }

                authFailedEx.Throw();
            }

            return null;
        }

        private AuthenticationProperties GetPropertiesFromState(string state)
        {
            // assume a well formed query string: <a=b&>OpenIdConnectAuthenticationDefaults.AuthenticationPropertiesKey=kasjd;fljasldkjflksdj<&c=d>
            int startIndex = 0;
            if (string.IsNullOrWhiteSpace(state) || (startIndex = state.IndexOf(/*OpenIdConnectAuthenticationDefaults.*/AuthenticationPropertiesKey, StringComparison.Ordinal)) == -1)
            {
                return null;
            }

            int authenticationIndex = startIndex + /*OpenIdConnectAuthenticationDefaults.*/AuthenticationPropertiesKey.Length;
            if (authenticationIndex == -1 || authenticationIndex == state.Length || state[authenticationIndex] != '=')
            {
                return null;
            }

            // scan rest of string looking for '&'
            authenticationIndex++;
            int endIndex = state.Substring(authenticationIndex, state.Length - authenticationIndex).IndexOf("&", StringComparison.Ordinal);

            // -1 => no other parameters are after the AuthenticationPropertiesKey
            if (endIndex == -1)
            {
                return Options.StateDataFormat.Unprotect(Uri.UnescapeDataString(state.Substring(authenticationIndex).Replace('+', ' ')));
            }
            else
            {
                return Options.StateDataFormat.Unprotect(Uri.UnescapeDataString(state.Substring(authenticationIndex, endIndex).Replace('+', ' ')));
            }
        }

        private static AuthenticationTicket GetHandledResponseTicket()
        {
            return new AuthenticationTicket(null, new AuthenticationProperties(new Dictionary<string, string>() { { HandledResponse, "true" } }));
        }

        /*
         * https://github.com/aspnet/AspNetKatana.git
         * checkout v3.1.0
         */
        

        /*
         * Microsoft.Owin.Security.OpenIdConnect::OpenIdConnect/OpenIdConnectAuthenticationDefaults.cs
         * 
         * OpenIdConnectAuthenticationDefaults.AuthenticationPropertiesKey is defined as internal const string
         */
        const string AuthenticationPropertiesKey = "OpenIdConnect.AuthenticationProperties";

        /*
         * Microsoft.Owin.Security.OpenIdConnect::Resources.Designer.cs
         * 
         * /// <summary>
         * ///   Looks up a localized string similar to &quot;OpenIdConnectMessage.Error was not null, indicating an error. Error: &apos;{0}&apos;. Error_Description (may be empty): &apos;{1}&apos;. Error_Uri (may be empty): &apos;{2}&apos;.&quot;.
         * /// </summary>
         * internal static string Exception_OpenIdConnectMessageError {
         *      get {
         *          return ResourceManager.GetString("Exception_OpenIdConnectMessageError", resourceCulture);
         *      }
         *  }
        */


        /*
         * Microsoft.Owin.Security.OpenIdConnect::Resources.resx
         *   <data name="Exception_OpenIdConnectMessageError" xml:space="preserve">
         *      <value>"OpenIdConnectMessage.Error was not null, indicating an error. Error: '{0}'. Error_Description (may be empty): '{1}'. Error_Uri (may be empty): '{2}'."</value>
         *   </data>
        */
        const string Exception_OpenIdConnectMessageError = "OpenIdConnectMessage.Error was not null, indicating an error. Error: '{0}'. Error_Description (may be empty): '{1}'. Error_Uri (may be empty): '{2}'.";
    }
}
 