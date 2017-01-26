using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;

namespace WolfeReiter.Owin.AzureAD.Utils
{
    public static class ConfigHelper
    {
        static string _clientId = null;
        public static string AzureClientId
        {
            get
            {
                if(_clientId == null)
                {
                    _clientId = ConfigurationManager.AppSettings["azure:clientId"];
                }
                return _clientId;
            }
        }

        static string _tenant = null;
        public static string AzureTenant
        {
            get
            {
                if(_tenant == null)
                {
                    _tenant = ConfigurationManager.AppSettings["azure:tenant"];
                }
                return _tenant;
            }
        }

        static string _instancePattern = null;
        static string AzureInstancePattern
        {
            get
            {
                if(_instancePattern == null)
                {
                    _instancePattern = ConfigurationManager.AppSettings["azure:instancePattern"];
                }
                return _instancePattern;
            }
        }

        public static string AzureAuthority
        {
            get
            {
                return string.Format(CultureInfo.InvariantCulture, AzureInstancePattern, AzureTenant);
            }
        }

        static string _logoutUri = null;
        public static string PostLogoutRedirectUri
        {
            get
            {
                if(_logoutUri == null)
                {
                    _logoutUri = ConfigurationManager.AppSettings["azure:postLogoutRedirectUri"];
                }
                return _logoutUri;
            }
        }

        static string _appKey = null;
        public static string AzureAppKey
        {
            get
            {
                if(_appKey == null)
                {
                    _appKey = ConfigurationManager.AppSettings["azure:appKey"];
                }
                return _appKey;
            }
        }

        static string _graphUrl = null;
        public static string AzureGraphResourceId
        {
            get
            {
                if(_graphUrl == null)
                {
                    _graphUrl = ConfigurationManager.AppSettings["azure:graphUrl"];
                }
                return _graphUrl;
            }
        }

        static string _graphApiVer = null;
        public static string GraphApiVersion
        {
            get
            {
                if(_graphApiVer == null)
                {
                    _graphApiVer = ConfigurationManager.AppSettings["azure:graphApiVersion"];
                }
                return _graphApiVer;
            }
        }

        public static Uri GraphClaimsRequestUri(string endpoint)
        {
            var builder = new UriBuilder(endpoint);
            builder.Query = "api-version=" + GraphApiVersion;
            return builder.Uri;
        }

        public static async Task<string> AzureGraphToken(ClaimsPrincipal principal)
        {
            var uid = new UserIdentifier(principal.FindFirst(AzureClaimTypes.ObjectIdentifier).Value, UserIdentifierType.UniqueId);
            var credential = new ClientCredential(AzureClientId, AzureAppKey);
            var authContext = new AuthenticationContext(AzureAuthority);
            var result = await authContext.AcquireTokenSilentAsync(AzureGraphResourceId, credential, uid);
            return result.AccessToken;
        }

        public static Uri AzureGraphServiceRoot()
        {
            return new Uri(AzureGraphResourceId + "/" + AzureTenant);
        }

        public static string OpenIdConnectRedirectScheme
        {
            get
            {
                return ConfigurationManager.AppSettings ["azure:openIdConnectRedirectScheme"];
            }
        }
        static int? _port = null;
        public static int? OpenIdConnectRedirectPort
        {
            get
            {
                if(!_port.HasValue) {
                    int port;
                    if(int.TryParse(ConfigurationManager.AppSettings["azure:openIdConnectRedirectPort"], out port)) _port = port;
                    else _port = int.MinValue;
                }
                return _port == int.MinValue ? null : _port;
            }
        }

        static string AzureAuthenticationFailedHandlerUrlTemplateConfig
        {
            get
            {
                return ConfigurationManager.AppSettings["azure:authFailedUrlTemplate"];
            }
        }
        const string AzureAuthenticationFailedHandlerUrlDefault = "/Error/ShowError?signIn=true&errorMessage={0}";
        static string _AzureAuthenticationFailedHandlerUrlTemplate = null;
        public static string AzureAuthenticationFailedHandlerUrlTemplate
        {
            get
            {
                if (_AzureAuthenticationFailedHandlerUrlTemplate == null)
                {
                    _AzureAuthenticationFailedHandlerUrlTemplate = AzureAuthenticationFailedHandlerUrlTemplateConfig;
                    if(string.IsNullOrEmpty(_AzureAuthenticationFailedHandlerUrlTemplate))
                    {
                        _AzureAuthenticationFailedHandlerUrlTemplate = AzureAuthenticationFailedHandlerUrlTemplateConfig;
                    }
                }
                return _AzureAuthenticationFailedHandlerUrlTemplate;
            }
        }
    }
}