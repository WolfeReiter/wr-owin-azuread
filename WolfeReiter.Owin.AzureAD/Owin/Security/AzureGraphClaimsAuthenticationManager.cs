using Microsoft.Azure.ActiveDirectory.GraphClient;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Web;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using WolfeReiter.Owin.AzureAD.Utils;
using Microsoft.Owin.Security.OpenIdConnect;
using Microsoft.Owin.Security.Cookies;

namespace WolfeReiter.Owin.AzureAD.Owin.Security
{
    public class AzureGraphClaimsAuthenticationManager : ClaimsAuthenticationManager
    {
        public override ClaimsPrincipal Authenticate(string resourceName, ClaimsPrincipal incomingPrincipal)
        {
            const int max_retries = 5;
            if (incomingPrincipal != null && incomingPrincipal.Identity.IsAuthenticated == true)
            {
                try
                {
                    var identity = (ClaimsIdentity)incomingPrincipal.Identity;
                    var groups = Task.Run(() => AzureGraphHelper.AzureGroups(incomingPrincipal)).Result;
                    foreach (var group in groups)
                    {
                        //add AzureAD Group claims as Roles.
                        identity.AddClaim(new Claim(ClaimTypes.Role, group.DisplayName, ClaimValueTypes.String, "AzureAD"));
                    }
                }
                catch (Exception ex)
                {
                    LogUtility.WriteEventLogEntry(LogUtility.FormatException(ex, string.Format("Exception Mapping Groups to Roles)")), EventType.Warning);
                    ClearAuthenticationContextState(incomingPrincipal);
                    return new GenericPrincipal(new GenericIdentity(""), new string[0]); //principal with unauthenticated identity
                }
            }
            return incomingPrincipal;

        }

        void ClearAuthenticationContextState(ClaimsPrincipal incomingPrincipal)
        {
			string userObjectID = incomingPrincipal.FindFirst(AzureClaimTypes.ObjectIdentifier).Value;
			var authContext = new AuthenticationContext(ConfigHelper.AzureAuthority);
			var cacheitem = authContext.TokenCache.ReadItems().Where(x => x.UniqueId == userObjectID).SingleOrDefault();
			if (cacheitem != null) authContext.TokenCache.DeleteItem(cacheitem);

            //force re-authentication
            try
            {
                HttpContext.Current.GetOwinContext().Authentication.SignOut(
                    OpenIdConnectAuthenticationDefaults.AuthenticationType, CookieAuthenticationDefaults.AuthenticationType);
            }
            catch (NullReferenceException)
            {
                //NullReferenceException can be thrown and it is death of redirects.
            }
        }
    }
}
