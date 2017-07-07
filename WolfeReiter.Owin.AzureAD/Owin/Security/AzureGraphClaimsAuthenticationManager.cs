using Microsoft.Azure.ActiveDirectory.GraphClient;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using WolfeReiter.Owin.AzureAD.Utils;

namespace WolfeReiter.Owin.AzureAD.Owin.Security
{
    public class AzureGraphClaimsAuthenticationManager : ClaimsAuthenticationManager
    {
        public override ClaimsPrincipal Authenticate(string resourceName, ClaimsPrincipal incomingPrincipal)
        {
            return _Authenticate(resourceName, incomingPrincipal, 0);
        }

        void ClearTokenCache(ClaimsPrincipal incomingPrincipal)
        {
			string userObjectID = incomingPrincipal.FindFirst(AzureClaimTypes.ObjectIdentifier).Value;
			var authContext = new AuthenticationContext(ConfigHelper.AzureAuthority);
			var cacheitem = authContext.TokenCache.ReadItems().Where(x => x.UniqueId == userObjectID).SingleOrDefault();
			if (cacheitem != null) authContext.TokenCache.DeleteItem(cacheitem);
        }

        ClaimsPrincipal _Authenticate(string resourceName, ClaimsPrincipal incomingPrincipal, int iteration)
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
                    LogUtility.WriteEventLogEntry(LogUtility.FormatException(ex, string.Format("Exception Mapping Groups to Roles (iteration: {0})",iteration)), EventType.Warning);
                    var agx = ex as AggregateException;
                    if(agx != null && agx.InnerExceptions.Any(x => x is AdalSilentTokenAcquisitionException)) //azure token requires refresh
                    {
                        ClearTokenCache(incomingPrincipal);
                        return new GenericPrincipal(new GenericIdentity(""), new string[0]); //principal with unauthenticated identity
                    }
                    else if(iteration < max_retries) //other failure, maybe retry will fix it
                    {
                        Thread.Sleep(5000);
                        return _Authenticate(resourceName, incomingPrincipal, iteration + 1);
                    }

                    ClearTokenCache(incomingPrincipal);
					//principal is not valid. Should be not authenticated.
					return new GenericPrincipal(new GenericIdentity(""), new string[0]); //principal with unauthenticated identity
                }
            }
            return incomingPrincipal;
        }
    }
}
