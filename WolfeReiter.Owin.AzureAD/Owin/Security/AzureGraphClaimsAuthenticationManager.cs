using Microsoft.Azure.ActiveDirectory.GraphClient;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
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

        ClaimsPrincipal _Authenticate(string resourceName, ClaimsPrincipal incomingPrincipal, int iteration)
        {
            const int max_retries = 5;
            if (incomingPrincipal != null && incomingPrincipal.Identity.IsAuthenticated == true)
            {
                var identity = (ClaimsIdentity)incomingPrincipal.Identity;

                try
                {
                    var groups = Task.Run(() => AzureGraphHelper.AzureGroups(incomingPrincipal)).Result;
                    foreach (var group in groups)
                    {
                        //add AzureAD Group claims as Roles.
                        identity.AddClaim(new Claim(ClaimTypes.Role, group.DisplayName, ClaimValueTypes.String, "AzureAD"));
                    }
                }
                catch (Exception ex)
                {
                    LogUtility.WriteEventLogEntry(LogUtility.FormatException(ex, string.Format("Exception Mapping Groups to Roles (iteration: {0})",iteration)), EventType.Exception);
                    if( iteration < max_retries)
                    {
                        Thread.Sleep(5000);
                        _Authenticate(resourceName, incomingPrincipal, iteration + 1);
                    }
                }
            }
            return incomingPrincipal;
        }
    }
}
