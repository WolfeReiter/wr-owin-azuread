using Microsoft.Azure.ActiveDirectory.GraphClient;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using WolfeReiter.Owin.AzureAD.Utils;

namespace WolfeReiter.Owin.AzureAD.Owin.Security
{
    public class AzureGraphClaimsAuthenticationManager : ClaimsAuthenticationManager
    {
        public override ClaimsPrincipal Authenticate(string resourceName, ClaimsPrincipal incomingPrincipal)
        {
            if (incomingPrincipal != null && incomingPrincipal.Identity.IsAuthenticated == true)
            {
                var identity = (ClaimsIdentity)incomingPrincipal.Identity;
                var groups = Task.Run(() => AzureGraphHelper.AzureGroups(incomingPrincipal)).Result;
                foreach(var group in groups)
                {
                    //add AzureAD Group claims as Roles.
                    identity.AddClaim(new Claim(ClaimTypes.Role, group.DisplayName, ClaimValueTypes.String, "AzureAD"));
                }
            }
            return incomingPrincipal;
        }
    }
}
