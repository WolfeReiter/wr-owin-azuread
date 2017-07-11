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
            if (incomingPrincipal != null && incomingPrincipal.Identity.IsAuthenticated == true)
            {
                try
                {
                    IEnumerable<string> groups = Enumerable.Empty<string>();
                    var identity               = (ClaimsIdentity)incomingPrincipal.Identity;
                    var identityKey            = identity.Name;
                    var cacheValid             = false;
                    if (PrincipalRoleCache.ContainsKey(identityKey))
                    {
                        var grouple    = PrincipalRoleCache[identityKey];
                        var expiration = grouple.Item1.AddSeconds(ConfigHelper.GroupCacheTtlSeconds);
                        if (DateTime.UtcNow > expiration ||
                            grouple.Item2.Count() != identity.Claims.Count(x => x.Type == "groups"))
                        {
                            PrincipalRoleCache.Remove(identityKey);
                        }
                        else
                        {
                            cacheValid = true;
                            groups     = grouple.Item2;
                        }
                    }

                    if(!cacheValid)
                    {
                        groups = Task.Run(() => AzureGraphHelper.AzureGroups(incomingPrincipal))
                            .Result
                            .Select(x => x.DisplayName);
                        PrincipalRoleCache.Add(identityKey, new Tuple<DateTime, IEnumerable<string>>(DateTime.UtcNow, groups));
                    }
                    foreach (var group in groups)
                    {
                        //add AzureAD Group claims as Roles.
                        identity.AddClaim(new Claim(ClaimTypes.Role, group, ClaimValueTypes.String, "AzureAD"));
                    }
                }
                catch (Exception ex)
                {
                    LogUtility.WriteEventLogEntry(LogUtility.FormatException(ex, string.Format("Exception Mapping Groups to Roles)")), EventType.Warning);
                    string userObjectID = incomingPrincipal.FindFirst(AzureClaimTypes.ObjectIdentifier).Value;
                    var authContext = new AuthenticationContext(ConfigHelper.AzureAuthority);
                    var cacheitem = authContext.TokenCache.ReadItems().Where(x => x.UniqueId == userObjectID).SingleOrDefault();
                    if (cacheitem != null) authContext.TokenCache.DeleteItem(cacheitem);

                    var httpContext = HttpContext.Current;
                    try
                    {
                        httpContext.GetOwinContext().Authentication.SignOut(
                            OpenIdConnectAuthenticationDefaults.AuthenticationType, CookieAuthenticationDefaults.AuthenticationType);
                    }
                    catch(Exception)
                    {
                        httpContext.Response.Cookies.Clear();
                    }
                    return new GenericPrincipal(new GenericIdentity(""), new string[0]); //principal with unauthenticated identity
                }
            }
            return incomingPrincipal;
        }

        static Dictionary<string, Tuple<DateTime, IEnumerable<string>>> PrincipalRoleCache { get; set; }
        static AzureGraphClaimsAuthenticationManager()
        {
            PrincipalRoleCache = new Dictionary<string, Tuple<DateTime, IEnumerable<string>>>();
        }
    }
}
