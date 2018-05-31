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
using System.Collections.Concurrent;

namespace WolfeReiter.Owin.AzureAD.Owin.Security
{
    public class AzureGraphClaimsAuthenticationManager : ClaimsAuthenticationManager
    {
        public override ClaimsPrincipal Authenticate(string resourceName, ClaimsPrincipal incomingPrincipal)
        {
            if (incomingPrincipal != null && incomingPrincipal.Identity.IsAuthenticated == true)
            {
                Tuple<DateTime, IEnumerable<string>> grouple = null;
                IEnumerable<string> groups                   = Enumerable.Empty<string>();
                IEnumerable<string> oldGroups                = Enumerable.Empty<string>();
                var identity                                 = (ClaimsIdentity)incomingPrincipal.Identity;
                var identityKey                              = identity.Name;
                var cacheValid                               = false;
                try
                {
                    if (PrincipalRoleCache.TryGetValue(identityKey, out grouple))
                    {
                        lock(grouple) //prevent concurrent access to grouple Tuple
                        {
                            var expiration = grouple.Item1.AddSeconds(ConfigHelper.GroupCacheTtlSeconds);
                            if (DateTime.UtcNow > expiration ||
                                grouple.Item2.Count() != identity.Claims.Count(x => x.Type == "groups"))
                            {
                                oldGroups = grouple.Item2;
                                //don't need to check return because if it failed, then the entry was removed already
                                Tuple<DateTime, IEnumerable<string>> removedGrouple = null;
                                PrincipalRoleCache.TryRemove(identityKey, out removedGrouple);
                            }
                            else
                            {
                                cacheValid = true;
                                groups = grouple.Item2;
                            }
                        }
                    }

                    if(!cacheValid)
                    {
                        groups = Task.Run(() => AzureGraphHelper.AzureGroups(incomingPrincipal))
                            .Result
                            .Select(x => x.DisplayName);
                        grouple = new Tuple<DateTime, IEnumerable<string>>(DateTime.UtcNow, groups);
                        PrincipalRoleCache.AddOrUpdate(identityKey, grouple, (key, oldGrouple) => grouple);
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
                    identity.AddClaim(new Claim(ClaimTypes.AuthorizationDecision, String.Format("AzureAD-Group-Lookup-Error:{0:yyyy-MM-dd_HH:mm.ss}Z", DateTime.UtcNow)));
                    //Handle intermittnent server problem by keeping old groups if they existed.
                    if (oldGroups.Any())
                    {
                        grouple = new Tuple<DateTime, IEnumerable<string>>(DateTime.UtcNow.AddSeconds(-(ConfigHelper.GroupCacheTtlSeconds / 2)), oldGroups);
                        PrincipalRoleCache.AddOrUpdate(identityKey, grouple, (key, oldGrouple) => grouple);
                        foreach (var group in oldGroups)
                        {
                            //add AzureAD Group claims as Roles.
                            identity.AddClaim(new Claim(ClaimTypes.Role, group, ClaimValueTypes.String, "AzureAD"));
                        }
                    }
                }
            }
            return incomingPrincipal;
        }
  
        static ConcurrentDictionary<string, Tuple<DateTime, IEnumerable<string>>> PrincipalRoleCache { get; set; }
        static AzureGraphClaimsAuthenticationManager()
        {
            PrincipalRoleCache = new ConcurrentDictionary<string, Tuple<DateTime, IEnumerable<string>>>();
        }
    }
}
