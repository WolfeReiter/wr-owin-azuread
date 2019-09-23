using Microsoft.Azure.ActiveDirectory.GraphClient;
using Microsoft.Azure.ActiveDirectory.GraphClient.Extensions;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;

namespace WolfeReiter.Owin.AzureAD.Utils
{
    public static class AzureGraphHelper
    {
        /// <summary>
        /// Get the AzureAD Graph object ID for the provided Group name.
        /// </summary>
        /// <param name="groupName"></param>
        /// <returns></returns>
        public static async Task<Group> GroupFromName(string groupDisplayName)
        {
            var directoryClient = new ActiveDirectoryClient(ConfigHelper.AzureGraphServiceRoot(), () => AzureGraphToken(ClaimsPrincipal.Current));
            var batch = new List<IReadOnlyQueryableSetBase>();
            var requests = new List<Task<Task<IBatchElementResult[]>>>();
            var groups = new List<Group>();

            batch.Add(directoryClient.Groups.Where(x => x.DisplayName == groupDisplayName));
            requests.Add(directoryClient.Context.ExecuteBatchAsync(batch.ToArray())
                .ContinueWith(t => t, TaskContinuationOptions.ExecuteSynchronously));
            batch.Clear();

            var responses = await Task.WhenAll(requests);
            foreach (var task in responses.Where(x => x.IsFaulted))
            {
                LogUtility.WriteEventLogEntry(LogUtility.FormatException(task.Exception, string.Format("Fault querying for AzureAD Group")), EventType.Warning);
            }

            foreach (var batchResult in responses.Where(x => x.Status == TaskStatus.RanToCompletion).Select(x => x.Result))
            {
                foreach (var item in batchResult)
                {
                    if (item.FailureResult == null)
                    {
                        if (item.SuccessResult != null)
                        {
                            var result = item.SuccessResult.CurrentPage.First();
                            if (result is Group) groups.Add((Group)result);
                        }
                    }
                    else
                    {
                        throw item.FailureResult;
                    }
                }
            }

            return groups.FirstOrDefault();
        }

        public static async Task<IEnumerable<User>> UsersInGroup(Group group)
        {
            if (group == null) return Enumerable.Empty<User>();

            var result     = new List<User>();
            var members = await ((IGroupFetcher)group).Members.ExecuteAsync();
            do
            {
                var directoryObjects = members.CurrentPage.ToList();
                foreach (var directoryObject in directoryObjects)
                {
                    if (directoryObject is User)
                    {
                        result.Add((User)directoryObject);
                    }
                }
                members = await members.GetNextPageAsync();
            }
            while (members != null);
            return result;
        }

        public static async Task<IEnumerable<User>> UsersInGroup(string groupDisplayName)
        {
            var group = await GroupFromName(groupDisplayName);
            return await UsersInGroup(group);
        }
        /// <summary>
        /// Convert the AzureAD Group ID claims on the principal to group names.
        /// </summary>
        /// <param name="principal"></param>
        /// <returns></returns>
        public static async Task<IEnumerable<Group>> AzureGroups(this ClaimsPrincipal principal)
        {
            var userObjectID        = principal.FindFirst(AzureClaimTypes.ObjectIdentifier).Value;
            var ids                 = GroupIDs(principal);
            var directoryClient     = new ActiveDirectoryClient(ConfigHelper.AzureGraphServiceRoot(), () => AzureGraphToken(principal));
            var batch               = new List<IReadOnlyQueryableSetBase>();
            var requests            = new List<Task<Task<IBatchElementResult[]>>>();
            var groups              = new List<Group>();
            var utcExpired          = DateTime.UtcNow.AddSeconds(ConfigHelper.GroupCacheTtlSeconds);

            const int batchSize = 5;
            int count = ids.Count(); //count of groups to look up remotely
            int index = 0;
            foreach(var id in ids)
            {
                index++;
                batch.Add(directoryClient.Groups.Where(x => x.ObjectId == id));
                if(count == index || batchSize == batch.Count) //batch requests
                {
                    var task = directoryClient.Context.ExecuteBatchAsync(batch.ToArray())
                         .ContinueWith(t => t, TaskContinuationOptions.ExecuteSynchronously);
                    requests.Add(task);
                    batch.Clear();
                }
            }

            var responses = await Task.WhenAll(requests);
            foreach(var task in responses.Where(x => x.IsFaulted))
            {
                LogUtility.WriteEventLogEntry(LogUtility.FormatException(task.Exception, string.Format("Fault querying for AzureAD Group")), EventType.Warning);
            }
            var utcNow = DateTime.UtcNow;
            foreach(var batchResult in responses.Where(x => x.Status == TaskStatus.RanToCompletion).Select(x => x.Result))
            {
                foreach(var item in batchResult)
                {
                    if(item.FailureResult == null)
                    {
                        if (item.SuccessResult != null)
                        {
                            //filter out any result type that is not a Group (e.g. a Role like "GlobalAdmin")
                            var result = item.SuccessResult.CurrentPage.First();
                            if (result is Group)
                            {
                                var group = (Group)result;
                                groups.Add(group);
                            }
                        }
                    }
                    else
                    {
                        var failureResult = item.FailureResult as Microsoft.Data.OData.ODataErrorException;
                        if (failureResult != null && failureResult.Error.ErrorCode == "Request_ResourceNotFound")
                        {
                            Debug.WriteLine("Group ID associated with user not found (deleted): {0}.", failureResult.Error.Message);
                        }
                        else
                        {
                            throw item.FailureResult;
                        }
                    }
                }
            }
            return groups;
        }

        /// <summary>
        /// Azure graph token acquired from the principal and application client credential.
        /// </summary>
        /// <returns></returns>
        static async Task<string> AzureGraphToken(ClaimsPrincipal principal)
        {
            var uid = new UserIdentifier(principal.FindFirst(AzureClaimTypes.ObjectIdentifier).Value, UserIdentifierType.UniqueId);
            var credential = new ClientCredential(ConfigHelper.AzureClientId, ConfigHelper.AzureAppKey);
            var authContext = new AuthenticationContext(ConfigHelper.AzureAuthority);

            var result = await authContext.AcquireTokenSilentAsync(ConfigHelper.AzureGraphResourceId, credential, uid);
            return result.AccessToken;
        }

        static IEnumerable<string> GroupIDs(ClaimsPrincipal principal)
        {
            return principal.Claims.Where(x => x.Type == "groups").Select(x => x.Value.ToLower());
        }
    }
}