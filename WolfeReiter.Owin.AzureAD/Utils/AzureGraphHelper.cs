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
            var directoryClient = new ActiveDirectoryClient(ConfigHelper.AzureGraphServiceRoot(), () => ConfigHelper.AzureGraphToken());
            var batch = new List<IReadOnlyQueryableSetBase>();
            var requests = new List<Task<IBatchElementResult[]>>();
            var groups = new List<Group>();

            batch.Add(directoryClient.Groups.Where(x => x.DisplayName == groupDisplayName));
            requests.Add(directoryClient.Context.ExecuteBatchAsync(batch.ToArray()));
            batch.Clear();

            var responses = await Task.WhenAll(requests);
            foreach (var batchResult in responses)
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
            var userObjectID     = ClaimsPrincipal.Current.FindFirst(AzureClaimTypes.ObjectIdentifier).Value;
            var ids                 = GroupIDs(principal);
            var directoryClient     = new ActiveDirectoryClient(ConfigHelper.AzureGraphServiceRoot(), () => ConfigHelper.AzureGraphToken());
            var batch               = new List<IReadOnlyQueryableSetBase>();
            var requests            = new List<Task<IBatchElementResult[]>>();
            var groups              = new List<Group>();
            var utcExpired          = DateTime.UtcNow.AddSeconds(ConfigHelper.GroupCacheTtlSeconds);

            const int batchSize = 5;
            int count = ids.Count(); //readonly
            int index = 0;
            foreach(var id in ids)
            {
                lock (s_groupCacheLock)
                {
                    if (GroupCache.ContainsKey(id))
                    {
                        var grouple = GroupCache[id];
                        if (grouple.Item2 < utcExpired)
                        {
                            //groop in cache is valid
                            groups.Add(grouple.Item1);
                            continue; //next iteration
                        }
                        else //expired
                        {
                            GroupCache.Remove(id);
                            //fall through
                        }
                    } //fall through
                }
                index++;
                batch.Add(directoryClient.Groups.Where(x => x.ObjectId == id));
                if(count == index || batchSize == batch.Count) //batch requests
                {
                    requests.Add(directoryClient.Context.ExecuteBatchAsync(batch.ToArray()));
                    batch.Clear();
                }
            }

            var responses = await Task.WhenAll(requests);
            var utcNow = DateTime.UtcNow;
            foreach(var batchResult in responses)
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
                                lock (s_groupCacheLock)
                                {
                                    var grouple = new Tuple<Group, DateTime>(group, utcNow);
                                    if (GroupCache.ContainsKey(group.ObjectId)) GroupCache[group.ObjectId] = grouple;
                                    s_GroupCache.Add(group.ObjectId, grouple);
                                }
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

        static IEnumerable<string> GroupIDs(ClaimsPrincipal principal)
        {
            return principal.Claims.Where(x => x.Type == "groups").Select(x => x.Value.ToLower());
        }

        static readonly object s_groupCacheLock = new object();
        static Dictionary<string,Tuple<Group, DateTime>> s_GroupCache = null;
        static Dictionary<string, Tuple<Group, DateTime>> GroupCache
        {
            get
            {
                if(s_GroupCache == null) s_GroupCache = new Dictionary<string, Tuple<Group, DateTime>>();
                return s_GroupCache;
            }
        }
    }
}