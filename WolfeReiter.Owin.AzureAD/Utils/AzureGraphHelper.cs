using Microsoft.Azure.ActiveDirectory.GraphClient;
using Microsoft.Azure.ActiveDirectory.GraphClient.Extensions;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using DynamicJson = System.Web.Helpers.Json;

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
            var ids                 = GroupIDs(principal);
            var directoryClient     = new ActiveDirectoryClient(ConfigHelper.AzureGraphServiceRoot(), () => ConfigHelper.AzureGraphToken());
            var batch               = new List<IReadOnlyQueryableSetBase>();
            var requests            = new List<Task<IBatchElementResult[]>>();
            var groups              = new List<Group>();

            const int batchSize = 5;
            int count = ids.Count(); //readonly
            int index = 0;
            foreach(var id in ids)
            {
                index++;
                batch.Add(directoryClient.Groups.Where(x => x.ObjectId == id));
                if(count == index || batchSize == batch.Count) //batch requests
                {
                    requests.Add(directoryClient.Context.ExecuteBatchAsync(batch.ToArray()));
                    batch.Clear();
                }
            }

            var responses = await Task.WhenAll(requests);
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
                            if(result is Group) groups.Add((Group)result);
                        }
                    }
                    else
                    {
                        throw item.FailureResult;
                    }
                }
            }
            return groups;
        }

        static IEnumerable<string> GroupIDs(ClaimsPrincipal principal)
        {
            return principal.Claims.Where(x => x.Type == "groups").Select(x => x.Value.ToLower());
        }
    }
}