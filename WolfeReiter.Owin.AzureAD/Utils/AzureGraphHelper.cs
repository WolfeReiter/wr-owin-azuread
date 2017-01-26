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
        public static async Task<IEnumerable<Group>> AzureGroups(this ClaimsPrincipal principal)
        {
            var ids                 = GroupIDs(principal);
            var directoryClient     = new ActiveDirectoryClient(ConfigHelper.AzureGraphServiceRoot(), () => ConfigHelper.AzureGraphToken(principal));
            var batch               = new List<IReadOnlyQueryableSetBase>();
            var requests            = new List<Task<IBatchElementResult[]>>();
            var groups              = new List<Group>();

            const int batchSize = 5;
            int count = ids.Count(); //readonly
            int index = 0;
            foreach(var id in ids)
            {
                index++;
                batch.Add(directoryClient.DirectoryObjects.Where(x => x.ObjectId == id));
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