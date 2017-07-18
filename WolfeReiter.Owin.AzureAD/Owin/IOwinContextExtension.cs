using Microsoft.Owin;
using System.Web;

namespace WolfeReiter.Owin
{
    public static class IOwinContextExtension
    {
        public static HttpContextBase GetHttpContext(this IOwinContext context)
        {
            return context.Get<HttpContextBase>(typeof(HttpContextBase).FullName);
        }
    }
}
