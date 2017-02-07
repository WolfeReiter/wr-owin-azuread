using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using WolfeReiter.Owin.AzureAD.Utils;

namespace WolfeReiter.Owin.AzureAD.Demo.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        // GET: Home
        public async Task<ActionResult> Index()
        {
            var test = User.IsInRole("WolfeReiter.AP.Administrator");
            var members = await AzureGraphHelper.UsersInGroup("WolfeReiter.AP.Administrator");
            return View();
        }
    }
}