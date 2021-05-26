using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;

namespace MvcDotNetClient.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {

            return View();
        }

        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }

        /// <summary>
        /// Send an OpenID Connect sign-in request.
        /// </summary>
        public void SignIn()
        {
            if (!Request.IsAuthenticated)
            {

                string redirectUri = ConfigurationManager.AppSettings["redirectUri"];
                var auth = HttpContext.GetOwinContext().Authentication;
                auth.Challenge(
                    new AuthenticationProperties { RedirectUri = redirectUri });
            }
        }

        /// <summary>
        /// Send an OpenID Connect sign-out request.
        /// </summary>
        public ActionResult SignOut()
        {
            if (Request.GetOwinContext().Authentication.User.Identity.IsAuthenticated)
            {
                HttpContext.GetOwinContext().Authentication.SignOut(
                   OpenIdConnectAuthenticationDefaults.AuthenticationType,
                   CookieAuthenticationDefaults.AuthenticationType);
            }
            return Redirect("~/");
        }
    }
}