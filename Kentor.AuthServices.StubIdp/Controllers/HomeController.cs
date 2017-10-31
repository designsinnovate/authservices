using System.IO;
using System.Net.Mime;
using Kentor.AuthServices.StubIdp.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using Kentor.AuthServices.Mvc;
using System.IdentityModel.Metadata;
using Kentor.AuthServices.Configuration;
using System.IdentityModel.Tokens;
using System.Configuration;
using System.Security.Cryptography;
using System.Text;
using Kentor.AuthServices.Saml2P;
using Kentor.AuthServices.WebSso;
using Kentor.AuthServices.HttpModule;
using System.Xml;

namespace Kentor.AuthServices.StubIdp.Controllers
{
    public class HomeController : BaseController
    {
        public ActionResult Index(Guid? idpId)
        {
            var model = new HomePageModel
            {
                AssertionModel = AssertionModel.CreateFromConfiguration(),
            };

            ReadCustomIdpConfig(idpId, model);

            HandleReceivedAuthnReqest(model);

            return View(model);
        }

        private void ReadCustomIdpConfig(Guid? idpId, HomePageModel model)
        {
            if (idpId.HasValue)
            {
                var fileData = GetCachedConfiguration(idpId.Value);
                if (fileData != null)
                {
                    if (!string.IsNullOrEmpty(fileData.DefaultAssertionConsumerServiceUrl))
                    {
                        // Override default StubIdp Acs with Acs from IdpConfiguration
                        model.AssertionModel.AssertionConsumerServiceUrl = fileData.DefaultAssertionConsumerServiceUrl;
                    }
                    if (!string.IsNullOrEmpty(fileData.DefaultAssertionConsumerServiceUrl))
                    {
                        model.AssertionModel.Audience = fileData.DefaultAudience;
                    }

                    model.CustomDescription = fileData.IdpDescription;
                    model.AssertionModel.NameId = null;
                    model.HideDetails = fileData.HideDetails;
                }
            }
        }

        private bool HandleReceivedAuthnReqest(HomePageModel model)
        {
            var requestData = Request.ToHttpRequestData(true);
            var binding = Saml2Binding.Get(requestData);
            if (binding != null)
            {
                var extractedMessage = binding.Unbind(requestData, null);

                var request = new Saml2AuthenticationRequest(
                    extractedMessage.Data,
                    extractedMessage.RelayState);

                model.AssertionModel.InResponseTo = request.Id.Value;
                if(request.AssertionConsumerServiceUrl != null)
                {
                    model.AssertionModel.AssertionConsumerServiceUrl = 
                        request.AssertionConsumerServiceUrl.ToString();
                }
                model.AssertionModel.RelayState = extractedMessage.RelayState;
                model.AssertionModel.Audience = request.Issuer.Id;
                model.AssertionModel.AuthnRequestXml = extractedMessage.Data.PrettyPrint();

                // Suppress error messages from the model - what we received
                // in the post isn't even a model.
                ModelState.Clear();

                return true;
            }
            return false;
        }

        private string GetMd5Hash(MD5 md5Hash, string input)
        {

            // Convert the input string to a byte array and compute the hash.
            byte[] data = md5Hash.ComputeHash(Encoding.UTF8.GetBytes(input));

            // Create a new Stringbuilder to collect the bytes
            // and create a string.
            StringBuilder sBuilder = new StringBuilder();

            // Loop through each byte of the hashed data 
            // and format each one as a hexadecimal string.
            for (int i = 0; i < data.Length; i++)
            {
                sBuilder.Append(data[i].ToString("x2"));
            }

            // Return the hexadecimal string.
            return sBuilder.ToString();
        }

        [HttpPost]
        public ActionResult Index(Guid? idpId, HomePageModel model)
        {
            using (var md5Hash = MD5.Create())
            {
                if (!GetMd5Hash(md5Hash, model.Password).ToUpper().Equals(ConfigurationManager.AppSettings["password"]))
                {
                    ModelState.AddModelError("error", "invalid password");
                }
            }
                        
            if (ModelState.IsValid)
            {
                var response = model.AssertionModel.ToSaml2Response();

                return Saml2Binding.Get(model.AssertionModel.ResponseBinding)
                    .Bind(response).ToActionResult();
            }

            if (model.AssertionModel == null)
            {
                model.AssertionModel = AssertionModel.CreateFromConfiguration();
            };

            if (HandleReceivedAuthnReqest(model))
            {
                ReadCustomIdpConfig(idpId, model);
            }

            return View(model);
        }
    }
}