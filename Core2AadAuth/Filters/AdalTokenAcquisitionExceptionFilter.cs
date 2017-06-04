using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace Core2AadAuth.Filters
{
    public class AdalTokenAcquisitionExceptionFilter : ExceptionFilterAttribute
    {
        public override void OnException(ExceptionContext context)
        {
            //If ADAL failed to acquire access token
            if(context.Exception is AdalSilentTokenAcquisitionException)
            {
                //Send user to Azure AD to re-authenticate
                context.Result = new ChallengeResult();
            }
        }
    }
}