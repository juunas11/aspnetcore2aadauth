using System;
using Core2AadAuth.Filters;
using Core2AadAuth.Options;
using Core2AadAuth.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.IdentityModel.Tokens;

namespace Core2AadAuth
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        private IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc(opts =>
            {
                opts.Filters.Add(typeof(AdalTokenAcquisitionExceptionFilter));
            }).SetCompatibilityVersion(CompatibilityVersion.Version_2_1);

            //TODO: Set up Data Protection key persistence correctly for your env: https://docs.microsoft.com/en-us/aspnet/core/security/data-protection/configuration/overview?tabs=aspnetcore2x
            //I go with defaults, which works fine in my case
            //But if you run on Azure App Service and use deployment slots, keys get swapped with the app
            //So you'll need to setup storage for keys outside the app, Key Vault and Blob Storage are some options
            services.AddDataProtection();

            //Add a strongly-typed options class to DI
            services.Configure<AuthOptions>(Configuration.GetSection("Authentication"));

            services.AddScoped<ITokenCacheFactory, TokenCacheFactory>();

            services.AddAuthentication(auth =>
            {
                auth.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                auth.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie()
            .AddOpenIdConnect(opts =>
            {
                Configuration.GetSection("Authentication").Bind(opts);

                opts.Events = new OpenIdConnectEvents
                {
                    OnAuthorizationCodeReceived = async ctx =>
                    {
                        HttpRequest request = ctx.HttpContext.Request;
                        //We need to also specify the redirect URL used
                        string currentUri = UriHelper.BuildAbsolute(request.Scheme, request.Host, request.PathBase, request.Path);
                        //Credentials for app itself
                        var credential = new ClientCredential(ctx.Options.ClientId, ctx.Options.ClientSecret);

                        //Construct token cache
                        ITokenCacheFactory cacheFactory = ctx.HttpContext.RequestServices.GetRequiredService<ITokenCacheFactory>();
                        TokenCache cache = cacheFactory.CreateForUser(ctx.Principal);

                        var authContext = new AuthenticationContext(ctx.Options.Authority, cache);

                        //Get token for Microsoft Graph API using the authorization code
                        string resource = "https://graph.microsoft.com";
                        AuthenticationResult result = await authContext.AcquireTokenByAuthorizationCodeAsync(
                            ctx.ProtocolMessage.Code, new Uri(currentUri), credential, resource);

                        //Tell the OIDC middleware we got the tokens, it doesn't need to do anything
                        ctx.HandleCodeRedemption(result.AccessToken, result.IdToken);
                    }
                };
                opts.TokenValidationParameters = new TokenValidationParameters
                {
                    // Checks tokens are issued from an issuer starting with https://sts.windows.net/
                    IssuerValidator = ValidateTokenIssuerPrefix
                };
            });

            services.Configure<HstsOptions>(o =>
            {
                o.IncludeSubDomains = false;
                o.Preload = false;
                o.MaxAge = TimeSpan.FromDays(365);
            });
        }

        private string ValidateTokenIssuerPrefix(
            string issuer, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            // Does the same as what the framework issuer validator does
            // Ref: https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/blob/b152f463d910230859ec67705f11e51af4db4217/src/Microsoft.IdentityModel.Tokens/Validators.cs#L125
            // Return issuer if it is valid
            if (issuer.StartsWith("https://sts.windows.net/", StringComparison.Ordinal))
            {
                return issuer;
            }

            // Otherwise throw an exception
            throw new SecurityTokenInvalidIssuerException("Invalid issuer in token")
            {
                InvalidIssuer = issuer
            };
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                //Outside dev, require HTTPS and use HSTS
                app.UseHttpsRedirection();
                app.UseHsts();
            }

            app.UseStaticFiles();

            app.UseAuthentication();

            app.UseMvcWithDefaultRoute();
        }
    }
}
