using System;
using System.Security.Claims;
using Core2AadAuth.Filters;
using Core2AadAuth.Options;
using Core2AadAuth.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Caching.Distributed;
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
            });

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
                    //We can't validate the issuer in a multi-tenant app
                    //We could check that the issuer claim starts with https://sts.windows.net/, but it's kind of unnecessary
                    //Token signature is still checked against the AAD signing keys anyway
                    ValidateIssuer = false
                };
            });
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
                app.Use(async (ctx, next) =>
                {
                    if (!ctx.Request.IsHttps)
                    {
                        //Insecure request, redirect to HTTPS side
                        HttpRequest req = ctx.Request;
                        string url = "https://" + req.Host + req.Path + req.QueryString;
                        ctx.Response.Redirect(url, permanent: true);
                    }
                    else
                    {
                        //Apply Strict Transport Security to all secure requests
                        //All requests done over secure channel for next year
                        ctx.Response.Headers["Strict-Transport-Security"] = "max-age=31536000";

                        await next();
                    }
                });
            }

            app.UseStaticFiles();

            app.UseAuthentication();

            app.UseMvcWithDefaultRoute();
        }
    }
}
