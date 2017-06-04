using System.Collections.Generic;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;

namespace Core2AadAuth
{
    public class Program
    {
        public static void Main(string[] args)
        {
            BuildWebHost(args).Run();
        }

        public static IWebHost BuildWebHost(string[] args) =>
            WebHost.CreateDefaultBuilder(args)
                .ConfigureLogging(loggerFactory =>
                {
                    loggerFactory.AddConsole();
                    loggerFactory.AddFilter(new Dictionary<string, LogLevel>
                    {
                        ["Microsoft"] = LogLevel.Debug
                    });
                })
                .UseStartup<Startup>()
                .Build();
    }
}
