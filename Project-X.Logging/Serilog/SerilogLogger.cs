using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Project_X.Logging.Interfaces;
using Serilog;
using Serilog.Events;

namespace Project_X.Logging.Serilog
{
    public class SerilogLogger<T> : ExtendedLogger, IApplicationLogger<T> where T : class
    {

        public SerilogLogger(IConfiguration configuration)
        {
            Log.Logger = new LoggerConfiguration().ReadFrom.Configuration(configuration).CreateLogger();

        }

        public void Custom(object level, string message)
        {
            Log.ForContext<T>().Write((LogEventLevel)level, message);
        }

        public void Custom(object level, string message, Exception e)
        {
            Log.ForContext<T>().Write((LogEventLevel)level, e, message);
        }

        public void Debug(string message, params object[] ps)
        {
            Log.ForContext<T>().Debug(message, ps);
        }

        public void Debug(string message, Exception exception)
        {
            Log.ForContext<T>().Debug(message, exception);
        }

        public void Error(string message, params object[] ps)
        {
            Log.ForContext<T>().Error(message, ps);
        }

        public void Error(string message, Exception exception)
        {
            Log.ForContext<T>().Error(message, exception);
        }

        public void Fatal(string message, params object[] ps)
        {
            Log.ForContext<T>().Fatal(message, ps);
        }

        public void Fatal(string message, Exception exception)
        {
            Log.ForContext<T>().Fatal(message, exception);
        }

        public void Info(string message, params object[] ps)
        {
            Log.ForContext<T>().Information(message, ps);
        }

        public void Info(string message, Exception exception)
        {
            Log.ForContext<T>().Information(message, exception);
        }

        public void Warn(string message, params object[] ps)
        {
            Log.ForContext<T>().Warning(message, ps);
        }

        public void Warn(string message, Exception exception)
        {
            Log.ForContext<T>().Warning(message, exception);
        }
    }
}
