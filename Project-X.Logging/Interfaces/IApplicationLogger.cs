using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Project_X.Logging.Interfaces
{
    public interface IApplicationLogger<T> : IExtendedLogger where T : class
    {
        void Debug(string message, params object[] ps);

        void Debug(string message, Exception exception);

        void Info(string message, params object[] ps);

        void Info(string message, Exception exception);

        void Warn(string message, params object[] ps);

        void Warn(string message, Exception exception);

        void Error(string message, params object[] ps);

        void Error(string message, Exception exception);

        void Fatal(string message, params object[] ps);

        void Fatal(string message, Exception exception);
        void Custom(object level, string message);
        void Custom(object level, string message, Exception e);

    }
}
