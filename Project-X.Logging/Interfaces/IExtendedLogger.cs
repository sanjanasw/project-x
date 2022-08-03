using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Project_X.Logging.Interfaces
{
    public interface IExtendedLogger
    {
        string SerializeException(Exception exception);
        string SerializeException(Exception e, string exceptionMessage);
        dynamic SerializeExceptionAsJsonObject(Exception e, dynamic exceptionMessage);
    }
}
