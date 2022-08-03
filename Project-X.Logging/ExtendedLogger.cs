using Newtonsoft.Json;
using Project_X.Logging.Interfaces;

namespace Project_X.Logging
{
    public class ExtendedLogger : IExtendedLogger
    {
        public string SerializeException(Exception exception)
        {
            return SerializeException(exception, string.Empty);
        }

        public string SerializeException(Exception e, string exceptionMessage)
        {
            if (e == null) return string.Empty;

            exceptionMessage =
                JsonConvert.SerializeObject(new { parent = exceptionMessage, message = e.Message, trance = e.StackTrace });
            if (e.InnerException != null)
                exceptionMessage = SerializeException(e.InnerException, exceptionMessage);

            return exceptionMessage;
        }

        public dynamic SerializeExceptionAsJsonObject(Exception e, dynamic exceptionMessage)
        {
            if (e == null) return string.Empty;

            exceptionMessage = new { parent = exceptionMessage ?? "", message = e.Message, trance = e.StackTrace };


            if (e.InnerException != null)
                exceptionMessage = SerializeExceptionAsJsonObject(e.InnerException, exceptionMessage);

            return exceptionMessage;
        }
    }
}
