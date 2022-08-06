using System;
using System.Net;

namespace Predictly_Api.Helpers
{
    public class HumanErrorException : Exception
    {
        public HumanErrorException(HttpStatusCode status, object details)
        {
            Details = details;
            Status = status;
        }

        public object Details { get; set; }
        public HttpStatusCode Status { get; set; }
    }
}
