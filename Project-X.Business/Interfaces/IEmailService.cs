namespace Project_X.Business.Interfaces
{
    public interface IEmailService
    {
        void Send(string to, string subject, string html, string? from = null);
    }
}
