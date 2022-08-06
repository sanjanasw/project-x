using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Options;
using MimeKit;
using MimeKit.Text;
using Project_X.Business.Interfaces;
using Project_X.Helpers;

namespace Project_X.Business
{
    public class EmailService : IEmailService
    {
        private readonly AppSettings _appSettings;

        public EmailService(IOptions<AppSettings> appSettings)
        {
            _appSettings = appSettings.Value;
        }

        public void Send(string to, string subject, string html, string? from = null)
        {
            // create message
            var email = new MimeMessage();
            email.From.Add(MailboxAddress.Parse(from ?? _appSettings?.EmailConfiguration?.EmailFrom));
            email.To.Add(MailboxAddress.Parse(to));
            email.Subject = subject;
            email.Body = new TextPart(TextFormat.Html) { Text = html };

            // send email
            using var smtp = new SmtpClient();
            smtp.Connect(_appSettings?.EmailConfiguration?.SmtpHost, _appSettings?.EmailConfiguration?.SmtpPort ?? 587, SecureSocketOptions.StartTls);
            smtp.Authenticate(_appSettings?.EmailConfiguration?.SmtpUser, _appSettings?.EmailConfiguration?.SmtpPass);
            smtp.Send(email);
            smtp.Disconnect(true);
        }
    }
}
